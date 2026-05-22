"""Backend abstraction over PyGhidra and Ghidra APIs for the MCP server."""
from __future__ import annotations
import base64
import binascii
import io
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4
MAX_MEMORY_READ_BYTES = 64 * 1024
DEFAULT_ANALYSIS_TIMEOUT = 60 * 60

class GhidraBackendError(RuntimeError):
    """Raised when a backend operation fails."""

@dataclass
class SessionRecord:
    """Tracks an open Ghidra program session."""
    session_id: str
    project: Any
    program: Any
    flat_api: Any
    program_name: str
    program_path: str
    project_location: str
    project_name: str
    source_path: str | None = None
    read_only: bool = True
    managed_project: bool = False
    managed_project_root: str | None = None
    temp_source_path: str | None = None
    program_consumer: Any = None
    decompiler: Any = None
    active_transaction_id: int | None = None
    active_transaction_description: str | None = None
    last_analysis_status: str = 'idle'
    last_analysis_started_at: float | None = None
    last_analysis_completed_at: float | None = None
    last_analysis_log: str | None = None
    last_analysis_error: str | None = None
    last_analysis_task_id: str | None = None

@dataclass
class TaskRecord:
    """Tracks an asynchronous backend task."""
    task_id: str
    kind: str
    future: Future[Any]
    session_id: str | None
    cancel_hook: Callable[[], None] | None = None
    cancel_requested: bool = False
    created_at: float = field(default_factory=time.time)

class GhidraBackend:
    """High-level Ghidra operations exposed to MCP tools."""

    def __init__(self, pyghidra_module: Any, *, install_dir: str | os.PathLike[str] | None=None, deterministic: bool=True):
        self._pyghidra = pyghidra_module
        self._install_dir = str(Path(install_dir).resolve()) if install_dir else None
        self._deterministic = deterministic
        self._sessions: dict[str, SessionRecord] = {}
        self._tasks: dict[str, TaskRecord] = {}
        self._lock = threading.Lock()
        self._startup_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix='ghidra_headless_mcp')
        self._started = False
        self._launcher: Any = None

    def ping(self) -> dict[str, str]:
        return {'status': 'ok', 'message': 'pong'}

    def session_open_existing(self, project_location: str, project_name: str, *, program_path: str | None=None, folder_path: str='/', program_name: str | None=None, read_only: bool=True, update_analysis: bool=False) -> dict[str, Any]:
        self._ensure_started()
        if not project_location:
            raise GhidraBackendError('project_location is required')
        if not project_name:
            raise GhidraBackendError('project_name is required')
        shared_project = self._find_open_project(project_location, project_name) is not None
        project = self._open_existing_project(project_location, project_name)
        if program_path:
            normalized = program_path if program_path.startswith('/') else f'/{program_path}'
            folder_path, _, tail = normalized.rpartition('/')
            folder_path = folder_path or '/'
            program_name = tail
        if not program_name:
            raise GhidraBackendError('program_name or program_path is required')
        try:
            program = project.openProgram(folder_path, program_name, False)
        except Exception as exc:
            if not shared_project:
                project.close()
            raise GhidraBackendError(f'failed to open program from project: {exc}') from exc
        if program is None:
            if not shared_project:
                project.close()
            raise GhidraBackendError('failed to open program from project: no Program returned')
        self._finalize_open_program(program, project)
        session_id = self._register_session(project=project, program=program, project_location=str(Path(project_location).resolve()), project_name=project_name, program_name=program_name, program_path=f"{folder_path.rstrip('/')}/{program_name}" if folder_path != '/' else f'/{program_name}', source_path=None, read_only=read_only, managed_project=False)
        if update_analysis:
            self.analysis_update_and_wait(session_id)
        return self.binary_summary(session_id)

    def session_close(self, session_id: str) -> dict[str, Any]:
        record = self._sessions.pop(session_id, None)
        if record is None:
            raise GhidraBackendError(f'unknown session_id: {session_id}')
        project_still_in_use = self._project_in_use(record.project_location, record.project_name, excluding_session_id=session_id)
        with suppress(Exception):
            if record.decompiler is not None:
                record.decompiler.closeProgram()
                record.decompiler.dispose()
        if record.program_consumer is not None:
            with suppress(Exception):
                record.program.release(record.program_consumer)
        with suppress(Exception):
            record.project.close(record.program)
        if not project_still_in_use:
            with suppress(Exception):
                record.project.close()
        if record.temp_source_path:
            with suppress(OSError):
                os.unlink(record.temp_source_path)
        if record.managed_project_root and (not project_still_in_use):
            shutil.rmtree(record.managed_project_root, ignore_errors=True)
        return {'closed': True, 'session_id': session_id}

    def analysis_update_and_wait(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        monitor = self._pyghidra.task_monitor(DEFAULT_ANALYSIS_TIMEOUT)
        record.last_analysis_status = 'running'
        record.last_analysis_started_at = time.time()
        record.last_analysis_completed_at = None
        record.last_analysis_error = None
        try:
            log = self._analyze_program(record.program, monitor)
        except Exception as exc:
            record.last_analysis_status = 'failed'
            record.last_analysis_completed_at = time.time()
            record.last_analysis_error = str(exc)
            raise GhidraBackendError(f'analysis failed: {exc}') from exc
        self._finalize_open_program(record.program, record.project)
        record.last_analysis_log = log or ''
        record.last_analysis_status = 'completed'
        record.last_analysis_completed_at = time.time()
        return {'session_id': session_id, 'status': record.last_analysis_status, 'log': record.last_analysis_log}

    def binary_summary(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        program = record.program
        entry = None
        with suppress(Exception):
            entry = record.flat_api.getEntryPoint()
        compiler_spec = None
        with suppress(Exception):
            compiler_spec = program.getCompilerSpec().getCompilerSpecID().toString()
        return {'session_id': session_id, 'filename': record.source_path or record.program_name, 'program_name': record.program_name, 'program_path': record.program_path, 'project_location': record.project_location, 'project_name': record.project_name, 'language_id': program.getLanguageID().toString(), 'compiler_spec_id': compiler_spec, 'format': program.getExecutableFormat(), 'entry_point': self._addr_str(entry), 'image_base': self._addr_str(program.getImageBase()), 'min_address': self._addr_str(program.getMinAddress()), 'max_address': self._addr_str(program.getMaxAddress()), 'read_only': record.read_only}

    def binary_get_function_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, address)
        return {'session_id': session_id, 'function': self._function_record(function)}

    def binary_strings(self, session_id: str, *, offset: int=0, limit: int=100, query: str | None=None) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        program = self._get_program(session_id)
        strings = list(self._iter_strings(program))
        if query:
            needle = query.lower()
            strings = [item for item in strings if needle in item['value'].lower()]
        items = strings[offset:offset + limit]
        return {'session_id': session_id, 'offset': offset, 'limit': limit, 'total': len(strings), 'count': len(items), 'items': items}

    def disasm_function(self, session_id: str, address: int | str, *, limit: int=500) -> dict[str, Any]:
        function = self._resolve_function(session_id, address)
        items = self._disassemble_instructions(self._get_program(session_id).getListing().getInstructions(function.getBody(), True), limit)
        return {'session_id': session_id, 'function': self._function_record(function), 'count': len(items), 'items': items}

    def decomp_function(self, session_id: str, function_start: int | str, *, timeout_secs: int=30) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        return self._decompile_function(session_id, function, timeout_secs=timeout_secs)

    def xref_to(self, session_id: str, address: int | str | None=None, *, start: int | str | None=None, end: int | str | None=None, limit: int=100) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError('limit must be > 0')
        if address is not None:
            if start is not None or end is not None:
                raise GhidraBackendError('address cannot be combined with start/end')
            addr = self._coerce_address(session_id, address, 'address')
            refs = list(self._get_program(session_id).getReferenceManager().getReferencesTo(addr))
            items = [self._reference_record(ref) for ref in refs[:limit]]
            return {'session_id': session_id, 'address': self._addr_str(addr), 'count': len(items), 'items': items}
        start_addr, end_addr, address_set = self._optional_address_range(session_id, start=start, end=end, arg_name='start')
        if address_set is None:
            raise GhidraBackendError('address or start is required')
        manager = self._get_program(session_id).getReferenceManager()
        items: list[dict[str, Any]] = []
        for to_addr in manager.getReferenceDestinationIterator(address_set, True):
            for ref in manager.getReferencesTo(to_addr):
                items.append(self._reference_record(ref))
                if len(items) >= limit:
                    break
            if len(items) >= limit:
                break
        return {'session_id': session_id, 'start': self._addr_str(start_addr), 'end': self._addr_str(end_addr), 'count': len(items), 'items': items}

    def xref_from(self, session_id: str, address: int | str | None=None, *, start: int | str | None=None, end: int | str | None=None, limit: int=100) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError('limit must be > 0')
        if address is not None:
            if start is not None or end is not None:
                raise GhidraBackendError('address cannot be combined with start/end')
            addr = self._coerce_address(session_id, address, 'address')
            refs = list(self._get_program(session_id).getReferenceManager().getReferencesFrom(addr))
            items = [self._reference_record(ref) for ref in refs[:limit]]
            return {'session_id': session_id, 'address': self._addr_str(addr), 'count': len(items), 'items': items}
        start_addr, end_addr, address_set = self._optional_address_range(session_id, start=start, end=end, arg_name='start')
        if address_set is None:
            raise GhidraBackendError('address or start is required')
        manager = self._get_program(session_id).getReferenceManager()
        items: list[dict[str, Any]] = []
        for from_addr in manager.getReferenceSourceIterator(address_set, True):
            for ref in manager.getReferencesFrom(from_addr):
                items.append(self._reference_record(ref))
                if len(items) >= limit:
                    break
            if len(items) >= limit:
                break
        return {'session_id': session_id, 'start': self._addr_str(start_addr), 'end': self._addr_str(end_addr), 'count': len(items), 'items': items}

    def data_typed_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, 'address')
        data = self._get_program(session_id).getListing().getDefinedDataContaining(addr)
        return {'session_id': session_id, 'address': self._addr_str(addr), 'defined': data is not None, 'data': self._data_record(data) if data is not None else None}

    def function_by_name(self, session_id: str, name: str, *, exact: bool=False, limit: int=20) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError('name is required')
        if limit <= 0:
            raise GhidraBackendError('limit must be > 0')
        funcs = sorted(self._get_program(session_id).getFunctionManager().getFunctions(True), key=self._function_sort_key)
        if exact:
            matched = [func for func in funcs if func.getName() == name]
        else:
            needle = name.lower()
            matched = [func for func in funcs if needle in func.getName().lower()]
        items = [self._function_record(func) for func in matched[:limit]]
        return {'session_id': session_id, 'query': name, 'exact': exact, 'limit': limit, 'total': len(matched), 'count': len(items), 'items': items}

    def symbol_by_name(self, session_id: str, name: str, *, exact: bool=False, limit: int=20, include_dynamic: bool=True) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError('name is required')
        if limit <= 0:
            raise GhidraBackendError('limit must be > 0')
        symbols = list(self._get_program(session_id).getSymbolTable().getAllSymbols(include_dynamic))
        if exact:
            matched = [symbol for symbol in symbols if symbol.getName(True) == name or symbol.getName() == name]
        else:
            needle = name.lower()
            matched = [symbol for symbol in symbols if needle in symbol.getName(True).lower()]
        items = [self._symbol_record(symbol) for symbol in matched[:limit]]
        return {'session_id': session_id, 'query': name, 'exact': exact, 'limit': limit, 'total': len(matched), 'count': len(items), 'items': items}

    def address_resolve(self, session_id: str, query: int | str) -> dict[str, Any]:
        if query is None or (isinstance(query, str) and (not query.strip())):
            raise GhidraBackendError('query is required')
        payload: dict[str, Any] = {'session_id': session_id, 'query': query, 'resolved': False}
        with suppress(GhidraBackendError):
            addr = self._coerce_address(session_id, query, 'query')
            payload['resolved'] = True
            payload['address'] = self._addr_str(addr)
            with suppress(GhidraBackendError):
                payload['function'] = self.binary_get_function_at(session_id, addr)['function']
            symbols = list(self._get_program(session_id).getSymbolTable().getSymbols(addr))
            payload['symbols'] = [self._symbol_record(symbol) for symbol in symbols]
            payload['data'] = self.data_typed_at(session_id, addr)['data']
            return payload
        if not isinstance(query, str):
            raise GhidraBackendError('query must be a string or address')
        symbols = self.symbol_by_name(session_id, query, exact=True, limit=50)['items']
        if not symbols:
            symbols = self.symbol_by_name(session_id, query, exact=False, limit=50)['items']
        functions = self.function_by_name(session_id, query, exact=True, limit=50)['items']
        if not functions:
            functions = self.function_by_name(session_id, query, exact=False, limit=50)['items']
        payload['symbols'] = symbols
        payload['functions'] = functions
        addresses = sorted({item['address'] for item in symbols if isinstance(item, dict) and item.get('address') is not None} | {item['entry_point'] for item in functions if isinstance(item, dict) and item.get('entry_point') is not None})
        if addresses:
            payload['resolved'] = True
            payload['address'] = addresses[0]
            with suppress(GhidraBackendError):
                payload['data'] = self.data_typed_at(session_id, addresses[0])['data']
        return payload

    def callgraph_paths(self, session_id: str, source_function: int | str, target_function: int | str, *, max_depth: int=4, limit: int=10) -> dict[str, Any]:
        if max_depth <= 0:
            raise GhidraBackendError('max_depth must be > 0')
        if limit <= 0:
            raise GhidraBackendError('limit must be > 0')
        source = self._resolve_function(session_id, source_function)
        target = self._resolve_function(session_id, target_function)
        target_entry = self._addr_str(target.getEntryPoint())
        queue: deque[list[Any]] = deque([[source]])
        paths: list[list[dict[str, Any]]] = []
        while queue and len(paths) < limit:
            path = queue.popleft()
            current = path[-1]
            if self._addr_str(current.getEntryPoint()) == target_entry:
                paths.append([self._function_record(func) for func in path])
                continue
            if len(path) - 1 >= max_depth:
                continue
            callees = sorted(current.getCalledFunctions(self._pyghidra.task_monitor()), key=self._function_sort_key)
            seen_in_path = {self._addr_str(func.getEntryPoint()) for func in path}
            for callee in callees:
                callee_entry = self._addr_str(callee.getEntryPoint())
                if callee_entry in seen_in_path:
                    continue
                queue.append([*path, callee])
        return {'session_id': session_id, 'source': self._function_record(source), 'target': self._function_record(target), 'max_depth': max_depth, 'count': len(paths), 'items': paths}

    def task_cancel(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        task.cancel_requested = True
        cancelled = task.future.cancel()
        if task.cancel_hook is not None:
            with suppress(Exception):
                task.cancel_hook()
        return {'task_id': task_id, 'cancel_requested': True, 'cancelled': cancelled, 'status': self._task_state(task)}

    def eval_code(self, code: str, *, session_id: str | None=None) -> dict[str, Any]:
        if not code:
            raise GhidraBackendError('code is required')
        self._ensure_started()
        transition_candidates = [session_id] if session_id else sorted(self._sessions)
        transitioned_session_ids = self._transition_sessions_to_writable(transition_candidates)
        context = self._eval_context(session_id)
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            try:
                compiled = compile(code, '<ghidra_headless_mcp>', 'eval')
            except SyntaxError:
                compiled = compile(code, '<ghidra_headless_mcp>', 'exec')
                exec(compiled, context, context)
                result = context.get('_')
            else:
                result = eval(compiled, context, context)
        payload: dict[str, Any] = {'result': self._to_jsonable(result)}
        if stdout_buffer.getvalue():
            payload['stdout'] = stdout_buffer.getvalue()
        if stderr_buffer.getvalue():
            payload['stderr'] = stderr_buffer.getvalue()
        payload['mode_transitioned'] = bool(transitioned_session_ids)
        payload['transitioned_session_ids'] = transitioned_session_ids
        return payload

    def shutdown(self) -> None:
        task_ids = list(self._tasks)
        for task_id in task_ids:
            with suppress(Exception):
                self.task_cancel(task_id)
        session_ids = list(self._sessions)
        for session_id in session_ids:
            with suppress(Exception):
                self.session_close(session_id)
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _ensure_started(self) -> None:
        if self._started:
            return
        with self._startup_lock:
            if self._started:
                return
            self._prune_conflicting_sys_path_entries()
            self._launcher = self._pyghidra.start(verbose=False, install_dir=Path(self._install_dir) if self._install_dir else None)
            self._started = True

    def _prune_conflicting_sys_path_entries(self) -> None:
        removable: list[str] = []
        for entry in list(sys.path):
            if not entry:
                path = Path.cwd()
            else:
                path = Path(entry)
            with suppress(OSError):
                if (path / 'ghidra' / 'Ghidra' / 'application.properties').exists():
                    removable.append(entry)
        for entry in removable:
            with suppress(ValueError):
                sys.path.remove(entry)

    def _find_open_project(self, project_location: str, project_name: str) -> Any:
        resolved_location = str(Path(project_location).resolve())
        for record in self._sessions.values():
            if record.project_location == resolved_location and record.project_name == project_name:
                return record.project
        return None

    def _project_in_use(self, project_location: str, project_name: str, *, excluding_session_id: str | None=None) -> bool:
        resolved_location = str(Path(project_location).resolve())
        return any((session_id != excluding_session_id and record.project_location == resolved_location and (record.project_name == project_name) for session_id, record in self._sessions.items()))

    def _open_existing_project(self, project_location: str, project_name: str) -> Any:
        from ghidra.base.project import GhidraProject
        existing = self._find_open_project(project_location, project_name)
        if existing is not None:
            return existing
        try:
            return GhidraProject.openProject(project_location, project_name)
        except Exception as exc:
            raise GhidraBackendError(f'failed to open project: {exc}') from exc

    def _register_session(self, *, project: Any, program: Any, project_location: str, project_name: str, program_name: str, program_path: str, source_path: str | None, read_only: bool, managed_project: bool, managed_project_root: str | None=None, temp_source_path: str | None=None, program_consumer: Any=None) -> str:
        from ghidra.program.flatapi import FlatProgramAPI
        session_id = uuid4().hex
        self._sessions[session_id] = SessionRecord(session_id=session_id, project=project, program=program, flat_api=FlatProgramAPI(program), program_name=program_name, program_path=program_path, project_location=project_location, project_name=project_name, source_path=source_path, read_only=read_only, managed_project=managed_project, managed_project_root=managed_project_root, temp_source_path=temp_source_path, program_consumer=program_consumer)
        return session_id

    def _get_record(self, session_id: str) -> SessionRecord:
        record = self._sessions.get(session_id)
        if record is None:
            raise GhidraBackendError(f'unknown session_id: {session_id}')
        return record

    def _get_program(self, session_id: str) -> Any:
        return self._get_record(session_id).program

    def _get_task(self, task_id: str) -> TaskRecord:
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            raise GhidraBackendError(f'unknown task_id: {task_id}')
        return task

    def _task_state(self, task: TaskRecord) -> str:
        future = task.future
        if future.cancelled():
            return 'cancelled'
        if future.done():
            return 'failed' if future.exception() is not None else 'completed'
        if future.running():
            return 'cancelling' if task.cancel_requested else 'running'
        return 'queued'

    def _transition_sessions_to_writable(self, session_ids: Iterable[str]) -> list[str]:
        transitioned: list[str] = []
        for session_id in session_ids:
            if session_id is None:
                continue
            record = self._get_record(session_id)
            if record.read_only:
                record.read_only = False
                transitioned.append(session_id)
        return transitioned

    def _analyze_program(self, program: Any, monitor: Any) -> str:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        from ghidra.program.util import GhidraProgramUtilities
        tx_id = int(program.startTransaction('Analysis'))
        try:
            manager = AutoAnalysisManager.getAnalysisManager(program)
            manager.initializeOptions()
            manager.reAnalyzeAll(None)
            manager.startAnalysis(monitor)
            GhidraProgramUtilities.markProgramAnalyzed(program)
            return str(manager.getMessageLog().toString())
        finally:
            program.endTransaction(tx_id, True)

    def _open_transaction_entry_ids(self, transaction: Any) -> list[int]:
        transaction_class = transaction.getClass()
        base_id_field = transaction_class.getDeclaredField('baseId')
        entries_field = transaction_class.getDeclaredField('list')
        base_id_field.setAccessible(True)
        entries_field.setAccessible(True)
        base_id = int(base_id_field.get(transaction))
        entries = entries_field.get(transaction)
        open_ids: list[int] = []
        for index in range(entries.size()):
            entry = entries.get(index)
            entry_class = entry.getClass()
            status_field = entry_class.getDeclaredField('status')
            status_field.setAccessible(True)
            if str(status_field.get(entry)) == 'NOT_DONE':
                open_ids.append(base_id + index)
        return open_ids

    def _drain_internal_transactions(self, program: Any, *, commit: bool=True) -> None:
        allowed_descriptions = {'', 'Analysis', 'Analyze', 'Batch Processing', 'Mark Program Analyzed'}
        while True:
            transaction = program.getCurrentTransactionInfo()
            if transaction is None:
                return
            if str(transaction.getDescription() or '') not in allowed_descriptions:
                return
            entry_ids = self._open_transaction_entry_ids(transaction)
            if not entry_ids:
                return
            program.endTransaction(entry_ids[-1], commit)

    def _sync_project_open_transaction(self, project: Any, program: Any, transaction_id: int) -> None:
        from java.lang import Integer
        project_class = project.getClass()
        open_programs_field = project_class.getDeclaredField('openPrograms')
        open_programs_field.setAccessible(True)
        open_programs = open_programs_field.get(project)
        if open_programs is not None and open_programs.containsKey(program):
            open_programs.put(program, Integer.valueOf(int(transaction_id)))

    def _finalize_open_program(self, program: Any, project: Any | None=None) -> None:
        with suppress(Exception):
            self._drain_internal_transactions(program, commit=True)
        if project is not None:
            with suppress(Exception):
                self._sync_project_open_transaction(project, program, -1)

    def _validate_offset_limit(self, offset: int, limit: int) -> None:
        if offset < 0:
            raise GhidraBackendError('offset must be >= 0')
        if limit <= 0:
            raise GhidraBackendError('limit must be > 0')

    def _coerce_address(self, session_id: str, value: int | str | Any, arg_name: str) -> Any:
        program = self._get_program(session_id)
        factory = program.getAddressFactory()
        if value is None:
            raise GhidraBackendError(f'{arg_name} is required')
        if hasattr(value, 'getAddressSpace') and hasattr(value, 'getOffset'):
            return value
        if isinstance(value, int):
            return factory.getDefaultAddressSpace().getAddress(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                raise GhidraBackendError(f'{arg_name} is required')
            with suppress(Exception):
                addr = factory.getAddress(text)
                if addr is not None:
                    return addr
            with suppress(Exception):
                return factory.getDefaultAddressSpace().getAddress(int(text, 0))
        raise GhidraBackendError(f'invalid {arg_name}: {value!r}')

    def _addr_str(self, address: Any) -> str | None:
        if address is None:
            return None
        return str(address)

    def _function_sort_key(self, function: Any) -> tuple[int, str]:
        return (int(function.getEntryPoint().getOffset()), function.getName())

    def _resolve_function(self, session_id: str, function_start: int | str | None) -> Any:
        if function_start is None:
            raise GhidraBackendError('function_start is required')
        addr = self._coerce_address(session_id, function_start, 'function_start')
        manager = self._get_program(session_id).getFunctionManager()
        function = manager.getFunctionAt(addr)
        if function is None:
            function = manager.getFunctionContaining(addr)
        if function is None:
            raise GhidraBackendError(f'no function found at {self._addr_str(addr)}')
        return function

    def _decompile_function(self, session_id: str, function: Any, *, timeout_secs: int) -> dict[str, Any]:
        if timeout_secs <= 0:
            raise GhidraBackendError('timeout_secs must be > 0')
        decompiler = self._get_decompiler(session_id)
        results = decompiler.decompileFunction(function, timeout_secs, self._pyghidra.task_monitor(timeout_secs))
        payload = {'session_id': session_id, 'function': self._function_record(function), 'decompile_completed': bool(results.decompileCompleted()), 'timed_out': bool(results.isTimedOut()), 'cancelled': bool(results.isCancelled()), 'error_message': results.getErrorMessage()}
        decompiled = results.getDecompiledFunction()
        if decompiled is not None:
            payload['c'] = decompiled.getC()
            payload['signature'] = decompiled.getSignature()
        return payload

    def _get_decompiler(self, session_id: str) -> Any:
        record = self._get_record(session_id)
        if record.decompiler is None:
            from ghidra.app.decompiler import DecompInterface
            decompiler = DecompInterface()
            decompiler.toggleCCode(True)
            decompiler.toggleSyntaxTree(True)
            decompiler.setSimplificationStyle('decompile')
            if not decompiler.openProgram(record.program):
                decompiler.dispose()
                raise GhidraBackendError('failed to open decompiler for program')
            record.decompiler = decompiler
        return record.decompiler

    def _function_record(self, function: Any) -> dict[str, Any]:
        return {'name': function.getName(), 'entry_point': self._addr_str(function.getEntryPoint()), 'body_start': self._addr_str(function.getBody().getMinAddress()), 'body_end': self._addr_str(function.getBody().getMaxAddress()), 'signature': function.getPrototypeString(False, True), 'calling_convention': function.getCallingConventionName(), 'external': bool(function.isExternal()), 'thunk': bool(function.isThunk())}

    def _symbol_record(self, symbol: Any) -> dict[str, Any] | None:
        if symbol is None:
            return None
        namespace = None
        with suppress(Exception):
            parent = symbol.getParentNamespace()
            namespace = parent.getName(True) if parent is not None else None
        return {'id': int(symbol.getID()), 'name': symbol.getName(True), 'short_name': symbol.getName(), 'address': self._addr_str(symbol.getAddress()), 'symbol_type': str(symbol.getSymbolType()), 'source_type': str(symbol.getSource()), 'namespace': namespace, 'primary': bool(symbol.isPrimary()), 'external': bool(symbol.isExternal())}

    def _reference_record(self, reference: Any) -> dict[str, Any]:
        return {'from': self._addr_str(reference.getFromAddress()), 'to': self._addr_str(reference.getToAddress()), 'reference_type': str(reference.getReferenceType()), 'operand_index': int(reference.getOperandIndex()), 'primary': bool(reference.isPrimary()), 'external': bool(reference.isExternalReference())}

    def _data_record(self, data: Any) -> dict[str, Any] | None:
        if data is None:
            return None
        value = None
        with suppress(Exception):
            value = data.getDefaultValueRepresentation()
        return {'address': self._addr_str(data.getAddress()), 'length': int(data.getLength()), 'data_type': data.getDataType().getPathName(), 'base_data_type': data.getBaseDataType().getPathName(), 'value': value, 'label': data.getLabel(), 'path_name': data.getPathName()}

    def _data_type_record(self, data_type: Any) -> dict[str, Any]:
        length = None
        with suppress(Exception):
            length = int(data_type.getLength())
        return {'name': data_type.getName(), 'display_name': data_type.getDisplayName(), 'path': data_type.getPathName(), 'category': str(data_type.getCategoryPath()), 'length': length, 'description': data_type.getDescription(), 'java_type': data_type.getClass().getName()}

    def _disassemble_instructions(self, instructions: Any, limit: int) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for instruction in instructions:
            if len(items) >= limit:
                break
            items.append({'address': self._addr_str(instruction.getAddress()), 'mnemonic': instruction.getMnemonicString(), 'text': instruction.toString(), 'bytes': bytes(instruction.getBytes()).hex()})
        return items

    def _iter_strings(self, program: Any, *, address_set: Any | None=None) -> Iterable[dict[str, Any]]:
        from ghidra.program.model.data import StringDataInstance
        from ghidra.program.util import DefinedDataIterator
        iterator = DefinedDataIterator.byDataInstance(program, lambda data: StringDataInstance.getStringDataInstance(data) != StringDataInstance.NULL_INSTANCE)
        for data in iterator:
            if address_set is not None and (not address_set.contains(data.getAddress())):
                continue
            instance = StringDataInstance.getStringDataInstance(data)
            yield {'address': self._addr_str(data.getAddress()), 'length': int(data.getLength()), 'value': instance.getStringValue(), 'data_type': data.getDataType().getPathName()}

    def _coerce_address_range(self, session_id: str, *, start: int | str, end: int | str | None=None, length: int | None=None, arg_name: str) -> tuple[Any, Any, Any]:
        if length is not None and length <= 0:
            raise GhidraBackendError('length must be > 0')
        start_addr = self._coerce_address(session_id, start, arg_name)
        if end is not None:
            end_addr = self._coerce_address(session_id, end, 'end')
        elif length is not None:
            end_addr = start_addr.add(int(length) - 1)
        else:
            end_addr = start_addr
        from ghidra.program.model.address import AddressSet
        return (start_addr, end_addr, AddressSet(start_addr, end_addr))

    def _optional_address_range(self, session_id: str, *, start: int | str | None=None, end: int | str | None=None, length: int | None=None, arg_name: str) -> tuple[Any | None, Any | None, Any | None]:
        if start is None:
            if end is not None or length is not None:
                raise GhidraBackendError(f'{arg_name} is required when end or length is provided')
            return (None, None, None)
        return self._coerce_address_range(session_id, start=start, end=end, length=length, arg_name=arg_name)

    def _eval_context(self, session_id: str | None) -> dict[str, Any]:
        self._ensure_started()
        import ghidra
        import java
        context: dict[str, Any] = {'pyghidra': self._pyghidra, 'ghidra': ghidra, 'java': java, 'sessions': {sid: record.program for sid, record in self._sessions.items()}}
        if session_id is not None:
            record = self._get_record(session_id)
            context.update({'session_id': session_id, 'program': record.program, 'project': record.project.getProject(), 'ghidra_project': record.project, 'flat_api': record.flat_api, 'decompiler': self._get_decompiler(session_id), 'listing': record.program.getListing(), 'memory': record.program.getMemory(), 'symbol_table': record.program.getSymbolTable()})
        return context

    def _to_jsonable(self, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, bytes):
            return base64.b64encode(value).decode('ascii')
        if isinstance(value, dict):
            return {str(key): self._to_jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            return [self._to_jsonable(item) for item in value]
        if hasattr(value, 'items'):
            with suppress(Exception):
                return {str(key): self._to_jsonable(item) for key, item in value.items()}
        if hasattr(value, 'getEntryPoint') and hasattr(value, 'getProgram'):
            return self._function_record(value)
        if hasattr(value, 'getPathName') and hasattr(value, 'getDisplayName'):
            return self._data_type_record(value)
        if hasattr(value, 'getSymbolType') and hasattr(value, 'getAddress'):
            return self._symbol_record(value)
        if hasattr(value, 'getAddressSpace') and hasattr(value, 'getOffset'):
            return self._addr_str(value)
        if hasattr(value, 'getBytes') and hasattr(value, 'toString'):
            with suppress(Exception):
                return str(value)
        if hasattr(value, 'toArray'):
            with suppress(Exception):
                return [self._to_jsonable(item) for item in value.toArray()]
        if hasattr(value, 'iterator'):
            with suppress(Exception):
                return [self._to_jsonable(item) for item in value]
        return str(value)