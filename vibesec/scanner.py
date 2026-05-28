import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

from vibesec.rules import ALL_RULES
from vibesec.utils import read_file, walk_files

logger = logging.getLogger(__name__)
console = Console()


class Scanner:

    def __init__(
        self,
        path,
        display_path=None,
        exclude_paths=None,
        max_file_size=None,
        rules=None,
        show_progress=True,
    ):
        self.path = path
        self.display_path = display_path
        self.exclude_paths = exclude_paths or []
        self.max_file_size = max_file_size
        self.rules = rules or ALL_RULES
        self.show_progress = show_progress
        self.files_scanned = 0
        self.duration = 0.0

    def run(self):
        findings = []
        lock = Lock()
        start_time = time.perf_counter()
        files = list(walk_files(
            self.path,
            exclude_paths=self.exclude_paths,
            max_file_size=self.max_file_size,
        ))

        def scan_file(file_path):
            file_findings = []
            content = read_file(file_path)
            if not content:
                return file_findings, False
            for rule in self.rules:
                try:
                    results = rule(file_path, content)
                    file_findings.extend(results)
                except Exception as e:
                    logger.warning(f"Rule {rule.__name__} failed on {file_path}: {e}")
            return file_findings, True

        def collect_result(future):
            file_findings, counted = future.result()
            with lock:
                findings.extend(file_findings)
                if counted:
                    self.files_scanned += 1

        if self.show_progress and files:
            with Progress(
                TextColumn("[cyan]Scanning[/cyan]"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total} files"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task_id = progress.add_task("scan", total=len(files))
                with ThreadPoolExecutor(max_workers=4) as executor:
                    futures = [executor.submit(scan_file, file_path) for file_path in files]
                    for future in as_completed(futures):
                        collect_result(future)
                        progress.advance(task_id)
        else:
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(scan_file, file_path) for file_path in files]
                for future in as_completed(futures):
                    collect_result(future)

        # Clean up temp paths for GitHub URL scans
        if self.display_path and self.display_path != self.path:
            for finding in findings:
                finding["file"] = finding["file"].replace(self.path, self.display_path)

        self.duration = time.perf_counter() - start_time
        return findings
