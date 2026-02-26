"""
AssemblyLine Sequential Queue Manager

Module de gestion de file d'attente séquentielle pour le connecteur
OpenCTI AssemblyLine. Garantit qu'un seul fichier est analysé à la fois
par AssemblyLine, évitant ainsi la surcharge de la plateforme.

API AssemblyLine utilisée:
    - GET /api/v4/submission/is_completed/{sid}/ -> {"completed": bool}
    - GET /api/v4/submission/full/{sid}/         -> résultats complets

Auteur: V1D1AN
Licence: Apache 2.0
"""

import threading
import time
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from enum import Enum
from datetime import datetime, timezone


logger = logging.getLogger(__name__)


class QueueItemStatus(Enum):
    """Statut d'un élément dans la queue."""
    PENDING = "pending"
    SUBMITTED = "submitted"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class QueueItem:
    """Représente un fichier en attente d'analyse."""
    observable_id: str
    observable_data: Dict[str, Any]
    status: QueueItemStatus = QueueItemStatus.PENDING
    sid: Optional[str] = None
    enqueued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    submitted_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict] = None
    error: Optional[str] = None
    retry_count: int = 0


class AssemblyLineQueue:
    """
    Gestionnaire de file d'attente séquentielle pour AssemblyLine.

    Garantit qu'un seul fichier est soumis à AssemblyLine à la fois.
    Les fichiers suivants attendent dans une queue FIFO que l'analyse
    en cours soit terminée avant d'être envoyés.

    Args:
        al_client:          Client AssemblyLine (assemblyline_client)
        submit_callback:    (observable_data) -> sid
        result_callback:    (observable_data, al_results) -> None
        error_callback:     (observable_data, error_message) -> None
        poll_interval:      Intervalle de polling en secondes (défaut: 30)
        submission_timeout: Timeout max pour une analyse en secondes (défaut: 600)
        max_retries:        Nombre max de tentatives en cas d'erreur (défaut: 2)
        enabled:            Active/désactive le mode séquentiel (défaut: True)
        helper:             OpenCTI helper pour les logs
    """

    def __init__(
        self,
        al_client,
        submit_callback: Callable,
        result_callback: Callable,
        error_callback: Callable,
        poll_interval: int = 30,
        submission_timeout: int = 600,
        max_retries: int = 2,
        enabled: bool = True,
        helper=None,
    ):
        self.al_client = al_client
        self.submit_callback = submit_callback
        self.result_callback = result_callback
        self.error_callback = error_callback
        self.poll_interval = poll_interval
        self.submission_timeout = submission_timeout
        self.max_retries = max_retries
        self.enabled = enabled
        self.helper = helper

        # Queue FIFO thread-safe
        self._queue: deque = deque()
        self._lock = threading.Lock()

        # État de la soumission en cours
        self._current_item: Optional[QueueItem] = None

        # Thread de traitement
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False

    # ──────────────────────────────────────────────
    # Logging helpers
    # ──────────────────────────────────────────────

    def _log_info(self, msg: str):
        if self.helper:
            self.helper.log_info(f"[Queue] {msg}")
        else:
            logger.info(f"[Queue] {msg}")

    def _log_warning(self, msg: str):
        if self.helper:
            self.helper.log_warning(f"[Queue] {msg}")
        else:
            logger.warning(f"[Queue] {msg}")

    def _log_error(self, msg: str):
        if self.helper:
            self.helper.log_error(f"[Queue] {msg}")
        else:
            logger.error(f"[Queue] {msg}")

    def _log_debug(self, msg: str):
        if self.helper:
            self.helper.log_debug(f"[Queue] {msg}")
        else:
            logger.debug(f"[Queue] {msg}")

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def start(self):
        """Démarre le worker thread de traitement de la queue."""
        if not self.enabled:
            self._log_info("Sequential mode DISABLED - files will be sent directly")
            return

        if self._running:
            self._log_warning("Queue worker already running")
            return

        self._stop_event.clear()
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="ALQueueWorker",
            daemon=True,
        )
        self._worker_thread.start()
        self._log_info(
            f"Sequential queue started "
            f"(poll={self.poll_interval}s, timeout={self.submission_timeout}s, "
            f"retries={self.max_retries})"
        )

    def stop(self):
        """Arrête proprement le worker thread."""
        if not self._running:
            return

        self._log_info("Stopping queue worker...")
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=10)
        self._running = False
        self._log_info(
            f"Queue worker stopped. Remaining in queue: {len(self._queue)}"
        )

    def enqueue(self, observable_id: str, observable_data: Dict[str, Any]) -> bool:
        """
        Ajoute un fichier à la file d'attente.

        Returns:
            True si ajouté à la queue, False si mode séquentiel désactivé
        """
        if not self.enabled:
            return False

        with self._lock:
            # Vérifier les doublons
            for existing in self._queue:
                if existing.observable_id == observable_id:
                    self._log_warning(
                        f"Observable {observable_id} already in queue, skipping"
                    )
                    return True

            # Vérifier si c'est l'item en cours
            if (self._current_item
                    and self._current_item.observable_id == observable_id):
                self._log_warning(
                    f"Observable {observable_id} currently being analyzed, skipping"
                )
                return True

            item = QueueItem(
                observable_id=observable_id,
                observable_data=observable_data,
            )
            self._queue.append(item)
            queue_size = len(self._queue)

        self._log_info(
            f"Enqueued: {observable_id} (queue size: {queue_size})"
        )
        return True

    def get_queue_status(self) -> Dict[str, Any]:
        """Retourne l'état actuel de la queue pour monitoring/logs."""
        with self._lock:
            current_info = None
            if self._current_item:
                elapsed = None
                if self._current_item.submitted_at:
                    elapsed = (
                        datetime.now(timezone.utc)
                        - self._current_item.submitted_at
                    ).total_seconds()
                current_info = {
                    "observable_id": self._current_item.observable_id,
                    "sid": self._current_item.sid,
                    "status": self._current_item.status.value,
                    "elapsed_seconds": elapsed,
                }

            return {
                "enabled": self.enabled,
                "running": self._running,
                "queue_size": len(self._queue),
                "current_analysis": current_info,
                "pending_items": [
                    {
                        "observable_id": item.observable_id,
                        "enqueued_at": item.enqueued_at.isoformat(),
                    }
                    for item in self._queue
                ],
            }

    @property
    def queue_size(self) -> int:
        return len(self._queue)

    @property
    def is_busy(self) -> bool:
        return self._current_item is not None

    # ──────────────────────────────────────────────
    # Worker loop (background thread)
    # ──────────────────────────────────────────────

    def _worker_loop(self):
        """Boucle principale du worker thread."""
        self._log_info("Worker loop started")

        while not self._stop_event.is_set():
            try:
                if (self._current_item
                        and self._current_item.status == QueueItemStatus.SUBMITTED):
                    # Vérifier l'analyse en cours
                    self._check_current_submission()

                elif (self._current_item is None
                      or self._current_item.status in (
                          QueueItemStatus.COMPLETED,
                          QueueItemStatus.FAILED,
                          QueueItemStatus.TIMEOUT,
                      )):
                    # Prendre le prochain fichier
                    self._process_next_item()

            except Exception as e:
                self._log_error(f"Unexpected error in worker loop: {str(e)}")

            # Attendre avant le prochain cycle
            self._stop_event.wait(timeout=self.poll_interval)

        self._log_info("Worker loop exited")

    def _check_current_submission(self):
        """
        Vérifie l'état de la soumission en cours auprès d'AssemblyLine
        via GET /api/v4/submission/is_completed/{sid}/
        """
        item = self._current_item
        if not item or not item.sid:
            return

        try:
            # Vérifier le timeout
            elapsed = 0.0
            if item.submitted_at:
                elapsed = (
                    datetime.now(timezone.utc) - item.submitted_at
                ).total_seconds()

                if elapsed > self.submission_timeout:
                    self._log_warning(
                        f"Timeout for {item.observable_id} "
                        f"(SID: {item.sid}, {elapsed:.0f}s > {self.submission_timeout}s)"
                    )
                    item.status = QueueItemStatus.TIMEOUT
                    item.error = f"Analysis timeout after {elapsed:.0f}s"
                    self.error_callback(item.observable_data, item.error)
                    self._current_item = None
                    return

            # Appel API: is_completed
            self._log_debug(
                f"Checking SID: {item.sid} ({elapsed:.0f}s elapsed)"
            )

            is_completed = self.al_client.submission.is_completed(item.sid)

            # L'API peut retourner un bool ou un dict {"completed": bool}
            if isinstance(is_completed, dict):
                completed = is_completed.get("completed", False)
            else:
                completed = bool(is_completed)

            if completed:
                self._log_info(
                    f"Analysis completed: {item.observable_id} "
                    f"(SID: {item.sid}, {elapsed:.0f}s)"
                )
                self._handle_completed_submission(item)
            else:
                self._log_debug(
                    f"Still running: SID {item.sid} "
                    f"({elapsed:.0f}s, {len(self._queue)} waiting)"
                )

        except Exception as e:
            self._log_error(
                f"Error checking SID {item.sid}: {str(e)}"
            )
            item.retry_count += 1
            # Plus tolérant pour les checks (x3 vs soumission)
            if item.retry_count > self.max_retries * 3:
                self._log_error(
                    f"Too many check failures for SID {item.sid}, marking failed"
                )
                item.status = QueueItemStatus.FAILED
                item.error = f"Status check failed repeatedly: {str(e)}"
                self.error_callback(item.observable_data, item.error)
                self._current_item = None

    def _handle_completed_submission(self, item: QueueItem):
        """Récupère les résultats et appelle le callback de traitement."""
        try:
            full_results = self.al_client.submission.full(item.sid)

            # Enrichir avec le summary pour avoir les tags détaillés
            try:
                summary = self.al_client.submission.summary(item.sid)
                if summary:
                    summary['sid'] = item.sid
                    summary['state'] = 'completed'
                    if 'max_score' in full_results:
                        summary['max_score'] = full_results['max_score']
                    if 'file_info' in full_results:
                        summary['file_info'] = full_results['file_info']
                    if 'times' in full_results:
                        summary['times'] = full_results['times']
                    if 'attack_matrix' in full_results:
                        summary['attack_matrix'] = full_results['attack_matrix']
                    full_results = summary
            except Exception as e:
                self._log_warning(f"Could not get summary for SID {item.sid}: {e}")
                full_results['sid'] = item.sid

            item.status = QueueItemStatus.COMPLETED
            item.completed_at = datetime.now(timezone.utc)
            item.result = full_results

            # Appeler le callback pour traiter les résultats dans OpenCTI
            self.result_callback(item.observable_data, full_results)

            self._log_info(
                f"Results processed: {item.observable_id} (SID: {item.sid})"
            )

        except Exception as e:
            self._log_error(
                f"Error retrieving results for SID {item.sid}: {str(e)}"
            )
            item.status = QueueItemStatus.FAILED
            item.error = f"Failed to retrieve results: {str(e)}"
            self.error_callback(item.observable_data, item.error)

        finally:
            self._current_item = None

    def _process_next_item(self):
        """Prend le prochain fichier de la queue et le soumet à AL."""
        item = None
        with self._lock:
            if self._queue:
                item = self._queue.popleft()

        if item is None:
            return

        self._log_info(
            f"Submitting: {item.observable_id} "
            f"(remaining: {len(self._queue)})"
        )

        try:
            sid = self.submit_callback(item.observable_data)

            if sid:
                item.sid = sid
                item.status = QueueItemStatus.SUBMITTED
                item.submitted_at = datetime.now(timezone.utc)
                self._current_item = item
                self._log_info(
                    f"Submitted: {item.observable_id} -> SID: {sid}"
                )
            else:
                self._log_warning(
                    f"No SID returned for {item.observable_id}"
                )
                item.status = QueueItemStatus.FAILED
                item.error = "No submission ID returned"
                self.error_callback(item.observable_data, item.error)
                self._current_item = None

        except Exception as e:
            self._log_error(
                f"Submit error for {item.observable_id}: {str(e)}"
            )
            item.retry_count += 1

            if item.retry_count <= self.max_retries:
                self._log_info(
                    f"Re-queuing {item.observable_id} "
                    f"(retry {item.retry_count}/{self.max_retries})"
                )
                with self._lock:
                    self._queue.appendleft(item)
                self._current_item = None
            else:
                self._log_error(
                    f"Max retries for {item.observable_id}, marking failed"
                )
                item.status = QueueItemStatus.FAILED
                item.error = f"Max retries exceeded: {str(e)}"
                self.error_callback(item.observable_data, item.error)
                self._current_item = None
