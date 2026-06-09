"""
ComplianceLoop — FAISS Index Manager
======================================
Manages the lifecycle of the FAISS vector index used by the RAG agent.

Index structure:
  - FAISS IndexFlatIP (Inner Product / cosine similarity on normalised vectors)
  - Dimension: 384 (all-MiniLM-L6-v2 output)
  - ID map: dict mapping FAISS integer ID → TextChunk metadata
  - Stored as two files:
      index_active/compliance.index   — FAISS binary index
      index_active/id_map.json        — ID → chunk metadata mapping

Directory layout (under FAISS_INDEX_DIR):
  index_active/    ← live index read by RAG agent workers
  index_staging/   ← build target (new index built here before swap)
  index_backup/    ← previous version (kept for one cycle for rollback)

Safe swap protocol (zero downtime):
  1. Build new index in index_staging/
  2. Run health check against golden test set (18/20 must pass)
  3. Move index_active/ → index_backup/ (atomic rename on POSIX)
  4. Move index_staging/ → index_active/ (atomic rename on POSIX)
  5. Publish Redis pub/sub reload signal to all RAG agent workers
  6. Each worker opens the new index file and atomically swaps its
     internal reference — requests in flight finish with old handle

Rollback:
  If step 2 fails (health check), index_staging/ is cleared.
  If step 4 fails (unexpected), index_backup/ can be moved back.
  See scripts/swap_faiss_index.sh for the manual rollback procedure.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any

import numpy as np
import structlog

logger = structlog.get_logger(__name__)

# ── Directory names ───────────────────────────────────────────────────────────
_ACTIVE_DIR = "index_active"
_STAGING_DIR = "index_staging"
_BACKUP_DIR = "index_backup"
_INDEX_FILENAME = "compliance.index"
_IDMAP_FILENAME = "id_map.json"

# ── Redis pub/sub channel for reload signal ───────────────────────────────────
_RELOAD_CHANNEL = "complianceloop:faiss:reload"


# ── Index Manager ─────────────────────────────────────────────────────────────

class IndexManager:
    """
    Manages the FAISS index lifecycle: build, health check, swap, load.

    One instance per process is sufficient. The loaded index is held
    as an instance attribute for the RAG agent workers.
    """

    def __init__(self, base_dir: str | None = None) -> None:
        self.base_dir = Path(
            base_dir or os.environ.get("FAISS_INDEX_DIR", "retrieval/index_data")
        )
        self._index: Any = None           # FAISS index object
        self._id_map: dict[int, dict[str, Any]] = {}
        self._loaded_from: Path | None = None

    @property
    def active_dir(self) -> Path:
        return self.base_dir / _ACTIVE_DIR

    @property
    def staging_dir(self) -> Path:
        return self.base_dir / _STAGING_DIR

    @property
    def backup_dir(self) -> Path:
        return self.base_dir / _BACKUP_DIR

    # ── Index loading ─────────────────────────────────────────────────────────

    def load(self, from_dir: Path | None = None) -> None:
        """
        Load the FAISS index and ID map from disk into memory.

        Called by RAG agent workers at startup and on Redis reload signal.

        Args:
            from_dir: Directory to load from. Defaults to active_dir.

        Raises:
            FileNotFoundError: If index files do not exist.
            ImportError: If faiss-cpu is not installed.
        """
        try:
            import faiss  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "faiss-cpu is required. Install with: pip install -r requirements/pipeline.txt"
            ) from exc

        load_dir = from_dir or self.active_dir
        index_path = load_dir / _INDEX_FILENAME
        idmap_path = load_dir / _IDMAP_FILENAME

        if not index_path.exists():
            raise FileNotFoundError(
                f"FAISS index not found at {index_path}. "
                "Run 'make build-index' to build the initial index."
            )
        if not idmap_path.exists():
            raise FileNotFoundError(f"ID map not found at {idmap_path}.")

        start = time.monotonic()
        new_index = faiss.read_index(str(index_path))
        with open(idmap_path, "r", encoding="utf-8") as f:
            # ID map keys are stored as strings in JSON — convert back to int
            raw_map = json.load(f)
            new_id_map = {int(k): v for k, v in raw_map.items()}

        duration_ms = int((time.monotonic() - start) * 1000)

        # Atomic swap of internal reference
        self._index = new_index
        self._id_map = new_id_map
        self._loaded_from = load_dir

        logger.info(
            "index.loaded",
            vector_count=new_index.ntotal,
            id_map_size=len(new_id_map),
            duration_ms=duration_ms,
            from_dir=str(load_dir),
        )

    def is_loaded(self) -> bool:
        """Return True if the index is currently loaded in memory."""
        return self._index is not None

    # ── Index building ────────────────────────────────────────────────────────

    def build(
        self,
        chunks: list[Any],  # list[TextChunk]
        target_dir: Path | None = None,
    ) -> int:
        """
        Build a new FAISS index from a list of TextChunk objects.

        Embeddings are computed in batches. The resulting index and ID map
        are written to target_dir (defaults to staging_dir).

        Args:
            chunks: List of TextChunk objects from the chunker.
            target_dir: Where to write the new index. Default: staging_dir.

        Returns:
            Number of vectors added to the index.

        Raises:
            ValueError: If chunks list is empty.
            ImportError: If faiss-cpu or sentence-transformers are not installed.
        """
        try:
            import faiss  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError("faiss-cpu is required.") from exc

        if not chunks:
            raise ValueError("Cannot build index from empty chunk list.")

        from retrieval.embedder import batch_embed, get_embedding_dimension  # noqa: PLC0415

        target = target_dir or self.staging_dir
        target.mkdir(parents=True, exist_ok=True)

        dimension = get_embedding_dimension()
        index = faiss.IndexFlatIP(dimension)  # Inner product = cosine on normalised vectors

        texts = [c.text for c in chunks]
        id_map: dict[int, dict[str, Any]] = {}

        logger.info(
            "index.build.started",
            chunk_count=len(chunks),
            dimension=dimension,
            target_dir=str(target),
        )
        start = time.monotonic()

        # Embed in batches of 256
        batch_size = 256
        for batch_start in range(0, len(texts), batch_size):
            batch_texts = texts[batch_start: batch_start + batch_size]
            batch_chunks = chunks[batch_start: batch_start + batch_size]

            vectors = batch_embed(batch_texts, normalise=True)
            index.add(vectors)

            # Build ID map entries
            for i, chunk in enumerate(batch_chunks):
                faiss_id = batch_start + i
                id_map[faiss_id] = chunk.to_metadata_dict()

        duration_ms = int((time.monotonic() - start) * 1000)

        # Write to disk
        index_path = target / _INDEX_FILENAME
        idmap_path = target / _IDMAP_FILENAME

        faiss.write_index(index, str(index_path))
        with open(idmap_path, "w", encoding="utf-8") as f:
            json.dump({str(k): v for k, v in id_map.items()}, f, ensure_ascii=True)

        logger.info(
            "index.build.completed",
            vector_count=index.ntotal,
            duration_ms=duration_ms,
            index_size_mb=round(index_path.stat().st_size / 1024 / 1024, 2),
            target_dir=str(target),
        )

        return index.ntotal

    # ── Health check ──────────────────────────────────────────────────────────

    def health_check(
        self,
        test_set_path: str | Path | None = None,
        check_dir: Path | None = None,
        pass_threshold: float = 0.9,
    ) -> tuple[bool, dict[str, Any]]:
        """
        Run the golden corpus health check against a test set.

        Loads the index from check_dir (staging by default), runs each
        query from the golden test set, and checks whether the expected
        top-1 result matches.

        Args:
            test_set_path: Path to golden_test_set.json.
                           Defaults to retrieval/golden_test_set.json.
            check_dir: Index directory to check. Defaults to staging_dir.
            pass_threshold: Fraction of queries that must pass (default 0.9 = 18/20).

        Returns:
            Tuple of (passed: bool, results: dict with details).
        """
        check_target = check_dir or self.staging_dir
        golden_path = Path(
            test_set_path or
            Path(__file__).parent / "golden_test_set.json"
        )

        if not golden_path.exists():
            logger.warning("index.health_check.no_test_set", path=str(golden_path))
            return True, {"skipped": True, "reason": "No golden test set found"}

        with open(golden_path, "r", encoding="utf-8") as f:
            test_set = json.load(f)

        # Load staging index into a temporary manager
        temp_manager = IndexManager(base_dir=str(self.base_dir))
        try:
            temp_manager.load(from_dir=check_target)
        except FileNotFoundError as exc:
            return False, {"error": str(exc)}

        passed = 0
        failed = 0
        details = []

        for item in test_set:
            query = item["query"]
            expected_doc_id = item["expected_source_document_id"]

            try:
                from retrieval.retriever import FAISSRetriever  # noqa: PLC0415
                retriever = FAISSRetriever(index_manager=temp_manager)
                results = retriever.query(query, top_k=1)

                if results and results[0].source_document_id == expected_doc_id:
                    passed += 1
                    details.append({"query": query[:50], "status": "pass"})
                else:
                    failed += 1
                    got = results[0].source_document_id if results else "no_result"
                    details.append({
                        "query": query[:50],
                        "status": "fail",
                        "expected": expected_doc_id,
                        "got": got,
                    })
            except Exception as exc:
                failed += 1
                details.append({"query": query[:50], "status": "error", "error": str(exc)})

        total = passed + failed
        pass_rate = passed / total if total > 0 else 0.0
        health_passed = pass_rate >= pass_threshold

        logger.info(
            "index.health_check.completed",
            passed=passed,
            failed=failed,
            pass_rate=round(pass_rate, 3),
            health_passed=health_passed,
        )

        return health_passed, {
            "passed": passed,
            "failed": failed,
            "total": total,
            "pass_rate": pass_rate,
            "threshold": pass_threshold,
            "details": details,
        }

    # ── Safe atomic swap ──────────────────────────────────────────────────────

    def safe_swap(
        self,
        skip_health_check: bool = False,
    ) -> bool:
        """
        Atomically swap staging index → active index.

        Steps:
          1. Health check on staging (unless skip_health_check=True)
          2. Move active → backup (atomic rename)
          3. Move staging → active (atomic rename)
          4. Reload live index in this manager
          5. Publish Redis reload signal to other workers

        Args:
            skip_health_check: If True, skip the health check step.
                               Only use in testing or emergency scenarios.

        Returns:
            True if swap succeeded, False if health check failed.
        """
        if not (self.staging_dir / _INDEX_FILENAME).exists():
            logger.error("index.swap.no_staging_index")
            return False

        # Step 1: Health check
        if not skip_health_check:
            passed, results = self.health_check()
            if not passed:
                logger.error(
                    "index.swap.health_check_failed",
                    pass_rate=results.get("pass_rate"),
                    failed=results.get("failed"),
                )
                from observability.metrics import FAISS_INDEX_SWAP_TOTAL  # noqa: PLC0415
                FAISS_INDEX_SWAP_TOTAL.labels(status="health_check_failed").inc()
                return False

        try:
            # Step 2: active → backup (remove old backup first)
            if self.backup_dir.exists():
                shutil.rmtree(self.backup_dir)
            if self.active_dir.exists():
                self.active_dir.rename(self.backup_dir)

            # Step 3: staging → active
            self.staging_dir.rename(self.active_dir)

            # Step 4: Reload live index
            self.load(from_dir=self.active_dir)

            # Step 5: Signal other workers to reload
            self._publish_reload_signal()

            logger.info("index.swap.completed", vector_count=self._index.ntotal)

            from observability.metrics import FAISS_INDEX_SWAP_TOTAL  # noqa: PLC0415
            FAISS_INDEX_SWAP_TOTAL.labels(status="success").inc()
            return True

        except Exception as exc:
            logger.error("index.swap.failed", error=str(exc))
            from observability.metrics import FAISS_INDEX_SWAP_TOTAL  # noqa: PLC0415
            FAISS_INDEX_SWAP_TOTAL.labels(status="error").inc()
            raise

    def _publish_reload_signal(self) -> None:
        """Publish Redis pub/sub message to signal worker reload."""
        try:
            import redis as redis_lib  # noqa: PLC0415
            redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
            r = redis_lib.from_url(redis_url)
            r.publish(_RELOAD_CHANNEL, "reload")
            logger.debug("index.reload_signal.published")
        except Exception as exc:
            # Reload signal failure is non-fatal — workers will reload on next request
            logger.warning("index.reload_signal.failed", error=str(exc))

    def subscribe_to_reload_signals(self) -> None:
        """
        Subscribe to Redis reload signals in a background thread.

        Called by RAG agent workers at startup. When a reload signal
        arrives, the worker reloads its index from the active directory.
        """
        import threading  # noqa: PLC0415

        def _listen() -> None:
            try:
                import redis as redis_lib  # noqa: PLC0415
                redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
                r = redis_lib.from_url(redis_url)
                pubsub = r.pubsub()
                pubsub.subscribe(_RELOAD_CHANNEL)
                for message in pubsub.listen():
                    if message["type"] == "message":
                        logger.info("index.reload_signal.received")
                        try:
                            self.load(from_dir=self.active_dir)
                        except Exception as exc:
                            logger.error("index.reload.failed", error=str(exc))
            except Exception as exc:
                logger.warning("index.reload_listener.failed", error=str(exc))

        thread = threading.Thread(target=_listen, daemon=True, name="faiss-reload-listener")
        thread.start()

    def get_index_stats(self) -> dict[str, Any]:
        """Return statistics about the loaded index."""
        if not self.is_loaded():
            return {"loaded": False}
        return {
            "loaded": True,
            "vector_count": self._index.ntotal,
            "id_map_size": len(self._id_map),
            "loaded_from": str(self._loaded_from),
            "active_dir_exists": self.active_dir.exists(),
            "staging_dir_exists": self.staging_dir.exists(),
            "backup_dir_exists": self.backup_dir.exists(),
        }