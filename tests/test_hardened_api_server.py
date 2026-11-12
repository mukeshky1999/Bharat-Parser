"""
Hostile QA Automation Test Suite: FastAPI Backend Hardening
Validates:
1. Concurrency guard on /api/case/ingest returning 409 Conflict.
2. Path traversal security boundary on /api/case/hex-window returning 403 Forbidden.
"""

import os
import unittest
import threading
import time
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from parsers.api_server import app, _case_state, _ingest_lock


class TestHardenedApiServer:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        self.client = TestClient(app)
        yield
        # Reset state after tests
        _case_state["loaded"] = False
        _case_state["case_id"] = None
        _case_state["evidence_path"] = None

    # --------------------------------------------------------------------------
    # 1. CONCURRENT INGESTION LOCK TEST (409 CONFLICT)
    # --------------------------------------------------------------------------
    def test_concurrent_ingest_returns_409_conflict(self):
        """
        Proves that invoking /api/case/ingest concurrently returns an HTTP 409 Conflict.
        Synchronizes two requests using threading Events so that Request 2 arrives
        while Request 1 is actively executing the ingestion pipeline holding _ingest_lock.
        """
        pipeline_started = threading.Event()
        release_pipeline = threading.Event()

        def mock_slow_ingestion(*args, **kwargs):
            pipeline_started.set()
            # Hold lock until released or timeout
            release_pipeline.wait(timeout=5)
            return {
                "success": True,
                "case_id": "TEST_LOCKED_CASE",
                "counts": {},
            }

        responses = []

        def execute_first_request():
            res = self.client.post(
                "/api/case/ingest",
                json={"evidence_path": "dummy_evidence_path_1"},
            )
            responses.append(("req1", res))

        with patch("parsers.api_server._execute_ingestion_pipeline", side_effect=mock_slow_ingestion):
            # Start Request 1 on background thread
            t1 = threading.Thread(target=execute_first_request)
            t1.start()

            # Wait until Request 1 has acquired _ingest_lock and entered pipeline
            assert pipeline_started.wait(timeout=3), "First ingestion request failed to start within timeout"

            # Assert that the lock is currently held
            assert _ingest_lock.locked(), "Ingest lock must be locked during pipeline execution"

            # Execute Request 2 while Request 1 is actively holding the lock
            res2 = self.client.post(
                "/api/case/ingest",
                json={"evidence_path": "dummy_evidence_path_2"},
            )
            responses.append(("req2", res2))

            # Release Request 1 to complete cleanly
            release_pipeline.set()
            t1.join(timeout=3)

        # Find results
        req1_res = next(r for tag, r in responses if tag == "req1")
        req2_res = next(r for tag, r in responses if tag == "req2")

        # Request 1 should succeed
        assert req1_res.status_code == 200, f"Expected 200 for initial request, got {req1_res.status_code}"

        # Request 2 MUST return 409 Conflict
        assert req2_res.status_code == 409, f"Expected 409 Conflict for concurrent request, got {req2_res.status_code}"
        
        detail_msg = req2_res.json().get("detail", "")
        assert "Conflict" in detail_msg or "already actively executing" in detail_msg, (
            f"Unexpected error detail: {detail_msg}"
        )

    # --------------------------------------------------------------------------
    # 2. PATH TRAVERSAL DEFENSE TEST (403 FORBIDDEN)
    # --------------------------------------------------------------------------
    def test_hex_window_path_traversal_returns_403_forbidden(self):
        """
        Proves that attempting to read ../../../../etc/passwd via /api/case/hex-window
        is intercepted by the sandbox boundary and returns HTTP 403 Forbidden.
        """
        # Ensure a forensic case is marked as active/loaded
        _case_state["loaded"] = True
        _case_state["case_id"] = "CASE_TRAVERSAL_TEST"
        _case_state["evidence_path"] = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scratch", "active_case"
        )

        hostile_path = "../../../../etc/passwd"

        response = self.client.get(
            "/api/case/hex-window",
            params={
                "file_path": hostile_path,
                "offset": 0,
                "window_size": 4096,
            },
        )

        assert response.status_code == 403, (
            f"Expected 403 Forbidden for path traversal attempt, received HTTP {response.status_code}"
        )

        resp_json = response.json()
        assert "Access Denied" in resp_json.get("detail", ""), (
            f"Detail does not indicate path sandboxing block: {resp_json}"
        )

    def test_hex_window_unloaded_case_returns_412(self):
        """
        Proves that calling /api/case/hex-window without an active case returns 412 Precondition Failed.
        """
        _case_state["loaded"] = False

        response = self.client.get(
            "/api/case/hex-window",
            params={
                "file_path": "any_file.db",
                "offset": 0,
            },
        )

        assert response.status_code == 412, (
            f"Expected 412 Precondition Failed when no case is loaded, got {response.status_code}"
        )


class TestApiToken(unittest.TestCase):
    """Per-launch API token (H-12 remainder)."""

    def setUp(self):
        self.client = TestClient(app)

    def tearDown(self):
        os.environ.pop("BHARAT_API_TOKEN", None)

    def test_requests_without_token_are_rejected_when_token_configured(self):
        os.environ["BHARAT_API_TOKEN"] = "s3cret-token"
        self.assertEqual(self.client.get("/api/health").status_code, 401)
        self.assertEqual(self.client.get("/api/health", headers={"X-Bharat-Token": "wrong"}).status_code, 401)
        ok = self.client.get("/api/health", headers={"X-Bharat-Token": "s3cret-token"})
        self.assertEqual(ok.status_code, 200)

    def test_preflight_is_not_blocked_and_unconfigured_means_open(self):
        os.environ["BHARAT_API_TOKEN"] = "s3cret-token"
        pre = self.client.options("/api/health", headers={
            "Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-bharat-token"})
        self.assertEqual(pre.status_code, 200)
        os.environ.pop("BHARAT_API_TOKEN")
        self.assertEqual(self.client.get("/api/health").status_code, 200)

    def test_rejection_carries_cors_headers_so_the_ui_can_report_it(self):
        os.environ["BHARAT_API_TOKEN"] = "s3cret-token"
        r = self.client.get("/api/health", headers={"Origin": "http://localhost:3000"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.headers.get("access-control-allow-origin"), "http://localhost:3000")
