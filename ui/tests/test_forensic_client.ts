/**
 * Hostile QA Automation Unit Tests: forensicClient.ts Hardening
 * Validates:
 * 1. Mock fetch returns 412 Precondition Failed -> asserts notifyHttpError toast listener is triggered.
 * 2. Mock AbortController -> asserts fetch rejects with AbortError when controller is aborted.
 */

import {
  forensicClient,
  registerApiToastListener,
  ApiToastEvent,
} from '../renderer/api/forensicClient';

console.log('=== [HOSTILE QA AUTOMATION: FORENSIC CLIENT UNIT TESTS] ===\n');

let totalTests = 0;
let passedTests = 0;

function assert(condition: boolean, testName: string) {
  totalTests++;
  if (condition) {
    console.log(`[PASS] ${testName}`);
    passedTests++;
  } else {
    console.error(`[FAIL] ${testName}`);
    throw new Error(`Assertion failed: ${testName}`);
  }
}

async function runForensicClientTests() {
  const originalFetch = globalThis.fetch;

  try {
    // =========================================================================
    // TEST CASE 1: 412 Precondition Failed triggers notifyHttpError toast listener
    // =========================================================================
    console.log('--- Test Suite 1: HTTP 412 Precondition Failed Toast Trigger ---');

    let capturedToast: ApiToastEvent | null = null;
    let toastTriggerCount = 0;

    // Register active toast listener
    registerApiToastListener((event: ApiToastEvent) => {
      capturedToast = event;
      toastTriggerCount++;
    });

    // Mock fetch to simulate FastAPI backend returning 412 Precondition Failed
    globalThis.fetch = async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
      const mockResponseBody = JSON.stringify({
        detail: 'Precondition Failed: No forensic case is currently loaded. Ingest evidence or open a case workspace first.'
      });
      return new Response(mockResponseBody, {
        status: 412,
        statusText: 'Precondition Failed',
        headers: { 'Content-Type': 'application/json' }
      });
    };

    // Invoke forensicClient method that hits the backend
    const result412 = await forensicClient.getHexWindow('evidence.raw', 0, 4096);

    // Verify toast listener was triggered
    const toast = capturedToast as ApiToastEvent | null;
    assert(toastTriggerCount === 1, 'Toast listener was triggered exactly once for 412 response');
    assert(toast !== null, 'Captured toast event is not null');
    assert(toast?.status === 412, 'Toast event status matches 412');
    assert(toast?.type === 'warning', 'Toast event type is warning for 412 status');
    assert(
      Boolean(toast?.title?.includes('412 Precondition Failed')),
      'Toast title includes "412 Precondition Failed"'
    );
    assert(
      Boolean(toast?.message?.includes('No forensic case is currently loaded')),
      'Toast message contains expected backend detail error message'
    );
    assert(
      result412.raw_hex === undefined || result412.hex_dump === '',
      'Client safely handles 412 response without unhandled crash'
    );

    // Clean up listener
    registerApiToastListener(null);

    // =========================================================================
    // TEST CASE 2: Mock AbortController & AbortError Rejection
    // =========================================================================
    console.log('\n--- Test Suite 2: Mock AbortController & AbortError Rejection ---');

    // Implement a strict mock AbortController conforming to DOM AbortController specification
    class MockAbortSignal {
      public aborted = false;
      public reason: any = undefined;
      private listeners: Array<() => void> = [];

      public addEventListener(type: string, listener: () => void): void {
        if (type === 'abort') {
          this.listeners.push(listener);
        }
      }

      public removeEventListener(type: string, listener: () => void): void {
        this.listeners = this.listeners.filter(l => l !== listener);
      }

      public _dispatchAbort(reason?: any): void {
        this.aborted = true;
        this.reason = reason || new Error('This operation was aborted');
        for (const fn of this.listeners) {
          try {
            fn();
          } catch {
            // ignore
          }
        }
      }
    }

    class MockAbortController {
      public signal = new MockAbortSignal();

      public abort(reason?: any): void {
        this.signal._dispatchAbort(reason);
      }
    }

    // Set up mock fetch that responds to signal abort
    globalThis.fetch = async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const signal = init?.signal as unknown as MockAbortSignal | AbortSignal;

      // If already aborted, reject immediately
      if (signal?.aborted) {
        const abortErr = new Error('The user aborted a request.');
        abortErr.name = 'AbortError';
        throw abortErr;
      }

      return new Promise<Response>((resolve, reject) => {
        if (signal) {
          signal.addEventListener('abort', () => {
            const abortErr = new Error('The user aborted a request.');
            abortErr.name = 'AbortError';
            reject(abortErr);
          });
        }
        // Simulated delayed request that resolves if not aborted
        setTimeout(() => {
          resolve(new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          }));
        }, 1000);
      });
    };

    // Subtest 2A: Assert direct mock fetch rejects with AbortError when controller.abort() is called
    const mockController = new MockAbortController();
    let fetchRejected: boolean = false;
    let rejectedErrorName = '';

    const fetchPromise = globalThis.fetch('http://127.0.0.1:8000/api/case/ingest', {
      signal: mockController.signal as unknown as AbortSignal
    }).catch((err: Error) => {
      fetchRejected = true;
      rejectedErrorName = err.name;
    });

    // Abort while request is pending
    mockController.abort();
    await fetchPromise;

    assert(Boolean(fetchRejected), 'Fetch rejected when MockAbortController was aborted');
    assert(rejectedErrorName === 'AbortError', 'Fetch rejected specifically with AbortError');

    // Subtest 2B: Assert pre-aborted controller rejects immediately with AbortError
    const preAbortedController = new MockAbortController();
    preAbortedController.abort();
    let preAbortedRejected: boolean = false;
    let preAbortedErrorName = '';

    try {
      await globalThis.fetch('http://127.0.0.1:8000/api/case/ingest', {
        signal: preAbortedController.signal as unknown as AbortSignal
      });
    } catch (err: any) {
      preAbortedRejected = true;
      preAbortedErrorName = err.name;
    }

    assert(preAbortedRejected === true, 'Fetch with pre-aborted controller rejects immediately');
    assert(preAbortedErrorName === 'AbortError', 'Pre-aborted rejection error name is AbortError');

    // Subtest 2C: Verify forensicClient handles AbortSignal via ingestCase and checkHealth
    const clientController = new MockAbortController();
    const clientIngestPromise = forensicClient.ingestCase(
      'evidence.raw',
      'CASE_TEST',
      'Test Case',
      clientController.signal as unknown as AbortSignal
    );
    clientController.abort();
    const ingestResult = await clientIngestPromise;

    assert(ingestResult.success === false, 'Client ingestCase returns success: false on abort');
    assert(
      ingestResult.error === 'Request aborted' || (typeof ingestResult.detail === 'string' && ingestResult.detail.includes('abort')),
      'Client surfaces "Request aborted" error message when aborted'
    );

    console.log(`=== RESULTS: ALL ${passedTests}/${totalTests} FORENSIC CLIENT TESTS PASSED (100% SUCCESS) ===\n`);
  } finally {
    // Restore original fetch
    globalThis.fetch = originalFetch;
  }
}

runForensicClientTests().catch((err) => {
  console.error('[FATAL] Test runner encountered uncaught error:', err);
  process.exit(1);
});
