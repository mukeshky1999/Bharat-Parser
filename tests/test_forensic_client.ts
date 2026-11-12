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
} from '../ui/renderer/api/forensicClient';

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
    assert(toastTriggerCount === 1, 'Toast listener was triggered exactly once for 412 response');
    assert(capturedToast !== null, 'Captured toast event is not null');
    assert(capturedToast?.status === 412, 'Toast event status matches 412');
    assert(capturedToast?.type === 'warning', 'Toast event type is warning for 412 status');
    assert(
      Boolean(capturedToast?.title?.includes('412 Precondition Failed')),
      'Toast title includes "412 Precondition Failed"'
    );
    assert(
      Boolean(capturedToast?.message?.includes('No forensic case is currently loaded')),
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
    let fetchRejected = false;
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

    assert(fetchRejected === true, 'Fetch rejected when MockAbortController was aborted');
    assert(rejectedErrorName === 'AbortError', 'Fetch rejected specifically with AbortError');

    // Subtest 2B: Assert pre-aborted controller rejects immediately with AbortError
    const preAbortedController = new MockAbortController();
    preAbortedController.abort();
    let preAbortedRejected = false;
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

    // =========================================================================
    // TEST CASE 3: adding a device to a case sends the mode and the examiner's label
    // =========================================================================
    console.log('\n--- Test Suite 3: Add a device to an existing case ---');
    let sentBody: Record<string, unknown> = {};
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      if (String(input).endsWith('/api/case/ingest')) {
        sentBody = JSON.parse(String(init?.body ?? '{}'));
      }
      return new Response(JSON.stringify({ success: true, evidence_item: 'EV-002' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    };
    const added = await forensicClient.ingestCase('phoneB', 'CASE-2', undefined, undefined, { mode: 'add', label: 'Second phone' });
    assert(added.success === true && added.evidence_item === 'EV-002', 'Client returns the new evidence item id');
    assert(sentBody.mode === 'add' && sentBody.label === 'Second phone', 'Client sends mode "add" and the label');
    await forensicClient.ingestCase('phoneA', 'CASE-2');
    assert(sentBody.mode === 'replace', 'Client defaults to starting the case again, never to adding silently');

    globalThis.fetch = async (): Promise<Response> =>
      new Response(JSON.stringify({ cases: [{ case_id: 'C1', evidence_items: [] }] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    const recent = await forensicClient.getRecentCases();
    assert(recent.length === 1 && recent[0].case_id === 'C1', 'Client lists saved cases');
    globalThis.fetch = async (): Promise<Response> => new Response('{}', { status: 500 });
    assert((await forensicClient.getRecentCases()).length === 0, 'A failing server gives an empty list, not a crash');

    // =========================================================================
    // TEST CASE 4: ingest progress is read as the server sends it, and a failure gives null
    // =========================================================================
    console.log('\n--- Test Suite 4: Ingest progress ---');
    let askedUrl = '';
    globalThis.fetch = async (input: RequestInfo | URL): Promise<Response> => {
      askedUrl = String(input);
      return new Response(JSON.stringify({
        job_id: 'j1', state: 'running', stage: 'parse', stage_label: 'Reading databases', stage_index: 4, stage_count: 11,
        units_done: 3, units_total: 12, unit: 'files', fraction: 0.25, stage_eta_s: null, detail: 'msgstore.db', seq: 7, events: []
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    const prog = await forensicClient.getIngestProgress(5);
    assert(askedUrl.endsWith('/api/case/ingest/progress?since=5'), 'Client asks only for events after the last one seen');
    assert(prog !== null && prog.stage_index === 4 && prog.fraction === 0.25 && prog.detail === 'msgstore.db', 'Client returns the server values unchanged');
    globalThis.fetch = async (): Promise<Response> => new Response('{}', { status: 500 });
    assert((await forensicClient.getIngestProgress()) === null, 'A failing server gives null, not an invented progress');

    // =========================================================================
    // TEST CASE 5: search, record and coverage calls
    // =========================================================================
    console.log('\n--- Test Suite 5: Search and coverage ---');
    globalThis.fetch = async (input: RequestInfo | URL): Promise<Response> => {
      askedUrl = String(input);
      return new Response(JSON.stringify({ query: 'x', mode: 'contains', total: 1, hits: [], tables: {}, complete: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    const found = await forensicClient.searchCase('भुगतान 1500', { mode: 'contains', tables: ['chats', 'transactions'], evidenceItem: 'EV-002', limit: 10 });
    const asked = new URL(askedUrl, 'http://x');
    assert(asked.pathname === '/api/case/search' && asked.searchParams.get('q') === 'भुगतान 1500' && asked.searchParams.get('mode') === 'contains'
      && asked.searchParams.get('tables') === 'chats,transactions' && asked.searchParams.get('evidence_item') === 'EV-002', 'Search sends the text, mode and filters unchanged');
    assert(found.data?.total === 1 && found.error === null, 'Search returns what the server sent');
    globalThis.fetch = async (): Promise<Response> => new Response(JSON.stringify({ detail: 'The pattern is not valid: missing )' }), { status: 422, headers: { 'Content-Type': 'application/json' } });
    const refused = await forensicClient.searchCase('(', { mode: 'regex' });
    assert(refused.data === null && (refused.error ?? '').includes('not valid'), 'A refused search gives the reason, not an empty result');
    globalThis.fetch = async (input: RequestInfo | URL): Promise<Response> => {
      askedUrl = String(input);
      return new Response(JSON.stringify({ table: 'chats', id: 3, record: { id: 3, Decoded_By: null } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    const rec = await forensicClient.getRecord('chats', 3);
    assert(askedUrl.endsWith('/api/case/record?table=chats&id=3') && rec.data !== null && rec.data.Decoded_By === null, 'A value that was not recorded stays null');
    await forensicClient.getCoverage('EV-001');
    assert(askedUrl.endsWith('/api/case/coverage?evidence_item=EV-001'), 'Coverage can be asked for one device');

    // =========================================================================
    // TEST CASE 6: tags and timeline calls
    // =========================================================================
    console.log('\n--- Test Suite 6: Tags and timeline ---');
    let sentTags = '';
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      askedUrl = String(input);
      sentTags = String(init?.body ?? '');
      return new Response(JSON.stringify({ tag: 'relied_upon', applied: 1, already_tagged: 0, missing: [], counts: {}, events: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    await forensicClient.tagRecords('relied_upon', [{ table: 'chats', id: 3 }], 'note');
    assert(askedUrl.endsWith('/api/case/tags') && JSON.parse(sentTags).records[0].id === 3 && JSON.parse(sentTags).tag === 'relied_upon', 'Tagging sends the tag and the record references');
    await forensicClient.untagRecords('relied_upon', [{ table: 'chats', id: 3 }]);
    assert(askedUrl.endsWith('/api/case/tags/remove'), 'Removing a tag uses its own call');
    await forensicClient.getTimeline({ group: 'clock_only', from: '2026-02-01', tables: ['chats', 'calls'], bucket: 'day', descending: true });
    const tl = new URL(askedUrl, 'http://x');
    assert(tl.pathname === '/api/case/timeline' && tl.searchParams.get('group') === 'clock_only' && tl.searchParams.get('from') === '2026-02-01'
      && tl.searchParams.get('tables') === 'chats,calls' && tl.searchParams.get('bucket') === 'day' && tl.searchParams.get('descending') === 'true', 'Timeline sends the group, range and filters');
    globalThis.fetch = async (): Promise<Response> => new Response(JSON.stringify({ detail: 'Not a table with a time: contacts.' }), { status: 422, headers: { 'Content-Type': 'application/json' } });
    const badTl = await forensicClient.getTimeline({ tables: ['contacts'] });
    assert(badTl.data === null && (badTl.error ?? '').includes('Not a table'), 'A refused timeline gives the reason');

    // Suite 7: tagged outputs
    console.log('\n--- Test Suite 7: Tagged outputs ---');
    let sentPkg = '';
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      askedUrl = String(input);
      sentPkg = String(init?.body ?? '');
      return new Response(JSON.stringify({ success: true, directory: 'd', viewer_path: 'v', included: 0, withheld: 1, merkle_root: 'r', accounts: [], left_out: [], note: '' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    await forensicClient.buildReviewPackage([{ path: 'a', disposition: 'INCLUDE' }], [], undefined, true);
    assert(JSON.parse(sentPkg).acknowledge_tagged === true, 'The package call carries the tag acknowledgement');
    await forensicClient.buildReviewPackage([{ path: 'a', disposition: 'INCLUDE' }], []);
    assert(JSON.parse(sentPkg).acknowledge_tagged === false, 'The acknowledgement is off unless asked for');
    await forensicClient.getAccountsOfInterest();
    assert(askedUrl.endsWith('/api/report/accounts-of-interest'), 'Accounts of interest has its own call');

    // Suite 8: media
    console.log('\n--- Test Suite 8: Media ---');
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      askedUrl = String(input);
      sentPkg = String(init?.body ?? '');
      return new Response(JSON.stringify({ total: 0, items: [], hash_sets: [], entries: 1, skipped_lines: 0, matching_files_now: 0 }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    await forensicClient.getMedia({ kind: 'image', inSet: 'Lab list', outsideSets: true, hasGps: false, limit: 20 });
    const mq = new URL(askedUrl, 'http://x');
    assert(mq.pathname === '/api/case/media' && mq.searchParams.get('kind') === 'image' && mq.searchParams.get('in_set') === 'Lab list'
      && mq.searchParams.get('outside_sets') === 'true' && mq.searchParams.get('has_gps') === 'false', 'Media listing sends its filters');
    await forensicClient.importHashSet('Lab list', 'known_notable', 'a'.repeat(32), 'note');
    assert(askedUrl.endsWith('/api/case/hashsets') && JSON.parse(sentPkg).kind === 'known_notable' && JSON.parse(sentPkg).source_note === 'note', 'Hash list import sends the values you supply');
    await forensicClient.analyseMedia({ redo: true, limit: 5 });
    assert(askedUrl.endsWith('/api/case/media/analyse') && JSON.parse(sentPkg).redo === true && JSON.parse(sentPkg).limit === 5, 'Analyse sends redo and the limit');
    await forensicClient.getSimilarMedia(7, 3);
    assert(askedUrl.endsWith('/api/case/media/7/similar?max_distance=3'), 'Similarity asks for a distance');
    globalThis.fetch = async (): Promise<Response> => new Response('nope', { status: 404 });
    assert((await forensicClient.getMediaThumbnail(1)) === null, 'A missing thumbnail gives null, not a broken URL');

    // Suite 9: key broker
    console.log('\n--- Test Suite 9: Key broker ---');
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      askedUrl = String(input);
      sentPkg = String(init?.body ?? '');
      return new Response(JSON.stringify({ success: true, keys: [], needed: [], events: [], note: '' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    await forensicClient.ingestCase('/ev', undefined, undefined, undefined, { mode: 'add', keys: { app: 'ab'.repeat(32) } });
    assert(JSON.parse(sentPkg).keys.app === 'ab'.repeat(32) && JSON.parse(sentPkg).mode === 'add', 'Keys you type go with the ingest request');
    await forensicClient.ingestCase('/ev', undefined, undefined, undefined, { keys: {} });
    assert(!('keys' in JSON.parse(sentPkg)), 'An empty key list is not sent');
    await forensicClient.checkKeys({ k: 'value' });
    assert(askedUrl.endsWith('/api/keys/check') && JSON.parse(sentPkg).keys.k === 'value', 'Keys are described by their own call');
    await forensicClient.getCaseKeys();
    assert(askedUrl.endsWith('/api/case/keys'), 'Files needing a key have their own call');
    const fsMod = await import('fs');
    const panel = fsMod.readFileSync('ui/renderer/inspectors/KeyBrokerPanel.tsx', 'utf8');
    assert(!/localStorage|sessionStorage|indexedDB|persist\(|zustand/.test(panel), 'The key panel keeps typed keys in component state only');

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
