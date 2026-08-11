import { randomBytes } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

import {
  expect,
  test,
  type APIResponse,
  type BrowserContext,
  type Page,
  type Request,
} from '@playwright/test';
import type { OwnershipProofV1, ProofRequest } from '@nexus/protocol';

import {
  REGISTRY_ORIGIN,
  RP_A_ORIGIN,
  RP_B_ORIGIN,
  TEST_ORIGINS,
  WALLET_ORIGIN,
} from './origins.js';

const IDENTITY_LABEL = 'E2E local-only identity';
const VISUAL_QA_DIR = resolve('test-results', 'browser-e2e', 'visual-qa');

interface LoggedRequest {
  method: string;
  url: string;
  body: string | null;
}

interface NoteDraft {
  title: string;
  body: string;
}

type NoteOperation =
  | { action: 'note.create'; draft: NoteDraft }
  | {
      action: 'note.edit';
      noteId: string;
      expectedVersion: number;
      draft: NoteDraft;
    }
  | { action: 'note.delete'; noteId: string; expectedVersion: number };

interface IssuedChallenge extends ProofRequest {
  challengeId: string;
}

interface NoteView {
  id: string;
  title: string;
  body: string;
  version: number;
  authorSubject: string;
}

interface RawWalletResponse {
  origin: string;
  sourceMatches: boolean;
  data: {
    channel: string;
    type: string;
    requestId: string;
    proof?: OwnershipProofV1;
    error?: { code: string };
  };
}

let context!: BrowserContext;
let networkLog: LoggedRequest[];
let proofForA: OwnershipProofV1;
let ownedNote: NoteView;

test.describe.serial('Nexus browser security boundary', () => {
  test.beforeAll(async ({ browser }) => {
    networkLog = [];
    context = await browser.newContext({ ignoreHTTPSErrors: true });
    context.on('request', (request) => {
      networkLog.push({
        method: request.method(),
        url: request.url(),
        body: request.postData(),
      });
    });
  });

  test.afterAll(async () => {
    await context?.close();
  });

  test('requires visible approval, binds aud to RP A, and rejects replay', async () => {
    const wallet = await context.newPage();
    await wallet.goto(WALLET_ORIGIN);
    await expect(
      wallet.getByRole('heading', { name: 'Choose who you are, each time.' }),
    ).toBeVisible();
    await wallet.getByRole('button', { name: 'Create first identity' }).click();
    await wallet.getByLabel('Local label (optional)').fill(IDENTITY_LABEL);
    await wallet.getByRole('button', { name: 'Create identity' }).click();
    await expect(wallet.getByRole('heading', { name: IDENTITY_LABEL }).first()).toBeVisible();
    await wallet.close();

    const title = 'Audience A approval gate';
    const page = await context.newPage();
    await page.goto(RP_A_ORIGIN);
    await page.getByRole('button', { name: 'Write a note' }).click();
    await page.getByLabel('Title').fill(title);
    await page
      .getByRole('textbox', { name: /^Note/u })
      .fill('The relying party must not mutate until the wallet visibly approves.');

    const popupPromise = page.waitForEvent('popup');
    await page.getByRole('button', { name: 'Continue with Nexus' }).click();
    const popup = await popupPromise;
    await expect(popup.getByRole('heading', { name: 'Allow a bound proof?' })).toBeVisible();
    await expect(popup.getByText(RP_A_ORIGIN, { exact: true }).first()).toBeVisible();
    await expect(popup.getByRole('button', { name: 'Approve new scope' })).toBeVisible();

    const beforeApproval = await listNotes(RP_A_ORIGIN);
    expect(beforeApproval.some((note) => note.title === title)).toBe(false);
    expect(findOperationRequest(title)).toBeUndefined();

    await popup.getByRole('button', { name: 'Approve new scope' }).click();
    await expect(page.getByText('Proof approved', { exact: true })).toBeVisible();
    await expect(page.getByText(title, { exact: true })).toBeVisible();

    await expect.poll(() => findOperationRequest(title)).not.toBeUndefined();
    const operationRequest = findOperationRequest(title) as LoggedRequest;
    const operationBody = JSON.parse(operationRequest.body ?? '') as {
      challengeId: string;
      operation: NoteOperation;
      proof: OwnershipProofV1;
    };
    proofForA = operationBody.proof;
    expect(proofForA.payload.aud).toBe(RP_A_ORIGIN);
    expect(Object.hasOwn(proofForA.payload, 'localScopes')).toBe(false);

    const replay = await context.request.post(`${RP_A_ORIGIN}/api/operations`, {
      data: operationBody,
    });
    expect(replay.status()).toBe(409);
    await expectApiCode(replay, 'CHALLENGE_EXPIRED');

    ownedNote = (await listNotes(RP_A_ORIGIN)).find((note) => note.title === title) as NoteView;
    expect(ownedNote.authorSubject).toBe(proofForA.payload.subject);
    await page.close();
  });

  test('rejects A proof at B and pins the wallet response to origin, source, and requestId', async () => {
    const operation: NoteOperation = {
      action: 'note.create',
      draft: {
        title: 'Audience B boundary',
        body: 'A proof from RP A must not authorize this RP B operation.',
      },
    };
    const challenge = await issueChallenge(RP_B_ORIGIN, operation);

    const crossOriginReplay = await context.request.post(`${RP_B_ORIGIN}/api/operations`, {
      data: {
        challengeId: challenge.challengeId,
        operation,
        proof: proofForA,
      },
    });
    expect(crossOriginReplay.status()).toBe(403);
    await expectApiCode(crossOriginReplay, 'CHALLENGE_MISMATCH');

    const page = await context.newPage();
    await page.goto(RP_B_ORIGIN);
    await expect(page.getByRole('heading', { name: 'Notes without accounts' })).toBeVisible();
    const opened = await openRawWalletRequest(page, toProofRequest(challenge));
    await expect(opened.popup.getByRole('heading', { name: 'Allow a bound proof?' })).toBeVisible();
    await expect(opened.popup.getByText(RP_B_ORIGIN, { exact: true }).first()).toBeVisible();
    await expect(opened.popup.getByText('New app scope', { exact: true })).toBeVisible();
    await opened.popup.getByRole('button', { name: 'Approve new scope' }).click();

    const response = await readRawWalletResponse(page);
    expect(response.origin).toBe(WALLET_ORIGIN);
    expect(response.sourceMatches).toBe(true);
    expect(response.data.requestId).toBe(opened.requestId);
    expect(response.data.type).toBe('NEXUS_PROOF_RESULT');
    expect(response.data.proof?.payload.aud).toBe(RP_B_ORIGIN);

    const accepted = await context.request.post(`${RP_B_ORIGIN}/api/operations`, {
      data: {
        challengeId: challenge.challengeId,
        operation,
        proof: response.data.proof,
      },
    });
    expect(accepted.status()).toBe(200);
    expect(
      (await listNotes(RP_B_ORIGIN)).some((note) => note.title === operation.draft.title),
    ).toBe(true);
    await page.close();
  });

  test('rejects an RP-supplied fake aud field and keeps the scope list local', async () => {
    const operation: NoteOperation = {
      action: 'note.create',
      draft: { title: 'Rejected fake audience', body: 'This challenge must remain unused.' },
    };
    const challenge = await issueChallenge(RP_A_ORIGIN, operation);
    const page = await context.newPage();
    await page.goto(RP_A_ORIGIN);
    await expect(page.getByRole('heading', { name: 'Notes without accounts' })).toBeVisible();
    const opened = await openRawWalletRequest(page, {
      ...toProofRequest(challenge),
      aud: RP_B_ORIGIN,
    });
    await waitForRawRequestToBeSent(page);
    await expect(opened.popup.getByRole('heading', { name: 'Allow a bound proof?' })).toHaveCount(
      0,
    );
    await expect(
      opened.popup.getByRole('heading', { name: 'Choose who you are, each time.' }),
    ).toBeVisible();
    await page.waitForTimeout(300);
    expect(await hasRawWalletResponse(page)).toBe(false);
    await opened.popup.close();
    await page.close();

    const wallet = await context.newPage();
    await wallet.goto(WALLET_ORIGIN);
    await expect(wallet.getByText('2 app scopes', { exact: true })).toBeVisible();
    await wallet.getByRole('button', { name: 'View details' }).click();
    await expect(wallet.getByText(RP_A_ORIGIN, { exact: true })).toBeVisible();
    await expect(wallet.getByText(RP_B_ORIGIN, { exact: true })).toBeVisible();
    await wallet.close();

    assertNoWalletSecretsOrScopes(networkLog);
  });

  test('denial and popup close leave the RP unchanged', async () => {
    const deniedTitle = 'Denied request stays absent';
    const deniedPage = await context.newPage();
    await openComposer(deniedPage, deniedTitle);
    const deniedPopupPromise = deniedPage.waitForEvent('popup');
    await deniedPage.getByRole('button', { name: 'Continue with Nexus' }).click();
    const deniedPopup = await deniedPopupPromise;
    await expect(deniedPopup.getByRole('heading', { name: 'Allow a bound proof?' })).toBeVisible();
    await deniedPopup.getByRole('button', { name: 'Deny' }).click();
    await expect(deniedPage.getByText('Approval cancelled', { exact: true })).toBeVisible();
    expect((await listNotes(RP_A_ORIGIN)).some((note) => note.title === deniedTitle)).toBe(false);
    expect(findOperationRequest(deniedTitle)).toBeUndefined();
    await deniedPage.close();

    const closedTitle = 'Closed popup stays absent';
    const closedPage = await context.newPage();
    await openComposer(closedPage, closedTitle);
    const closedPopupPromise = closedPage.waitForEvent('popup');
    await closedPage.getByRole('button', { name: 'Continue with Nexus' }).click();
    const closedPopup = await closedPopupPromise;
    await expect(closedPopup.getByRole('heading', { name: 'Allow a bound proof?' })).toBeVisible();
    await closedPopup.close();
    await expect(closedPage.getByText('Approval cancelled', { exact: true })).toBeVisible();
    expect((await listNotes(RP_A_ORIGIN)).some((note) => note.title === closedTitle)).toBe(false);
    expect(findOperationRequest(closedTitle)).toBeUndefined();
    await closedPage.close();
  });

  test('serves production CSP and makes no third-party requests', async () => {
    const observed: Request[] = [];
    const onRequest = (request: Request): void => {
      observed.push(request);
    };
    context.on('request', onRequest);

    const page = await context.newPage();
    for (const origin of [RP_A_ORIGIN, RP_B_ORIGIN, WALLET_ORIGIN]) {
      const response = await page.goto(origin);
      expect(response).not.toBeNull();
      const csp = response?.headers()['content-security-policy'] ?? '';
      expect(csp).toContain("default-src 'self'");
      expect(csp).toContain("script-src 'self'");
      expect(csp).toContain("object-src 'none'");
      expect(csp).not.toContain("script-src 'unsafe-inline'");
      if (origin === WALLET_ORIGIN) {
        expect(csp).toContain(`connect-src 'self' ${REGISTRY_ORIGIN}`);
      }
      await expect(page.locator('body')).toBeVisible();
    }
    await page.close();
    context.off('request', onRequest);

    const unexpected = observed.filter((request) => {
      const url = new URL(request.url());
      return (
        (url.protocol === 'http:' || url.protocol === 'https:') && !TEST_ORIGINS.has(url.origin)
      );
    });
    expect(unexpected.map((request) => request.url())).toEqual([]);
  });

  test('captures deterministic desktop, consent, wallet, and mobile visual QA', async () => {
    await mkdir(VISUAL_QA_DIR, { recursive: true });

    const wallet = await context.newPage();
    await wallet.goto(WALLET_ORIGIN);
    await expect(wallet.getByRole('heading', { name: 'Identity wallet' })).toBeVisible();
    await wallet.screenshot({
      path: resolve(VISUAL_QA_DIR, 'wallet-dashboard.png'),
      fullPage: true,
      animations: 'disabled',
    });
    await wallet.close();

    const rp = await context.newPage();
    await rp.goto(RP_A_ORIGIN);
    await expect(rp.getByText(/proof-backed notes/u)).toBeVisible();
    await rp.screenshot({
      path: resolve(VISUAL_QA_DIR, 'reference-rp-desktop.png'),
      fullPage: true,
      animations: 'disabled',
    });

    const operation: NoteOperation = {
      action: 'note.create',
      draft: {
        title: 'Visual consent fixture',
        body: 'Public fixture content used only for visual quality assurance.',
      },
    };
    const challenge = await issueChallenge(RP_A_ORIGIN, operation);
    const opened = await openRawWalletRequest(rp, toProofRequest(challenge));
    await expect(opened.popup.getByRole('heading', { name: 'Allow a bound proof?' })).toBeVisible();
    await opened.popup.screenshot({
      path: resolve(VISUAL_QA_DIR, 'proof-consent.png'),
      fullPage: true,
      animations: 'disabled',
    });
    await opened.popup.getByRole('button', { name: 'Deny' }).click();
    await rp.close();

    const mobile = await context.newPage();
    await mobile.setViewportSize({ width: 390, height: 844 });
    await mobile.goto(RP_A_ORIGIN);
    await expect(mobile.getByText(/proof-backed notes/u)).toBeVisible();
    await mobile.screenshot({
      path: resolve(VISUAL_QA_DIR, 'reference-rp-mobile.png'),
      fullPage: true,
      animations: 'disabled',
    });
    await mobile.close();
  });

  test('authoritative revocation blocks create, edit, and delete with pre-revocation proofs', async () => {
    const operations: NoteOperation[] = [
      {
        action: 'note.create',
        draft: {
          title: 'Blocked after revocation',
          body: 'This proof was signed before disposal but submitted after it.',
        },
      },
      {
        action: 'note.edit',
        noteId: ownedNote.id,
        expectedVersion: ownedNote.version,
        draft: { title: ownedNote.title, body: 'A revoked identity must not edit this note.' },
      },
      {
        action: 'note.delete',
        noteId: ownedNote.id,
        expectedVersion: ownedNote.version,
      },
    ];

    const pending: Array<{
      challenge: IssuedChallenge;
      operation: NoteOperation;
      proof: OwnershipProofV1;
    }> = [];
    const rp = await context.newPage();
    await rp.goto(RP_A_ORIGIN);
    await expect(rp.getByRole('heading', { name: 'Notes without accounts' })).toBeVisible();
    for (const operation of operations) {
      const challenge = await issueChallenge(RP_A_ORIGIN, operation);
      const opened = await openRawWalletRequest(rp, toProofRequest(challenge));
      await expect(
        opened.popup.getByRole('heading', { name: 'Allow a bound proof?' }),
      ).toBeVisible();
      await opened.popup.getByRole('button', { name: 'Approve and sign' }).click();
      const response = await readRawWalletResponse(rp);
      expect(response.data.proof).toBeDefined();
      pending.push({ challenge, operation, proof: response.data.proof as OwnershipProofV1 });
    }
    await rp.close();

    const wallet = await context.newPage();
    await wallet.goto(WALLET_ORIGIN);
    await wallet.getByRole('button', { name: 'View details' }).click();
    await wallet.getByRole('button', { name: 'Dispose' }).click();
    await wallet.locator('#dispose-confirmation').fill(IDENTITY_LABEL);
    await wallet.getByRole('button', { name: 'Dispose forever' }).click();
    await expect(wallet.getByText('Disposed', { exact: true })).toBeVisible();
    await wallet.close();

    for (const item of pending) {
      const response = await context.request.post(`${RP_A_ORIGIN}/api/operations`, {
        data: {
          challengeId: item.challenge.challengeId,
          operation: item.operation,
          proof: item.proof,
        },
      });
      expect(response.status()).toBe(403);
      await expectApiCode(response, 'IDENTITY_REVOKED');
    }

    const after = await listNotes(RP_A_ORIGIN);
    expect(after.some((note) => note.title === 'Blocked after revocation')).toBe(false);
    const unchanged = after.find((note) => note.id === ownedNote.id);
    expect(unchanged?.body).toBe(ownedNote.body);
    assertNoWalletSecretsOrScopes(networkLog);
  });
});

async function openComposer(page: Page, title: string): Promise<void> {
  await page.goto(RP_A_ORIGIN);
  await expect(page.getByText(/proof-backed notes/u)).toBeVisible();
  await page.getByRole('button', { name: 'Write a note' }).click();
  await expect(page.getByRole('heading', { name: 'Write anonymously' })).toBeVisible();
  await page.waitForTimeout(250);
  await page.getByLabel('Title').fill(title);
  await page
    .getByRole('textbox', { name: /^Note/u })
    .fill('Cancelling or closing the popup must leave no protected mutation.');
}

async function issueChallenge(origin: string, operation: NoteOperation): Promise<IssuedChallenge> {
  const response = await context.request.post(`${origin}/api/challenges`, { data: operation });
  expect(response.status()).toBe(201);
  const value = (await response.json()) as { challenge: IssuedChallenge };
  return value.challenge;
}

async function listNotes(origin: string): Promise<NoteView[]> {
  const response = await context.request.get(`${origin}/api/notes`);
  expect(response.status()).toBe(200);
  const value = (await response.json()) as { notes: NoteView[] };
  return value.notes;
}

async function expectApiCode(response: APIResponse, code: string): Promise<void> {
  const value = (await response.json()) as { error?: { code?: string } };
  expect(value.error?.code).toBe(code);
}

async function openRawWalletRequest(
  page: Page,
  request: ProofRequest | (ProofRequest & { aud: string }),
): Promise<{ popup: Page; requestId: string }> {
  const requestId = randomBytes(16).toString('base64url');
  await page.evaluate(
    ({ requestId: id, proofRequest, walletOrigin }) => {
      type E2eState = {
        listener: (event: MessageEvent<unknown>) => void;
        popup: Window | null;
        response?: RawWalletResponse;
        requestSent: boolean;
      };
      type E2eWindow = Window & { __nexusE2e?: E2eState };
      const target = window as E2eWindow;
      if (target.__nexusE2e !== undefined) {
        window.removeEventListener('message', target.__nexusE2e.listener);
      }
      const state = {
        popup: null,
        requestSent: false,
      } as E2eState;
      state.listener = (event: MessageEvent<unknown>): void => {
        if (event.source !== state.popup || event.origin !== walletOrigin) return;
        const data = event.data as { type?: string; requestId?: string };
        if (data?.type === 'NEXUS_READY' && !state.requestSent) {
          state.requestSent = true;
          state.popup?.postMessage(
            {
              channel: 'nexus.popup.v1',
              type: 'NEXUS_PROOF_REQUEST',
              requestId: id,
              request: proofRequest,
            },
            walletOrigin,
          );
          return;
        }
        if (
          data?.requestId === id &&
          (data.type === 'NEXUS_PROOF_RESULT' || data.type === 'NEXUS_PROOF_ERROR')
        ) {
          state.response = {
            origin: event.origin,
            sourceMatches: event.source === state.popup,
            data: event.data as RawWalletResponse['data'],
          };
          window.removeEventListener('message', state.listener);
        }
      };
      target.__nexusE2e = state;
      window.addEventListener('message', state.listener);

      const trigger = document.createElement('button');
      trigger.id = 'nexus-e2e-open-wallet';
      trigger.type = 'button';
      trigger.textContent = 'Open E2E wallet';
      trigger.style.cssText =
        'position:fixed;inset:8px auto auto 8px;z-index:2147483647;padding:8px;background:white;color:black';
      trigger.addEventListener(
        'click',
        () => {
          state.popup = window.open(walletOrigin, '_blank', 'popup,width=480,height=720');
          trigger.remove();
        },
        { once: true },
      );
      document.body.append(trigger);
    },
    { requestId, proofRequest: request, walletOrigin: WALLET_ORIGIN },
  );
  const popupPromise = page.waitForEvent('popup');
  await page.locator('#nexus-e2e-open-wallet').click();
  return { popup: await popupPromise, requestId };
}

async function readRawWalletResponse(page: Page): Promise<RawWalletResponse> {
  await page.waitForFunction(() => {
    const target = window as Window & { __nexusE2e?: { response?: RawWalletResponse } };
    return target.__nexusE2e?.response !== undefined;
  });
  return page.evaluate(() => {
    const target = window as Window & { __nexusE2e?: { response?: RawWalletResponse } };
    if (target.__nexusE2e?.response === undefined) throw new Error('Wallet response is missing.');
    return target.__nexusE2e.response;
  });
}

async function waitForRawRequestToBeSent(page: Page): Promise<void> {
  await page.waitForFunction(() => {
    const target = window as Window & { __nexusE2e?: { requestSent: boolean } };
    return target.__nexusE2e?.requestSent === true;
  });
}

function hasRawWalletResponse(page: Page): Promise<boolean> {
  return page.evaluate(() => {
    const target = window as Window & { __nexusE2e?: { response?: RawWalletResponse } };
    return target.__nexusE2e?.response !== undefined;
  });
}

function findOperationRequest(title: string): LoggedRequest | undefined {
  return networkLog.find((request) => {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/api/operations')
      return false;
    return request.body?.includes(title) === true;
  });
}

function toProofRequest(challenge: IssuedChallenge): ProofRequest {
  return {
    action: challenge.action,
    resource: challenge.resource,
    nonce: challenge.nonce,
    expiresAt: challenge.expiresAt,
    ...(challenge.contextHash === undefined ? {} : { contextHash: challenge.contextHash }),
  };
}

function assertNoWalletSecretsOrScopes(requests: LoggedRequest[]): void {
  const bodies = requests
    .filter((request) => request.body !== null)
    .map((request) => request.body as string);
  const serialized = bodies.join('\n').toLowerCase();
  for (const forbidden of [
    '"localid"',
    '"localscopes"',
    '"label"',
    '"privatekey"',
    '"privatekeyref"',
    '"revocationsecret"',
    '"revocationsecretref"',
    '"controllerid"',
    '"vaultid"',
    '"installationid"',
  ]) {
    expect(serialized).not.toContain(forbidden);
  }
  expect(serialized).not.toContain(IDENTITY_LABEL.toLowerCase());

  const registryRequests = requests.filter((request) =>
    request.url.startsWith(`${REGISTRY_ORIGIN}/v1/identity/`),
  );
  expect(registryRequests.length).toBeGreaterThan(0);
  for (const request of registryRequests) {
    expect(new URL(request.url).search).toBe('');
  }
}
