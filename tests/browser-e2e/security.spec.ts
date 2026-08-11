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

interface IssuedChallenge extends ProofRequest {
  challengeId: string;
}

interface NoteView {
  id: string;
  title: string;
  body: string;
  visibility: 'public' | 'private';
  version: number;
  authorSubject: string;
  authorFriendlyName: string | null;
  likeCount: number;
  replies: Array<{ id: string; body: string; authorSubject: string }>;
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

  test('requires visible login approval, binds aud to RP A, and reuses only the scoped session', async () => {
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

    const page = await context.newPage();
    await page.goto(RP_A_ORIGIN);
    await expect(page.getByRole('heading', { name: 'Notes without accounts' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log in', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log in with Nexus' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Log in to write' })).toHaveCount(0);
    await expect(page.getByText('Log in to write.', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Edit' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Delete' })).toHaveCount(0);

    const popupPromise = page.waitForEvent('popup');
    await page.getByRole('button', { name: 'Log in', exact: true }).click();
    const popup = await popupPromise;
    await expect(popup.getByRole('heading', { name: 'Allow a bound proof?' })).toBeVisible();
    await expect(popup.getByText(RP_A_ORIGIN, { exact: true }).first()).toBeVisible();
    await expect(popup.getByText('session.start', { exact: true })).toBeVisible();
    await expect(popup.getByText('urn:rowo:nexus-notes:session', { exact: true })).toBeVisible();
    await approveWallet(popup);
    await expect(page.getByText('Session active', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log out', exact: true })).toBeVisible();
    await page.getByLabel('Friendly name').fill('friendly_name');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByText('friendly_name', { exact: true }).first()).toBeVisible();

    const loginRequest = lastRequest('/api/operations');
    expect(loginRequest).toBeDefined();
    const loginBody = JSON.parse(loginRequest?.body ?? '') as {
      challengeId: string;
      operation: { action: string };
      proof: OwnershipProofV1;
    };
    proofForA = loginBody.proof;
    expect(loginBody.operation).toEqual({ action: 'session.start' });
    expect(proofForA.payload.aud).toBe(RP_A_ORIGIN);
    expect(proofForA.payload.act).toBe('session.start');
    expect(proofForA.payload.resource).toBe('urn:rowo:nexus-notes:session');
    expect(Object.hasOwn(proofForA.payload, 'localScopes')).toBe(false);

    const replay = await context.request.post(`${RP_A_ORIGIN}/api/operations`, {
      data: loginBody,
    });
    expect(replay.status()).toBe(409);
    await expectApiCode(replay, 'CHALLENGE_EXPIRED');

    const title = 'One approval, scoped session';
    await page.getByRole('button', { name: 'Write a note' }).click();
    await page.getByLabel('Title').fill(title);
    await page
      .getByRole('textbox', { name: /^Note/u })
      .fill('Creating this note must use the RP session without opening the wallet again.');
    const unexpectedPopup = page.waitForEvent('popup', { timeout: 1_000 }).catch(() => null);
    await page.getByRole('button', { name: 'Publish note' }).click();
    expect(await unexpectedPopup).toBeNull();
    await expect(page.getByRole('heading', { name: title })).toBeVisible();
    expect(findSessionOperationRequest(title)).toBeDefined();

    ownedNote = (await listNotes(RP_A_ORIGIN)).find((note) => note.title === title) as NoteView;
    expect(ownedNote.authorSubject).toBe(proofForA.payload.subject);
    expect(ownedNote.authorFriendlyName).toBe('friendly_name');
    await expect(page).toHaveURL(`${RP_A_ORIGIN}/notes/${ownedNote.id}`);
    await page.reload();
    await expect(page.getByRole('heading', { name: title })).toBeVisible();

    const historyPage = await context.newPage();
    await historyPage.goto(WALLET_ORIGIN);
    await expect(historyPage.getByText('1 authorization', { exact: true })).toBeVisible();
    await historyPage.getByRole('button', { name: 'View details' }).click();
    await expect(historyPage.getByRole('heading', { name: 'Authorization history' })).toBeVisible();
    const authorizationHistory = historyPage.locator('ol');
    await expect(authorizationHistory.getByText(RP_A_ORIGIN, { exact: true })).toBeVisible();
    await expect(historyPage.getByText('session.start', { exact: true })).toBeVisible();
    await expect(
      historyPage.getByText('urn:rowo:nexus-notes:session', { exact: true }),
    ).toBeVisible();
    await expect(historyPage.getByText('New app scope', { exact: true })).toBeVisible();
    await expect(historyPage.getByText(proofForA.payload.nonce, { exact: true })).toHaveCount(0);
    await historyPage.close();
    await page.close();
  });

  test('supports private notes, replies, and idempotent likes in the browser', async () => {
    const shortenedDestinations: string[] = [];
    let shortLinkSequence = 0;
    await context.route('https://pi3.dev/create', async (route) => {
      const request = route.request();
      if (request.method() === 'OPTIONS') {
        await route.fulfill({
          status: 204,
          headers: {
            'Access-Control-Allow-Headers': 'content-type',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Origin': '*',
          },
        });
        return;
      }
      const requestBody = request.postDataJSON() as { url?: unknown };
      expect(typeof requestBody.url).toBe('string');
      shortenedDestinations.push(requestBody.url as string);
      shortLinkSequence += 1;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({
          slug: `e2e${shortLinkSequence}`,
          link: `https://pi3.dev/e2e${shortLinkSequence}`,
          expiresAt: null,
        }),
      });
    });

    const page = await context.newPage();
    await page.goto(RP_A_ORIGIN);
    await page.getByText(ownedNote.title, { exact: true }).click();
    await expect(page.getByRole('button', { name: 'Edit' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Delete' })).toBeVisible();

    await page.getByRole('button', { name: /^Like · 0$/u }).click();
    await expect(page.getByRole('button', { name: /^Unlike · 1$/u })).toBeVisible();
    await page.getByRole('button', { name: /^Unlike · 1$/u }).click();
    await expect(page.getByRole('button', { name: /^Like · 0$/u })).toBeVisible();

    await page.getByPlaceholder('Write a reply…').fill('The creator can reply too.');
    await page.getByRole('button', { name: 'Reply' }).click();
    await expect(page.getByText('The creator can reply too.', { exact: true })).toBeVisible();
    const noteWithReply = (await listNotes(RP_A_ORIGIN)).find((note) => note.id === ownedNote.id);
    const createdReply = noteWithReply?.replies.find(
      (reply) => reply.body === 'The creator can reply too.',
    );
    expect(createdReply).toBeDefined();
    const replyUrl = `${RP_A_ORIGIN}/notes/${ownedNote.id}/replies/${createdReply?.id}`;
    await page.goto(replyUrl);
    await expect(page).toHaveURL(replyUrl);
    const focusedReply = page.locator(`[data-reply-id="${createdReply?.id}"]`);
    await expect(focusedReply).toBeFocused();

    await page.getByRole('button', { name: 'Share note' }).click();
    await expect(page.getByRole('link', { name: 'Short link for note' })).toHaveAttribute(
      'href',
      'https://pi3.dev/e2e1',
    );
    await focusedReply.getByRole('button', { name: 'Share reply' }).click();
    await expect(focusedReply.getByRole('link', { name: 'Short link for reply' })).toHaveAttribute(
      'href',
      'https://pi3.dev/e2e2',
    );
    expect(shortenedDestinations).toEqual([`${RP_A_ORIGIN}/notes/${ownedNote.id}`, replyUrl]);

    await focusedReply.getByRole('button', { name: 'Delete reply' }).click();
    await expect(page.getByText('The creator can reply too.', { exact: true })).toHaveCount(0);

    await page.getByRole('button', { name: 'Notes', exact: true }).click();
    await page.getByRole('button', { name: 'Write a note' }).click();
    await page.getByRole('button', { name: /private Only this subject/iu }).click();
    const privateTitle = 'Creator-only browser note';
    await page.getByLabel('Title').fill(privateTitle);
    await page.getByRole('textbox', { name: /^Note/u }).fill('This note is not public.');
    await page.getByRole('button', { name: 'Publish note' }).click();
    await expect(page.getByRole('heading', { name: privateTitle })).toBeVisible();
    await expect(page.getByText('Private', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Share note' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Share reply' })).toHaveCount(0);
    const privateNoteUrl = page.url();
    expect(privateNoteUrl).toMatch(new RegExp(`${RP_A_ORIGIN}/notes/nt_[A-Za-z0-9_-]+$`, 'u'));

    const browser = context.browser();
    if (browser === null) throw new Error('Expected a browser.');
    const anonymous = await browser.newContext({ ignoreHTTPSErrors: true });
    const anonymousPage = await anonymous.newPage();
    await anonymousPage.goto(privateNoteUrl);
    await expect(anonymousPage).toHaveURL(`${RP_A_ORIGIN}/`);
    await expect(anonymousPage.getByText(privateTitle, { exact: true })).toHaveCount(0);
    await anonymousPage.goto(`${RP_A_ORIGIN}/notes/${ownedNote.id}`);
    await expect(anonymousPage).toHaveURL(`${RP_A_ORIGIN}/notes/${ownedNote.id}`);
    await expect(anonymousPage.getByRole('heading', { name: ownedNote.title })).toBeVisible();
    await expect(anonymousPage.getByText('friendly_name', { exact: true })).toBeVisible();
    await expect(anonymousPage.getByText('Log in to reply.', { exact: true })).toBeVisible();
    await expect(anonymousPage.getByRole('button', { name: 'Log in to reply' })).toHaveCount(0);
    await expect(
      anonymousPage.getByText(
        'Log in with Nexus to reveal controls available to your current subject.',
        { exact: true },
      ),
    ).toHaveCount(0);
    await anonymousPage.goto(`${RP_A_ORIGIN}/notes/${ownedNote.id}/replies/rpy_missingreply000`);
    await expect(anonymousPage).toHaveURL(`${RP_A_ORIGIN}/notes/${ownedNote.id}`);
    await expect(anonymousPage.getByRole('heading', { name: ownedNote.title })).toBeVisible();
    await anonymousPage.goto(`${RP_A_ORIGIN}/notes/nt_does-not-exist`);
    await expect(anonymousPage).toHaveURL(`${RP_A_ORIGIN}/`);
    await expect(
      anonymousPage.getByRole('heading', { name: 'Notes without accounts' }),
    ).toBeVisible();
    await anonymous.close();
    await page.close();
    await context.unroute('https://pi3.dev/create');
  });

  test('rejects an A proof at B and pins the wallet response to origin, source, and requestId', async () => {
    const challenge = await issueChallenge(RP_B_ORIGIN);
    const crossOriginReplay = await context.request.post(`${RP_B_ORIGIN}/api/operations`, {
      data: {
        challengeId: challenge.challengeId,
        operation: { action: 'session.start' },
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
    await approveWallet(opened.popup);

    const response = await readRawWalletResponse(page);
    expect(response.origin).toBe(WALLET_ORIGIN);
    expect(response.sourceMatches).toBe(true);
    expect(response.data.requestId).toBe(opened.requestId);
    expect(response.data.type).toBe('NEXUS_PROOF_RESULT');
    expect(response.data.proof?.payload.aud).toBe(RP_B_ORIGIN);

    const accepted = await context.request.post(`${RP_B_ORIGIN}/api/operations`, {
      data: {
        challengeId: challenge.challengeId,
        operation: { action: 'session.start' },
        proof: response.data.proof,
      },
    });
    expect(accepted.status()).toBe(200);
    await page.close();
  });

  test('rejects an RP-supplied fake aud field and keeps wallet scopes local', async () => {
    const challenge = await issueChallenge(RP_A_ORIGIN);
    const page = await context.newPage();
    await page.goto(RP_A_ORIGIN);
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

    assertNoWalletSecretsOrScopes(networkLog);
  });

  test('denial and popup close create no session', async () => {
    await context.request.delete(`${RP_A_ORIGIN}/api/session`, {
      headers: { 'X-Nexus-Notes-Session': '1' },
    });
    const loggedIn = await context.newPage();
    await loggedIn.goto(RP_A_ORIGIN);
    await expect(loggedIn.getByRole('button', { name: 'Log in', exact: true })).toBeVisible();

    const deniedPopupPromise = loggedIn.waitForEvent('popup');
    await loggedIn.getByRole('button', { name: 'Log in', exact: true }).click();
    const deniedPopup = await deniedPopupPromise;
    await expect(deniedPopup.getByRole('heading', { name: 'Allow a bound proof?' })).toBeVisible();
    await deniedPopup.getByRole('button', { name: 'Deny' }).click();
    await expect(loggedIn.getByText('Login cancelled', { exact: true })).toBeVisible();
    expect((await context.request.get(`${RP_A_ORIGIN}/api/session`)).status()).toBe(401);

    const closedPopupPromise = loggedIn.waitForEvent('popup');
    await loggedIn.getByRole('button', { name: 'Log in', exact: true }).click();
    const closedPopup = await closedPopupPromise;
    await expect(closedPopup.getByRole('heading', { name: 'Allow a bound proof?' })).toBeVisible();
    await closedPopup.close();
    await expect(loggedIn.getByText('Login cancelled', { exact: true })).toBeVisible();
    expect((await context.request.get(`${RP_A_ORIGIN}/api/session`)).status()).toBe(401);
    await loggedIn.close();
  });

  test('serves production CSP, makes no third-party requests, and captures visual QA', async () => {
    const observed: Request[] = [];
    const onRequest = (request: Request): void => {
      observed.push(request);
    };
    context.on('request', onRequest);
    await mkdir(VISUAL_QA_DIR, { recursive: true });

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
      } else {
        expect(csp).toContain("connect-src 'self' https://pi3.dev");
      }
      await expect(page.locator('body')).toBeVisible();
    }

    await page.goto(RP_A_ORIGIN);
    await page.screenshot({
      path: resolve(VISUAL_QA_DIR, 'reference-rp-desktop.png'),
      fullPage: true,
      animations: 'disabled',
    });
    const challenge = await issueChallenge(RP_A_ORIGIN);
    const opened = await openRawWalletRequest(page, toProofRequest(challenge));
    await expect(opened.popup.getByRole('heading', { name: 'Allow a bound proof?' })).toBeVisible();
    await opened.popup.screenshot({
      path: resolve(VISUAL_QA_DIR, 'proof-consent.png'),
      fullPage: true,
      animations: 'disabled',
    });
    await opened.popup.getByRole('button', { name: 'Deny' }).click();

    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: resolve(VISUAL_QA_DIR, 'reference-rp-mobile.png'),
      fullPage: true,
      animations: 'disabled',
    });
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

  test('authoritative revocation invalidates the existing session before its next mutation', async () => {
    const page = await context.newPage();
    await page.goto(RP_A_ORIGIN);
    const popupPromise = page.waitForEvent('popup');
    await page.getByRole('button', { name: 'Log in', exact: true }).click();
    const popup = await popupPromise;
    await approveWallet(popup);
    await expect(page.getByText('Session active', { exact: true })).toBeVisible();

    const wallet = await context.newPage();
    await wallet.goto(WALLET_ORIGIN);
    await wallet.getByRole('button', { name: 'View details' }).click();
    await wallet.getByRole('button', { name: 'Dispose' }).click();
    await wallet.locator('#dispose-confirmation').fill(IDENTITY_LABEL);
    await wallet.getByRole('button', { name: 'Dispose forever' }).click();
    await expect(wallet.getByText('Disposed', { exact: true })).toBeVisible();
    await wallet.close();

    const response = await context.request.post(`${RP_A_ORIGIN}/api/session-operations`, {
      headers: { 'X-Nexus-Notes-Session': '1' },
      data: {
        action: 'note.delete',
        noteId: ownedNote.id,
        expectedVersion: ownedNote.version,
      },
    });
    expect(response.status()).toBe(401);
    await expectApiCode(response, 'SESSION_INVALID');
    const unchanged = (await listNotes(RP_A_ORIGIN)).find((note) => note.id === ownedNote.id);
    expect(unchanged?.body).toBe(ownedNote.body);
    assertNoWalletSecretsOrScopes(networkLog);
    await page.close();
  });
});

async function approveWallet(popup: Page): Promise<void> {
  const button = popup.getByRole('button', { name: /Approve (new scope|and sign)/u });
  await expect(button).toBeVisible();
  await button.click();
}

async function issueChallenge(origin: string): Promise<IssuedChallenge> {
  const response = await context.request.post(`${origin}/api/challenges`, {
    data: { action: 'session.start' },
  });
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
      const state = { popup: null, requestSent: false } as E2eState;
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

function lastRequest(pathname: string): LoggedRequest | undefined {
  for (let index = networkLog.length - 1; index >= 0; index -= 1) {
    const request = networkLog[index];
    if (
      request !== undefined &&
      request.method === 'POST' &&
      new URL(request.url).pathname === pathname
    ) {
      return request;
    }
  }
  return undefined;
}

function findSessionOperationRequest(text: string): LoggedRequest | undefined {
  return networkLog.find(
    (request) =>
      request.method === 'POST' &&
      new URL(request.url).pathname === '/api/session-operations' &&
      request.body?.includes(text) === true,
  );
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
  const serialized = requests
    .filter((request) => request.body !== null)
    .map((request) => request.body as string)
    .join('\n')
    .toLowerCase();
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
  for (const request of registryRequests) expect(new URL(request.url).search).toBe('');
}
