/**
 * This SDK's "everything agent" for the conformance suite: it reads the scenario from the environment
 * and carries out each step with the SDK's public API.
 *
 *   node packages/conformance/src/cli.ts agent --command "node examples/conformance-agent.ts"
 *
 * Agents in other languages follow the same contract: read POPPY_CONFORMANCE_CONTEXT, do each step in
 * order, print one JSON line per failed step, and keep going.
 */
import {
  approvalFor,
  type Company,
  operationFromResponse,
  operatorKeyId,
  PoppyAgent,
  PoppyError,
  type PoppyUser,
  type Session,
} from "../src/index.ts";

type Step =
  | { action: "discover"; website: string }
  | { action: "request"; url: string; method?: string; body?: string }
  | { action: "sign_in"; scopes: string[] }
  | { action: "sign_out" }
  | { action: "converse"; text: string }
  | { action: "request_with_approval"; url: string; method: string; body: string }
  | { action: "task_coverage" }
  | { action: "report_task"; task: string; description: string }
  | { action: "join_browser" }
  | { action: "fetch_page"; url: string }
  | { action: "handoff_then_cancel"; text: string }
  | { action: "read_skill"; name: string }
  | { action: "sign_in_device"; scopes: string[] }
  | { action: "new_session" }
  | { action: "request_rate_limited"; url: string }
  | { action: "converse_with_approval"; text: string };

interface Context {
  steps: Step[];
  client_id: string;
  redirect_uri: string;
  signing_key?: JsonWebKey & { kid: string };
  user_id: string;
}

const context = JSON.parse(process.env["POPPY_CONFORMANCE_CONTEXT"] ?? "{}") as Context;
if (context.signing_key === undefined)
  throw new Error("bring your own key: this agent uses the test identity");

const agent = new PoppyAgent({
  clientId: context.client_id,
  signingKey: {
    privateKey: await crypto.subtle.importKey(
      "jwk",
      context.signing_key,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    ),
    kid: context.signing_key.kid,
  },
  redirectUri: context.redirect_uri,
  extensions: { operations: { version: "2" } },
  // Web Bot Auth, so bot defenses can recognize the operator (spec 5.3). The key is made for this
  // run: a real agent publishes its public key in a key directory and keeps the private one.
  operatorSignature: await (async () => {
    const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    return {
      privateKey: pair.privateKey,
      keyId: await operatorKeyId(pair.publicKey),
      signatureAgent: new URL("/keys", context.client_id).href,
    };
  })(),
});

let company: Company | undefined;
let user: PoppyUser | undefined;
let session: Session | undefined;

function ready(): { company: Company; user: PoppyUser; session: Session } {
  if (company === undefined || user === undefined || session === undefined)
    throw new Error("no Company: discovery didn't succeed");
  return { company, user, session };
}

async function run(step: Step): Promise<void> {
  switch (step.action) {
    case "discover":
      company = await agent.discover(step.website);
      user = await agent.user(company, context.user_id);
      session = user.session();
      return;
    case "request": {
      const response = await ready().session.fetch(step.url, {
        ...(step.method === undefined ? {} : { method: step.method }),
        ...(step.body === undefined ? {} : { body: step.body }),
      });
      await response.body?.cancel();
      return;
    }
    case "sign_in": {
      const { company: c, user: u } = ready();
      const { url } = await u.startDirectSignIn({ scope: step.scopes });
      // The User's browser: open the link and come back with the redirect.
      const browser = await fetch(url, { redirect: "manual" });
      const callback = browser.headers.get("location");
      if (callback === null) throw new Error("the authorization endpoint didn't redirect back");
      await agent.completeDirectSignIn(c, callback);
      return;
    }
    case "sign_out":
      await ready().user.signOut();
      return;
    case "converse": {
      const { conversation } = await ready().session.conversations().start({ text: step.text });
      await conversation.send({ text: "Thanks" });
      await conversation.readAll();
      return;
    }
    case "task_coverage":
      // 0.3 reads the excluded tasks document; 0.4 gets all three from tasks.endpoint (spec 9).
      await ready().session.taskCoverage();
      return;
    case "report_task":
      await ready().session.sendFeedback({ task: step.task, description: step.description });
      return;
    case "join_browser": {
      const { company: c, session: s } = ready();
      const endpoint = c.browserSessionEndpoint;
      if (endpoint === undefined) throw new Error("the Company lists no browser_session_endpoint");
      // The agent's own browser: load the page, read the code out of its form, submit it.
      const page = await (await fetch(endpoint)).text();
      const code = /name="code" value="([^"]+)"/.exec(page)?.[1] ?? "";
      try {
        await s.authorizeBrowserCode(code);
      } catch (error) {
        // From 0.4 a signed-in join needs poppy:browser-sign-in; without it, join signed out.
        if (!(error instanceof PoppyError) || error.error !== "insufficient_scope") throw error;
        await s.authorizeBrowserCode(code, { signedOut: true });
      }
      await fetch(`${endpoint.replace(/\/$/, "")}/submit`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ code }).toString(),
      });
      return;
    }
    case "fetch_page": {
      const response = await ready().session.fetchPage(step.url);
      await response.body?.cancel();
      return;
    }
    case "handoff_then_cancel": {
      const { conversation } = await ready().session.conversations().start({ text: step.text });
      // Read until the Company has no work in progress before deciding anything (spec 8.7).
      let update = await conversation.readAll({ wait: 1 });
      while (update.working) update = await conversation.readAll({ wait: 1 });
      await conversation.handoff();
      await conversation.cancelHandoff();
      return;
    }
    case "read_skill":
      await ready().session.fetchSkill(step.name);
      return;
    case "sign_in_device": {
      const started = await ready().user.startDeviceSignIn({ scope: step.scopes });
      // A real agent shows verificationUri and userCode with the Company's name and domain; the
      // SDK has already checked the link's host (spec 4.3).
      await started.wait();
      return;
    }
    case "new_session":
      session = ready().user.session();
      return;
    case "request_rate_limited": {
      const { session: s } = ready();
      const first = await s.fetch(step.url);
      await first.body?.cancel();
      if (first.status === 429) {
        // Retry-After is a floor, not a suggestion (spec 5.6).
        const seconds = Number(first.headers.get("retry-after") ?? 0);
        await new Promise((resolve) => setTimeout(resolve, seconds * 1000 + 50));
      }
      const again = await s.fetch(step.url);
      await again.body?.cancel();
      return;
    }
    case "converse_with_approval": {
      const { session: s } = ready();
      const { conversation, update } = await s
        .conversations()
        .start({ text: step.text }, { wait: 2 });
      let events = update.events;
      if (!events.some((e) => e.type === "message"))
        events = (await conversation.readAll({ wait: 2 })).events;
      const operation = events
        .flatMap((e) => (e.type === "message" && e.message.operation ? [e.message.operation] : []))
        .at(-1);
      if (operation === undefined) throw new Error("the Company Agent asked for no approval");
      await conversation.send({
        text: "The user approved this.",
        approval: approvalFor(operation),
      });
      return;
    }
    case "request_with_approval": {
      const { session: s } = ready();
      const init = { method: step.method, body: step.body };
      const refused = await s.fetch(step.url, init);
      const operation = await operationFromResponse(refused);
      await refused.body?.cancel();
      if (operation === undefined) return;
      // The conformance suite stands in for the User, who approves.
      const approved = await s.fetch(step.url, { ...init, approval: approvalFor(operation) });
      await approved.body?.cancel();
      return;
    }
  }
}

for (const step of context.steps) {
  try {
    await run(step);
  } catch (error) {
    console.log(
      JSON.stringify({
        step: step.action,
        error: error instanceof Error ? error.message : String(error),
      }),
    );
  }
}
