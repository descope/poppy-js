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
  PoppyAgent,
  type PoppyUser,
  type Session,
} from "../src/index.ts";

type Step =
  | { action: "discover"; website: string }
  | { action: "request"; url: string; method?: string; body?: string }
  | { action: "sign_in"; scopes: string[] }
  | { action: "sign_out" }
  | { action: "converse"; text: string }
  | { action: "request_with_approval"; url: string; method: string; body: string };

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
