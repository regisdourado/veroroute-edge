import type { Context } from "hono";
import { getProviderCredentials, selectActiveCredential } from "@/routing/keyPool";
import { forbidden, isModelAllowed } from "@/admin/auth";
import type { AuthPrincipal } from "@/admin/auth";
import type { EnvBindings } from "@/types/provider";

const JEV_MODEL = "typesafe/jev-1.13";
const OPENROUTER_DECISIONS_URL = "https://openrouter.ai/api/alpha/decisions";
const MAX_BODY_BYTES = 64 * 1024;

type JevContext = Context<{
  Bindings: EnvBindings;
  Variables: { principal: AuthPrincipal };
}>;

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export async function handleJevDecision(c: JevContext): Promise<Response> {
  if (!c.req.header("Authorization")?.startsWith("Bearer ")) {
    return c.json({ error: { message: "Use Authorization: Bearer", type: "unauthorized" } }, 401);
  }
  const principal = c.get("principal");
  // A virtual key must explicitly allow Jev. An empty allowlist is too broad
  // for a separately billed decision endpoint.
  if (principal.kind === "virtual" &&
      (principal.allowedModels.length === 0 || !isModelAllowed(principal, JEV_MODEL))) {
    return forbidden("Chave virtual sem permissao explicita para Jev");
  }

  const raw = await c.req.text();
  if (new TextEncoder().encode(raw).length > MAX_BODY_BYTES) {
    return c.json({ error: { message: "Requisicao excede 64 KiB", type: "validation" } }, 413);
  }

  let input: unknown;
  try {
    input = JSON.parse(raw);
  } catch {
    return c.json({ error: { message: "JSON invalido", type: "validation" } }, 400);
  }
  if (!isObject(input) || !isObject(input.state) || !isObject(input.questions) ||
      Object.keys(input.questions).length === 0 ||
      (input.model !== undefined && input.model !== JEV_MODEL)) {
    return c.json({
      error: { message: "Envie state e questions como objetos e model=typesafe/jev-1.13", type: "validation" },
    }, 400);
  }

  const credentials = await getProviderCredentials(c.env, "openrouter");
  if (credentials.length === 0) {
    return c.json({ error: { message: "Configure OPENROUTER_API_KEYS como segredo na Cloudflare", type: "configuration" } }, 503);
  }
  const { apiKey } = await selectActiveCredential(c.env, "openrouter");

  try {
    const upstream = await fetch(OPENROUTER_DECISIONS_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ model: JEV_MODEL, state: input.state, questions: input.questions }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!upstream.ok) {
      return Response.json({
        error: { message: "OpenRouter rejeitou a decisao", type: "upstream", upstream_status: upstream.status },
      }, { status: upstream.status, headers: { "Cache-Control": "no-store" } });
    }
    return new Response(upstream.body, {
      status: upstream.status,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
    });
  } catch {
    return c.json({ error: { message: "Falha de comunicacao com OpenRouter", type: "upstream" } }, 502);
  }
}
