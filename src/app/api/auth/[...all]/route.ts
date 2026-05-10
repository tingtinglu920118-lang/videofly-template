import { toNextJsHandler } from "better-auth/next-js";

import { auth } from "@/lib/auth";

const handlers = toNextJsHandler(auth);

async function readTurnstileToken(request: Request): Promise<string | null> {
  const contentType = request.headers.get("content-type") ?? "";

  if (contentType.includes("application/json")) {
    const body = (await request.clone().json().catch(() => null)) as
      | { turnstileToken?: unknown }
      | null;
    const token = body?.turnstileToken;
    return typeof token === "string" && token.length > 0 ? token : null;
  }

  if (
    contentType.includes("application/x-www-form-urlencoded") ||
    contentType.includes("multipart/form-data")
  ) {
    const form = await request.clone().formData().catch(() => null);
    const token = form?.get("turnstileToken");
    return typeof token === "string" && token.length > 0 ? token : null;
  }

  return null;
}

async function verifyTurnstile(turnstileToken: string): Promise<boolean> {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) return false;

  const body = new URLSearchParams({
    secret,
    response: turnstileToken,
  });

  const verifyResponse = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body,
    },
  );

  const verifyResult = (await verifyResponse.json().catch(() => null)) as
    | { success?: unknown }
    | null;

  return verifyResult?.success === true;
}

export const GET = handlers.GET;
export const POST = async (request: Request) => {
  const { pathname } = new URL(request.url);
  const needsTurnstile =
    pathname.includes("/api/auth/sign-in") ||
    pathname.includes("/api/auth/signin") ||
    pathname.includes("/api/auth/sign-up") ||
    pathname.includes("/api/auth/signup") ||
    pathname.includes("/api/auth/magic-link") ||
    pathname.includes("/api/auth/magiclink");

  if (needsTurnstile) {
    const turnstileToken = await readTurnstileToken(request);
    if (!turnstileToken) {
      return Response.json({ error: "人机验证失败，请重试" }, { status: 403 });
    }

    const ok = await verifyTurnstile(turnstileToken);
    if (!ok) {
      return Response.json({ error: "人机验证失败，请重试" }, { status: 403 });
    }
  }

  return handlers.POST(request);
};
