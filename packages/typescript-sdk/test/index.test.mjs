import assert from "node:assert/strict";
import test from "node:test";

import { AuthForge, AuthForgeError } from "../dist/index.js";

test("service requests normalize the base URL and authenticate with the API key", async () => {
  let request;
  const client = new AuthForge({
    baseUrl: "https://auth.example.test/",
    apiKey: "af_test_secret",
    fetch: async (input, init) => {
      request = { input, init };
      return Response.json({ id: "app-1", name: "Example", slug: "example" });
    },
  });

  const application = await client.service.application();
  assert.equal(request.input, "https://auth.example.test/api/v1/service/application");
  assert.equal(request.init.headers.get("Authorization"), "Bearer af_test_secret");
  assert.equal(application.id, "app-1");
});

test("structured API errors preserve status, code, and request ID", async () => {
  const client = new AuthForge({
    baseUrl: "https://auth.example.test",
    fetch: async () => Response.json(
      { error: { code: "FORBIDDEN", message: "Permission denied", request_id: "req-1" } },
      { status: 403 },
    ),
  });

  await assert.rejects(
    client.auth.login("user@example.test", "not-a-real-secret"),
    (error) => error instanceof AuthForgeError
      && error.status === 403
      && error.code === "FORBIDDEN"
      && error.requestId === "req-1",
  );
});
