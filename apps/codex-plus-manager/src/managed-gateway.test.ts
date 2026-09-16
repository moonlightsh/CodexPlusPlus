import { test } from "node:test";
import assert from "node:assert/strict";

import { describeManagedGatewayStatus } from "./managed-gateway.ts";

test("status description covers conflict, ready, disabled and not-configured", () => {
  assert.equal(
    describeManagedGatewayStatus({
      enabled: false,
      credentialConfigured: false,
      externalCatalogConflict: null,
    }),
    "not-configured",
  );
  assert.equal(
    describeManagedGatewayStatus({
      enabled: true,
      credentialConfigured: true,
      externalCatalogConflict: null,
    }),
    "ready",
  );
  assert.equal(
    describeManagedGatewayStatus({
      enabled: true,
      credentialConfigured: false,
      externalCatalogConflict: null,
    }),
    "disabled",
  );
  assert.equal(
    describeManagedGatewayStatus({
      enabled: false,
      credentialConfigured: true,
      externalCatalogConflict: null,
    }),
    "disabled",
  );
  assert.equal(
    describeManagedGatewayStatus({
      enabled: true,
      credentialConfigured: true,
      externalCatalogConflict: "/tmp/x.json",
    }),
    "conflict",
  );
});
