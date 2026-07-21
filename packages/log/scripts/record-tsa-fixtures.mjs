#!/usr/bin/env node
/**
 * Record real RFC 3161 tokens from the public TSAs into test fixtures.
 *
 * CI verifies tokens offline against these recordings so the tamper suite
 * does not depend on TSA availability (T10: a TSA outage must never be able
 * to fail a build or an exam). The nightly `live-tsa` job exercises the
 * network path against the real services.
 *
 * Regenerate:  node scripts/record-tsa-fixtures.mjs
 */
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { blake2b } from "@zw/crypto";
import { PUBLIC_TSAS, Rfc3161AnchorBackend } from "../dist/anchor.js";

const here = dirname(fileURLToPath(import.meta.url));
const outPath = join(here, "..", "test", "fixtures", "tsa-tokens.json");

// A fixed, documented root so the fixture is reproducible and reviewable.
const ROOT_PREIMAGE = "zero-window/test-fixture/checkpoint-root/v1";
const root = blake2b(Buffer.from(ROOT_PREIMAGE, "utf8"));

const fixtures = { root_preimage: ROOT_PREIMAGE, root: root.toString("hex"), anchors: [] };

for (const [key, config] of Object.entries(PUBLIC_TSAS)) {
  const backend = new Rfc3161AnchorBackend({ ...config, timeoutMs: 30_000 });
  try {
    const anchor = await backend.anchor(root);
    await backend.verify(anchor, root);
    fixtures.anchors.push({ key, ...anchor });
    console.log(`${key}: recorded, genTime ${new Date(anchor.genTime).toISOString()}`);
  } catch (err) {
    console.error(`${key}: FAILED — ${err.message}`);
    process.exitCode = 1;
  }
}

if (fixtures.anchors.length < 2) {
  console.error("refusing to write fixtures: fewer than two independent TSAs recorded");
  process.exit(1);
}

await writeFile(outPath, JSON.stringify(fixtures, null, 2) + "\n");
console.log(`wrote ${fixtures.anchors.length} anchors to ${outPath}`);
