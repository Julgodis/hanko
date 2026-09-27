import assert from "node:assert/strict";
import test from "node:test";
import { generateHankoPalette, generateHankoPath, ORIGINAL_HANKO_GRADIENT } from "../src/components/generateHankoPath.ts";

test("a seed produces the same generated Hanko every time", () => {
  const first = generateHankoPath("test-seal-2026");
  assert.equal(generateHankoPath("test-seal-2026"), first);
});

test("different seeds produce different connected grid marks", () => {
  const first = generateHankoPath("user-one");
  const second = generateHankoPath("user-two");
  assert.notEqual(first, second);

  for (const path of [first, second]) {
    const edges = path.match(/M \d+ \d+ L \d+ \d+/g) ?? [];
    assert.ok(edges.length >= 10);
    for (const edge of edges) {
      const [, x1, y1, x2, y2] = edge.match(/M (\d+) (\d+) L (\d+) (\d+)/) ?? [];
      for (const coordinate of [Number(x1), Number(y1), Number(x2), Number(y2)]) {
        assert.ok(coordinate >= 278 && coordinate <= 746);
        assert.equal((coordinate - 278) % 117, 0);
      }
      assert.ok(x1 === x2 || y1 === y2, "every generated stroke must be orthogonal");
    }
  }
});

test("a seed produces a stable palette of solid inks and gradients", () => {
  const palette = generateHankoPalette("test-seal-2026");
  assert.deepEqual(generateHankoPalette("test-seal-2026"), palette);
  assert.equal(palette.length, 9);
  assert.equal(palette[0].name, "Hanko original");
  assert.equal(palette[0].color, ORIGINAL_HANKO_GRADIENT);
  assert.equal(palette[0].kind, "gradient");
  assert.equal(palette.slice(1).filter((variant) => variant.kind === "solid").length, 4);
  assert.equal(palette.slice(1).filter((variant) => variant.kind === "gradient").length, 4);
  assert.ok(palette.slice(1, 5).every((variant) => /^#[\da-f]{6}$/i.test(variant.color)));
  assert.ok(palette.slice(5).every((variant) => /^linear\(#[\da-f]{6},#[\da-f]{6}\)$/i.test(variant.color)));
  assert.notDeepEqual(generateHankoPalette("another-seal"), palette);
});
