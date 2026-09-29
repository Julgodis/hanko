import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createServer } from "vite";
import { renderToStaticMarkup } from "react-dom/server";
import { createProfileDraft } from "../src/lib/profile.ts";

let server;
let ProfileFields;
before(async () => {
  // Use the application's TSX compiler without adding a second test toolchain.
  server = await createServer({ configFile: false, server: { middlewareMode: true }, appType: "custom" });
  ({ ProfileFields } = await server.ssrLoadModule("/src/components/ProfileFields.tsx"));
});
after(async () => { await server?.close(); });

function elements(node) {
  if (Array.isArray(node)) return node.flatMap(elements);
  if (!node || typeof node !== "object" || !node.props) return [];
  return [node, ...elements(node.props.children)];
}

test("shared profile form marks required inputs and renders saved values", () => {
  const value = createProfileDraft({ username: "alice", address: { country: "Sweden" } });
  const view = ProfileFields({ value, onChange: () => {}, requiredUserClaims: ["preferred_username", "country"] });
  const fields = elements(view);
  const username = fields.find(element => element.type === "input" && element.props.autoComplete === "username");
  const country = fields.find(element => element.type === "input" && element.props.autoComplete === "country-name");
  assert.equal(username.props.required, true);
  assert.equal(country.props.required, true);
  const html = renderToStaticMarkup(view);
  assert.match(html, /value="alice"/);
  assert.match(html, /value="Sweden"/);
  assert.match(html, /<label/);
});

test("editing profile inputs preserves sibling fields and normalizes usernames", () => {
  let value = createProfileDraft({ displayName: "Alice", address: { country: "Sweden", locality: "Stockholm" } });
  const change = (autoComplete, text) => {
    const view = ProfileFields({ value, onChange: next => { value = next; }, requiredUserClaims: [] });
    const field = elements(view).find(element => element.props.autoComplete === autoComplete);
    assert.ok(field, `missing field ${autoComplete}`);
    field.props.onChange({ target: { value: text } });
  };
  change("username", "ALICE");
  change("address-level2", "Uppsala");
  change("given-name", "Alice");
  assert.equal(value.username, "alice");
  assert.equal(value.displayName, "Alice");
  assert.equal(value.address.country, "Sweden");
  assert.equal(value.address.locality, "Uppsala");
  assert.equal(value.profileClaims.given_name, "Alice");
});
