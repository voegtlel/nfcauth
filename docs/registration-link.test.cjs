const assert = require("node:assert/strict");
const { registrationLinks } = require("./registration-link.js");
const links = registrationLinks("?provider=https%3A%2F%2FAUTH.example.com%3A443%2F");
assert.equal(links.provider, "https://auth.example.com");
assert.equal(links.direct, "nfcauth://register?provider=https%3A%2F%2Fauth.example.com");
assert.ok(links.intent.includes("package=de.infornautik.nfcauth;"));
for (const value of [
  "", "?provider=http://example.com", "?provider=javascript:alert(1)",
  "?provider=https://user@example.com", "?provider=https://example.com/path",
  "?provider=https://example.com&provider=https://other.example",
  "?provider=https://example.com&token=secret", "?provider=https://example.com%23fragment",
  "?provider=%3Cscript%3E", "?provider=" + "x".repeat(4096),
]) assert.throws(() => registrationLinks(value), undefined, value);
console.log("Registration landing-page tests passed");
