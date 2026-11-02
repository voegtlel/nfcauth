/* No analytics, provider fetches, installation detection, or automatic redirects. */
(function () {
  "use strict";
  const store = "https://play.google.com/store/apps/details?id=de.infornautik.nfcauth";

  function registrationLinks(search) {
    if (search.length > 4096) throw new Error("Registration link is too long.");
    const entries = Array.from(new URLSearchParams(search).entries());
    if (entries.length !== 1 || entries[0][0] !== "provider") {
      throw new Error("Use a registration link containing exactly one provider address.");
    }
    const value = entries[0][1];
    if (!value || value.length > 2048 || value !== value.trim() || /[\\\s]/.test(value)) {
      throw new Error("Invalid provider address.");
    }
    const provider = new URL(value);
    if (provider.protocol !== "https:" || provider.username || provider.password ||
        provider.search || provider.hash || provider.pathname !== "/") {
      throw new Error("The provider must be an HTTPS origin, without credentials, a path, query, or fragment.");
    }
    const encoded = encodeURIComponent(provider.origin);
    return {
      provider: provider.origin,
      direct: "nfcauth://register?provider=" + encoded,
      intent: "intent://register?provider=" + encoded +
        "#Intent;scheme=nfcauth;package=de.infornautik.nfcauth;S.browser_fallback_url=" +
        encodeURIComponent(store) + ";end",
    };
  }

  if (typeof module !== "undefined" && module.exports) module.exports = { registrationLinks };
  if (typeof document === "undefined") return;
  try {
    const links = registrationLinks(window.location.search);
    document.getElementById("provider").textContent = links.provider;
    document.getElementById("open-app").href = links.intent;
    document.getElementById("direct-link").href = links.direct;
    document.getElementById("status").textContent = "Review this provider in the app before registering.";
    document.getElementById("registration").hidden = false;
  } catch (error) {
    document.getElementById("status").textContent = "Invalid registration link. " + error.message;
  }
}());
