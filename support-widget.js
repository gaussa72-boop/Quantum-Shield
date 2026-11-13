(function () {
  "use strict";
  if (window.__ULTIMA_SUPPORT_WIDGET__) return;
  window.__ULTIMA_SUPPORT_WIDGET__ = true;

  var username = "Ari_phenex";
  var link = "https://t.me/" + username;
  var designLink = document.createElement("link");
  designLink.rel = "stylesheet";
  designLink.href = "https://ultima-membership-api.onrender.com/design-system.css";
  designLink.dataset.ultimaDesignSystem = "2026";
  document.head.appendChild(designLink);

  var style = document.createElement("style");
  style.textContent = [
    "#ultima-support-button{position:fixed;right:20px;bottom:20px;z-index:2147483000;display:flex;align-items:center;gap:10px;padding:13px 17px;border:1px solid rgba(125,211,252,.45);border-radius:999px;background:#101827;color:#f8fafc;font:600 14px/1.2 system-ui,-apple-system,sans-serif;text-decoration:none;box-shadow:0 8px 28px rgba(0,0,0,.28);}",
    "#ultima-support-button:hover{background:#17263b;transform:translateY(-1px)}",
    "#ultima-support-button:focus-visible{outline:3px solid #7dd3fc;outline-offset:3px}",
    "#ultima-support-button svg{width:21px;height:21px;flex:none}",
    "@media(prefers-reduced-motion:no-preference){#ultima-support-button{transition:transform .15s ease,background .15s ease}}"
  ].join("");
  var add = function () {
    if (!document.body || document.getElementById("ultima-support-button")) return;
    document.head.appendChild(style);
    var a = document.createElement("a");
    a.id = "ultima-support-button";
    a.href = link;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.setAttribute("aria-label", "ULTIMA Support auf Telegram öffnen");
    a.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true" fill="currentColor"><path d="M21.8 4.2 18.7 19c-.2 1-1 1.2-1.8.7l-4.9-3.6-2.4 2.3c-.3.3-.5.5-1 .5l.4-5 9.1-8.2c.4-.4-.1-.6-.6-.3L6.2 12.6l-4.8-1.5c-1-.3-1-1 .2-1.5L20.3 2.7c.9-.3 1.7.2 1.5 1.5Z"/></svg><span>Support · Telegram</span>';
    document.body.appendChild(a);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", add, { once: true });
  else add();
})();