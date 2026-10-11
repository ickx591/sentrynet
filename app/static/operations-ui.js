(function () {
  "use strict";

  function el(id) { return document.getElementById(id); }
  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
      return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
    });
  }
  function cookie(name) {
    var match = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return match ? decodeURIComponent(match[1]) : null;
  }
  function csrf() { return cookie("sentrynet_csrf"); }
  async function api(path, options) {
    options = options || {};
    var method = (options.method || "GET").toUpperCase();
    if (["POST","PUT","PATCH","DELETE"].indexOf(method) !== -1) {
      options.headers = options.headers || {};
      options.headers["X-CSRF-Token"] = csrf() || "";
      if (options.body && !options.headers["Content-Type"]) options.headers["Content-Type"] = "application/json";
    }
    var response = await fetch(path, options);
    var data = await response.json().catch(function () { return {}; });
    if (!response.ok) throw new Error(data.detail || data.error || "Request failed (" + response.status + ")");
    return data;
  }
  function toast(message, error) {
    var stack = document.querySelector(".toast-stack");
    if (!stack) { stack = document.createElement("div"); stack.className = "toast-stack"; document.body.appendChild(stack); }
    var node = document.createElement("div"); node.className = "toast" + (error ? " error" : ""); node.textContent = message; stack.appendChild(node);
    setTimeout(function () { node.remove(); }, 4200);
  }
  function fmt(iso) { return iso ? new Date(iso + (/Z$|[+-]\d\d:\d\d$/.test(iso) ? "" : "Z")).toLocaleString() : "—"; }

  async function loadIncidents() {
    if (!el("incidentList")) return;
    var params = new URLSearchParams();
    if (el("incidentQuery").value.trim()) params.set("q", el("incidentQuery").value.trim());
    if (el("incidentStatus").value) params.set("status", el("incidentStatus").value);
    if (el("incidentSeverity").value) params.set("severity", el("incidentSeverity").value);
    try {
      var rows = await api("/api/incidents?" + params.toString());
      el("incidentCount").textContent = rows.length;
      var open = rows.filter(function (r) { return r.status !== "resolved"; });
      el("incidentOpen").textContent = open.length;
      el("incidentCritical").textContent = open.filter(function (r) { return r.severity === "critical"; }).length;
      el("incidentInvestigating").textContent = rows.filter(function (r) { return r.status === "investigating"; }).length;
      var badge = el("incidentBadge");
      if (open.length) { badge.style.display = "inline-flex"; badge.textContent = open.length; } else badge.style.display = "none";
      el("incidentList").innerHTML = rows.map(function (r) {
        return '<div class="incident-row" data-incident="' + esc(r.id) + '">' +
          '<span class="severity-chip severity-' + esc(r.severity) + '">' + esc(r.severity) + '</span>' +
          '<div class="incident-main"><strong>' + esc(r.title) + '</strong><span>' + esc(r.summary || r.category) + ' · ' + esc(fmt(r.updated_at)) + '</span></div>' +
          '<select class="incident-status" data-status aria-label="Incident status"><option value="open"' + (r.status === "open" ? " selected" : "") + '>Open</option><option value="investigating"' + (r.status === "investigating" ? " selected" : "") + '>Investigating</option><option value="resolved"' + (r.status === "resolved" ? " selected" : "") + '>Resolved</option></select>' +
          '<button class="btn btn-sm" data-note>Case notes</button></div>';
      }).join("") || '<div class="empty">No incidents match this view.</div>';
    } catch (e) { el("incidentList").innerHTML = '<div class="empty">' + esc(e.message) + '</div>'; }
  }
  if (el("refreshIncidents")) el("refreshIncidents").addEventListener("click", loadIncidents);
  ["incidentStatus","incidentSeverity"].forEach(function (id) { if (el(id)) el(id).addEventListener("change", loadIncidents); });
  if (el("incidentQuery")) el("incidentQuery").addEventListener("keydown", function (e) { if (e.key === "Enter") loadIncidents(); });
  if (el("incidentList")) el("incidentList").addEventListener("change", async function (event) {
    if (!event.target.matches("[data-status]")) return;
    var row = event.target.closest("[data-incident]");
    try { await api("/api/incidents/" + row.dataset.incident, {method:"PATCH", body:JSON.stringify({status:event.target.value})}); toast("Incident updated"); loadIncidents(); }
    catch (e) { toast(e.message, true); }
  });
  if (el("incidentList")) el("incidentList").addEventListener("click", async function (event) {
    var button = event.target.closest("[data-note]"); if (!button) return;
    var row = button.closest("[data-incident]"); var notes = prompt("Case notes (replaces current notes):"); if (notes === null) return;
    try { await api("/api/incidents/" + row.dataset.incident, {method:"PATCH", body:JSON.stringify({notes:notes})}); toast("Case notes saved"); }
    catch (e) { toast(e.message, true); }
  });

  var lastSearch = "";
  async function runSearch(term) {
    term = (term || el("globalSearchInput").value).trim();
    if (term.length < 2) { toast("Enter at least two characters", true); return; }
    lastSearch = term; el("globalSearchInput").value = term;
    el("exportSearchBtn").href = "/api/search/export?q=" + encodeURIComponent(term);
    el("globalSearchResults").innerHTML = '<div class="empty">Searching…</div>';
    try {
      var data = await api("/api/search?q=" + encodeURIComponent(term));
      el("searchResultCount").textContent = data.results.length;
      el("globalSearchResults").innerHTML = data.results.map(function (r) {
        return '<div class="search-result"><span class="type-chip">' + esc(r.type) + '</span><div class="result-main"><strong>' + esc(r.title) + '</strong><span>' + esc(r.meta) + '</span></div><time>' + esc(fmt(r.timestamp)) + '</time></div>';
      }).join("") || '<div class="empty">No matching telemetry found.</div>';
    } catch (e) { el("globalSearchResults").innerHTML = '<div class="empty">' + esc(e.message) + '</div>'; }
  }
  if (el("globalSearchBtn")) el("globalSearchBtn").addEventListener("click", function () { runSearch(); });
  if (el("globalSearchInput")) el("globalSearchInput").addEventListener("keydown", function (e) { if (e.key === "Enter") runSearch(); });
  async function loadViews() {
    if (!el("savedViewSelect")) return;
    try { var rows = await api("/api/saved-views"); el("savedViewSelect").innerHTML = '<option value="">Saved views</option>' + rows.map(function (r) { return '<option value="' + esc((r.query || {}).q || "") + '">' + esc(r.name) + '</option>'; }).join(""); } catch (e) {}
  }
  if (el("savedViewSelect")) el("savedViewSelect").addEventListener("change", function () { if (this.value) runSearch(this.value); });
  if (el("saveViewBtn")) el("saveViewBtn").addEventListener("click", async function () {
    if (!lastSearch) { toast("Run a search before saving it", true); return; }
    var name = prompt("Name this saved view:", lastSearch); if (!name) return;
    try { await api("/api/saved-views", {method:"POST", body:JSON.stringify({name:name, query:{q:lastSearch}})}); toast("View saved"); loadViews(); } catch (e) { toast(e.message, true); }
  });

  async function loadPolicies() {
    if (!el("policyList")) return;
    try {
      var rows = await api("/api/policies"); el("policyCount").textContent = rows.length;
      el("policyList").innerHTML = rows.map(function (p) {
        return '<div class="policy-row" data-policy="' + esc(p.id) + '"><div><strong>' + esc(p.name) + '</strong><span class="row-meta">Score ≥ ' + p.min_score + (p.countries.length ? ' · ' + esc(p.countries.join(", ")) : ' · all countries') + (p.managed_by_fleet ? ' · fleet managed' : '') + '</span></div>' +
          '<span class="severity-chip ' + (p.enabled ? 'health-ok' : '') + '">' + (p.enabled ? 'enabled' : 'disabled') + '</span><span class="severity-chip ' + (p.dry_run ? 'severity-medium' : 'severity-critical') + '">' + (p.dry_run ? 'dry run' : 'enforce') + '</span>' +
          '<div class="policy-actions"><button class="btn btn-sm" data-run>' + (p.dry_run ? 'Preview' : 'Run now') + '</button>' + (p.managed_by_fleet ? '' : '<button class="btn btn-sm btn-danger" data-delete>Delete</button>') + '</div></div>';
      }).join("") || '<div class="empty">No response policies configured.</div>';
    } catch (e) { el("policyList").innerHTML = '<div class="empty">' + esc(e.message) + '</div>'; }
  }
  if (el("createPolicyBtn")) el("createPolicyBtn").addEventListener("click", async function () {
    var payload = {name:el("policyName").value, min_score:Number(el("policyScore").value), countries:el("policyCountries").value.split(",").map(function(c){return c.trim();}).filter(Boolean), duration_hours:el("policyDuration").value ? Number(el("policyDuration").value) : null, enabled:el("policyEnabled").checked, dry_run:el("policyDryRun").checked};
    try { await api("/api/policies", {method:"POST", body:JSON.stringify(payload)}); el("policyName").value=""; toast("Policy created"); loadPolicies(); } catch (e) { toast(e.message, true); }
  });
  if (el("policyList")) el("policyList").addEventListener("click", async function (event) {
    var row = event.target.closest("[data-policy]"); if (!row) return;
    try {
      if (event.target.closest("[data-run]")) { var out = await api("/api/policies/" + row.dataset.policy + "/run", {method:"POST"}); toast(out.dry_run ? out.matched + " targets matched in preview" : out.enforced + " targets blocked"); }
      if (event.target.closest("[data-delete]") && confirm("Delete this response policy?")) { await api("/api/policies/" + row.dataset.policy, {method:"DELETE"}); toast("Policy deleted"); }
      loadPolicies();
    } catch (e) { toast(e.message, true); }
  });

  function integrationFields() { var pager = el("integrationKind").value === "pagerduty"; el("integrationUrlLabel").style.display = pager ? "none" : "grid"; el("integrationKeyLabel").style.display = pager ? "grid" : "none"; }
  if (el("integrationKind")) el("integrationKind").addEventListener("change", integrationFields);
  async function loadIntegrations() {
    if (!el("integrationList")) return;
    try { var rows = await api("/api/integrations"); el("integrationCount").textContent=rows.length; el("integrationList").innerHTML=rows.map(function(r){return '<div class="integration-row" data-integration="'+esc(r.key)+'"><span class="type-chip">'+esc(r.kind)+'</span><div><strong>'+esc(r.name)+'</strong><span class="row-meta">'+esc((r.config||{}).url || (r.config||{}).routing_key || "Configured")+'</span></div><span class="severity-chip '+(r.enabled?'health-ok':'')+'">'+(r.enabled?'enabled':'disabled')+'</span><div class="row-actions"><button class="btn btn-sm btn-danger" data-delete>Remove</button></div></div>';}).join("") || '<div class="empty">No additional integrations connected.</div>'; } catch(e){ el("integrationList").innerHTML='<div class="empty">'+esc(e.message)+'</div>'; }
  }
  if (el("saveIntegrationBtn")) el("saveIntegrationBtn").addEventListener("click", async function(){var name=el("integrationName").value.trim(),kind=el("integrationKind").value,key=(kind+"-"+name.toLowerCase().replace(/[^a-z0-9]+/g,"-")).replace(/-+$/g,"");var config=kind==="pagerduty"?{routing_key:el("integrationRoutingKey").value}:{url:el("integrationUrl").value};try{await api("/api/integrations",{method:"POST",body:JSON.stringify({key:key,kind:kind,name:name,enabled:el("integrationEnabled").checked,config:config})});toast("Integration saved");el("integrationName").value="";el("integrationUrl").value="";el("integrationRoutingKey").value="";loadIntegrations();}catch(e){toast(e.message,true);}});
  if (el("integrationList")) el("integrationList").addEventListener("click",async function(event){var row=event.target.closest("[data-integration]");if(!row||!event.target.closest("[data-delete]"))return;try{await api("/api/integrations/"+encodeURIComponent(row.dataset.integration),{method:"DELETE"});toast("Integration removed");loadIntegrations();}catch(e){toast(e.message,true);}});
  if (el("testIntegrationsBtn")) el("testIntegrationsBtn").addEventListener("click",async function(){try{await api("/api/integrations/test",{method:"POST"});toast("Test event queued");}catch(e){toast(e.message,true);}});

  async function loadMfa(){if(!el("mfaStatus"))return;try{var s=await api("/api/account/mfa");if(s.enabled){el("mfaStatus").innerHTML='<div class="mfa-box"><span class="health-chip health-ok">Enabled</span><p class="card-hint">Authenticator verification is required at sign-in.</p><button class="btn btn-sm" id="disableMfaBtn">Disable MFA</button></div>';el("disableMfaBtn").onclick=async function(){var code=prompt("Enter your current 6-digit authenticator code:");if(!code)return;try{await api("/api/account/mfa",{method:"DELETE",body:JSON.stringify({code:code})});toast("MFA disabled");loadMfa();}catch(e){toast(e.message,true);}};}else{el("mfaStatus").innerHTML='<div class="mfa-box"><span class="health-chip health-warning">Not enabled</span><button class="btn btn-sm" id="setupMfaBtn">Set up authenticator</button></div>';el("setupMfaBtn").onclick=setupMfa;}}catch(e){el("mfaStatus").innerHTML='<div class="empty">'+esc(e.message)+'</div>';}}
  async function setupMfa(){try{var s=await api("/api/account/mfa/setup",{method:"POST"});el("mfaStatus").innerHTML='<div class="mfa-box"><p class="card-hint">Add this secret to your authenticator app, then enter the current code.</p><div class="mfa-secret">'+esc(s.secret)+'</div><input id="mfaConfirmCode" inputmode="numeric" maxlength="6" placeholder="6-digit code"><button class="btn btn-sm" id="confirmMfaBtn">Verify and enable</button></div>';el("confirmMfaBtn").onclick=async function(){try{await api("/api/account/mfa/enable",{method:"POST",body:JSON.stringify({code:el("mfaConfirmCode").value})});toast("MFA enabled");loadMfa();}catch(e){toast(e.message,true);}};}catch(e){toast(e.message,true);}}

  function b64decode(value){var raw=atob(value.replace(/-/g,"+").replace(/_/g,"/")+"===".slice((value.length+3)%4));return Uint8Array.from(raw,function(c){return c.charCodeAt(0);});}
  function b64encode(value){var bytes=new Uint8Array(value),raw="";bytes.forEach(function(b){raw+=String.fromCharCode(b);});return btoa(raw).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
  async function loadPasskeys(){
    if(!el("passkeyStatus"))return;
    if(!window.PublicKeyCredential||!navigator.credentials){el("passkeyStatus").innerHTML='<div class="mfa-box"><strong>Passkeys</strong><p class="card-hint">This browser does not support WebAuthn passkeys.</p></div>';return;}
    try{var rows=await api("/api/account/passkeys");el("passkeyStatus").innerHTML='<div class="passkey-head"><div><strong>Passkeys</strong><p class="card-hint">Use a device, hardware key, or password manager to sign in.</p></div><button class="btn btn-sm" id="addPasskeyBtn">Add passkey</button></div>'+(rows.length?rows.map(function(r){return '<div class="passkey-row" data-passkey="'+esc(r.id)+'"><div><strong>'+esc(r.label)+'</strong><span class="row-meta">Added '+esc(fmt(r.created_at))+(r.last_used_at?' · Used '+esc(fmt(r.last_used_at)):'')+'</span></div><button class="btn btn-sm btn-danger" data-remove-passkey>Remove</button></div>';}).join(""):'<div class="empty compact">No passkeys registered.</div>');el("addPasskeyBtn").onclick=registerPasskey;}catch(e){el("passkeyStatus").innerHTML='<div class="empty">'+esc(e.message)+'</div>';}
  }
  async function registerPasskey(){
    try{var options=await api("/api/account/passkeys/options",{method:"POST"});options.challenge=b64decode(options.challenge);options.user.id=b64decode(options.user.id);(options.excludeCredentials||[]).forEach(function(c){c.id=b64decode(c.id);});var credential=await navigator.credentials.create({publicKey:options});var label=prompt("Name this passkey:","My passkey")||"Passkey";var payload={id:credential.id,rawId:b64encode(credential.rawId),type:credential.type,response:{clientDataJSON:b64encode(credential.response.clientDataJSON),attestationObject:b64encode(credential.response.attestationObject)}};await api("/api/account/passkeys",{method:"POST",body:JSON.stringify({credential:payload,label:label})});toast("Passkey added");loadPasskeys();}catch(e){if(e.name!=="NotAllowedError")toast(e.message,true);}
  }
  if(el("passkeyStatus"))el("passkeyStatus").addEventListener("click",async function(event){var button=event.target.closest("[data-remove-passkey]");if(!button)return;var row=button.closest("[data-passkey]");if(!confirm("Remove this passkey?"))return;try{await api("/api/account/passkeys/"+row.dataset.passkey,{method:"DELETE"});toast("Passkey removed");loadPasskeys();}catch(e){toast(e.message,true);}});

  async function loadUpdate(){if(!el("updateStatus"))return;try{var s=await api("/api/update-status");el("updateStatus").innerHTML='<div class="mfa-box"><span class="health-chip health-ok">v'+esc(s.current_version)+'</span><p class="card-hint">'+esc(s.channel)+' channel · '+(s.managed_updates?'Managed update manifest connected.':'Rollback-aware package updates enabled.')+'</p><code class="update-command">sudo ./install.sh --check &amp;&amp; sudo ./install.sh --upgrade</code></div>';}catch(e){el("updateStatus").innerHTML='<div class="empty">Unavailable for this role.</div>';}}
  async function diagnostics(){if(!el("diagnosticList"))return;el("diagnosticList").innerHTML='<div class="empty">Checking installation…</div>';try{var d=await api("/api/diagnostics");el("diagnosticList").innerHTML=d.checks.map(function(c){return '<div class="diagnostic-row"><span class="health-chip health-'+esc(c.status)+'">'+esc(c.status)+'</span><div class="diagnostic-detail"><strong>'+esc(c.label)+'</strong><p>'+esc(c.detail)+(c.action?' · '+esc(c.action):'')+'</p></div></div>';}).join("");}catch(e){el("diagnosticList").innerHTML='<div class="empty">'+esc(e.message)+'</div>';}}
  if(el("runDiagnosticsBtn"))el("runDiagnosticsBtn").addEventListener("click",diagnostics);

  async function loadOidc(){if(!el("oidcIssuer"))return;try{var s=await api("/api/oidc-settings");el("oidcIssuer").value=s.issuer||"";el("oidcClientId").value=s.client_id||"";el("oidcClientSecret").value=s.client_secret||"";el("oidcDefaultRole").value=s.default_role||"spectator";el("oidcEnabled").checked=!!s.enabled;el("oidcStatus").textContent=s.configured?(s.enabled?"SSO is enabled.":"SSO is configured but disabled."):"No identity provider configured.";}catch(e){}}
  if(el("saveOidcBtn"))el("saveOidcBtn").addEventListener("click",async function(){try{await api("/api/oidc-settings",{method:"POST",body:JSON.stringify({issuer:el("oidcIssuer").value,client_id:el("oidcClientId").value,client_secret:el("oidcClientSecret").value,default_role:el("oidcDefaultRole").value,enabled:el("oidcEnabled").checked})});toast("SSO configuration saved");loadOidc();}catch(e){toast(e.message,true);}});

  document.querySelectorAll(".tab").forEach(function(tab){tab.addEventListener("click",function(){var key=tab.dataset.tab;if(key==="incidents")loadIncidents();if(key==="search")loadViews();if(key==="policies")loadPolicies();if(key==="integrations")loadIntegrations();if(key==="setup"){loadMfa();loadPasskeys();loadUpdate();}if(key==="users")loadOidc();});});
  loadIncidents(); loadViews(); loadPolicies(); loadMfa(); loadPasskeys(); loadUpdate(); loadOidc();
})();
