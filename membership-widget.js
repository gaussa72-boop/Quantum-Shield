(()=>{"use strict";
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function init(opts={}){
 const api=(opts.apiBase||"https://ultima-membership-api.onrender.com").replace(/\/$/,""),slug=opts.siteSlug||"";
 if(!slug)return;
 const key="ultima-session:"+slug,token=()=>sessionStorage.getItem(key)||"",save=t=>t?sessionStorage.setItem(key,t):sessionStorage.removeItem(key);
 const style=document.createElement("style");style.textContent="#ultima-launch{position:fixed;right:20px;bottom:20px;z-index:2147483000;border:1px solid #8ddde8;background:linear-gradient(135deg,#15233b,#0b1222);color:#effbff;border-radius:999px;padding:12px 18px;font:600 14px system-ui;box-shadow:0 12px 36px #0008;cursor:pointer}#ultima-global-launch{position:fixed;right:20px;bottom:128px;z-index:2147483000;border:1px solid #e6c77b;background:linear-gradient(135deg,#392e18,#171321);color:#fff0c6;border-radius:999px;padding:11px 16px;font:700 13px system-ui;box-shadow:0 12px 36px #0009;text-decoration:none}#aurealis-launch{position:fixed;right:20px;bottom:74px;z-index:2147483000;border:1px solid #a5ff18;background:linear-gradient(135deg,#153c42,#071b22);color:#eaffd0;border-radius:999px;padding:12px 18px;font:700 14px system-ui;box-shadow:0 12px 36px #0009;cursor:pointer}#ultima-panel{position:fixed;right:20px;bottom:76px;z-index:2147483000;width:min(360px,calc(100vw - 32px));background:#0d1424;color:#f4f7ff;border:1px solid #31415e;border-radius:18px;padding:18px;box-shadow:0 20px 70px #000b;font:14px system-ui}#ultima-panel input,#ultima-panel textarea{box-sizing:border-box;width:100%;padding:11px;margin:6px 0;border-radius:9px;border:1px solid #34445f;background:#080e1b;color:white;font:inherit}#ultima-panel button{padding:10px 13px;border:0;border-radius:9px;background:#9ce5eb;color:#08121b;font-weight:700;cursor:pointer;margin:5px 4px 0 0}#ultima-panel .secondary{background:#263650;color:#eaf5ff}#ultima-panel small{color:#aab8ce}#ultima-panel [role=status]{min-height:20px;color:#ffcc9a}@media(max-width:480px){#ultima-launch{right:12px;bottom:12px}#ultima-global-launch{right:12px;bottom:120px}#ultima-panel{right:12px;bottom:66px}}";document.head.appendChild(style);
 const btn=document.createElement("button");btn.id="ultima-launch";btn.type="button";btn.textContent="Mein Konto";
 const aiBtn=document.createElement("button");aiBtn.id="aurealis-launch";aiBtn.type="button";aiBtn.textContent="✦ Aurealis KI Center";
 const globalBtn=document.createElement("a");globalBtn.id="ultima-global-launch";globalBtn.href="https://ultima-membership-api.onrender.com/portal";globalBtn.target="_blank";globalBtn.rel="noopener noreferrer";globalBtn.textContent="ULTIMA Zentralprofil ↗";
 const panel=document.createElement("section");panel.id="ultima-panel";panel.hidden=true;panel.setAttribute("aria-label","Aurealis KI Center und Mitgliederkonto");document.body.append(btn,aiBtn,globalBtn,panel);
 const apiCall=async(path,method="GET",data=null)=>{const r=await fetch(api+"/api/"+encodeURIComponent(slug)+path,{method,headers:{"Content-Type":"application/json",...(token()?{"Authorization":"Bearer "+token()}:{})},body:data?JSON.stringify(data):undefined,mode:"cors"});const d=await r.json().catch(()=>({error:"Serverantwort ungültig."}));if(!r.ok)throw Error(d.error||"Anfrage fehlgeschlagen.");return d};
 function status(s){const el=panel.querySelector("[role=status]");if(el)el.textContent=s||""}
 async function render(){panel.hidden=false;panel.innerHTML="<h3 style='margin:0 0 12px'>"+esc(opts.brand||"Mitgliederbereich")+"</h3><p role='status'></p><div>Wird geladen …</div>";
  if(token()){try{const d=await apiCall("/me"),m=d.member;panel.innerHTML="<h3>Mein Profil</h3><p><b>"+esc(m.display_name||m.username)+"</b><br><small>"+esc(m.email)+" · "+esc(m.role)+(m.is_lifetime_premium?" · Lifetime Premium":"")+"</small></p><p>"+esc(m.bio||"Noch keine Profilbeschreibung.")+"</p><button id='u-edit'>Profil bearbeiten</button><button id='u-copilot'>Aurealis KI Center</button><button class='secondary' id='u-credits'>Credits & Premium</button>"+(["site_admin","superadmin"].includes(m.role)?"<button class='secondary' id='u-admin'>Mitglieder verwalten</button>":"")+"<button class='secondary' id='u-out'>Abmelden</button><p role='status'></p>";panel.querySelector("#u-edit").onclick=()=>edit(m);panel.querySelector("#u-copilot").onclick=copilotView;panel.querySelector("#u-credits").onclick=creditsView;if(panel.querySelector("#u-admin"))panel.querySelector("#u-admin").onclick=adminView;panel.querySelector("#u-out").onclick=async()=>{try{await apiCall("/logout","POST",{})}catch(e){}save("");render()};return}catch(e){save("")}}
  panel.innerHTML="<h3 style='margin:0 0 12px'>"+esc(opts.brand||"Mitgliederbereich")+"</h3><p role='status'></p><form id='u-form'><input name='identity' placeholder='E-Mail' type='email' autocomplete='username' required><input name='password' placeholder='Passwort (mind. 12 Zeichen)' type='password' autocomplete='current-password' required><div><button type='submit'>Anmelden</button><button type='button' class='secondary' id='u-register'>Konto erstellen</button></div></form><small>Dein Konto gilt nur für diese Webseite.</small>";
  panel.querySelector("#u-form").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{const d=await apiCall("/login","POST",{identity:f.get("identity"),password:f.get("password")});save(d.token);render()}catch(err){status(err.message)}};
  panel.querySelector("#u-register").onclick=()=>register();
 }

 async function copilotView(){
  const history=[];
  panel.innerHTML="<h3>Aurealis KI Center</h3><small>"+esc(opts.brand||"Diese Website")+" · persönlicher KI-Assistent</small><div id='u-copilot-log' style='height:230px;overflow:auto;padding:10px 0;margin:8px 0;border-top:1px solid #293650;border-bottom:1px solid #293650'><p style='color:#aab8ce'>Ich helfe dir mit dieser Website, deinem Profil, Shop, Funktionen, Ideen und technischen Fragen.</p></div><form id='u-copilot-form'><textarea name='message' rows='3' maxlength='4000' placeholder='Was möchtest du machen?' required></textarea><button type='submit'>Nachricht senden</button><button type='button' class='secondary' id='u-copilot-back'>Zurück</button></form><p role='status'></p><small>Änderungen, Zahlungen und Veröffentlichungen benötigen weiterhin eine Administratorfreigabe.</small>";
  const log=panel.querySelector('#u-copilot-log'),form=panel.querySelector('#u-copilot-form');
  panel.querySelector('#u-copilot-back').onclick=render;
  form.onsubmit=async e=>{e.preventDefault();const input=form.elements.message,message=input.value.trim();if(!message)return;input.value='';
   const user=document.createElement('p');user.style.cssText='background:#1b2940;padding:9px;border-radius:10px;white-space:pre-wrap';user.textContent='Du: '+message;log.append(user);
   const wait=document.createElement('p');wait.style.color='#aab8ce';wait.textContent='Aurealis generiert …';log.append(wait);log.scrollTop=log.scrollHeight;
   try{const d=await apiCall('/copilot','POST',{message:message,history:history});wait.textContent='Aurealis: '+d.answer;history.push({role:'user',content:message},{role:'assistant',content:d.answer});if(history.length>12)history.splice(0,history.length-12);}
   catch(err){wait.textContent='Hinweis: '+err.message;}log.scrollTop=log.scrollHeight;
  };
 }
 async function adminView(){try{const d=await apiCall("/admin/members");panel.innerHTML="<h3>Mitgliederverwaltung</h3><p role='status'></p><div id='u-members'></div><button class='secondary' id='u-back'>Zurück zum Profil</button>";panel.querySelector("#u-back").onclick=render;const list=panel.querySelector("#u-members");for(const m of d.members){const row=document.createElement("div");row.style.cssText="padding:10px 0;border-bottom:1px solid #293650";const title=document.createElement("b");title.textContent=m.username+" · "+m.role;const detail=document.createElement("small");detail.style.display="block";detail.textContent=m.email+" · "+m.status;row.append(title,detail);if(m.role!=="site_admin"){const promote=document.createElement("button");promote.textContent="Zum Admin";promote.onclick=async()=>{await apiCall("/admin/members/"+m.id,"PATCH",{action:"promote"});adminView()};row.append(promote)}const toggle=document.createElement("button");toggle.className="secondary";toggle.textContent=m.status==="pending"?"Registrierung freigeben":(m.status==="active"?"Sperren":"Aktivieren");toggle.onclick=async()=>{await apiCall("/admin/members/"+m.id,"PATCH",{action:m.status==="pending"?"approve":(m.status==="active"?"disable":"enable")});adminView()};row.append(toggle);list.append(row)}}catch(e){panel.innerHTML="<h3>Mitgliederverwaltung</h3><p role='status'>"+esc(e.message)+"</p><button class='secondary' id='u-back'>Zurück</button>";panel.querySelector("#u-back").onclick=render}}

 async function creditsView(){
  try{
   const [p,bills]=await Promise.all([apiCall("/premium/status"),apiCall("/premium/invoices")]);
   const premium=p.premium||{},items=bills.invoices||[];
   const state=premium.status==="trial"?"7-Tage-Testphase":premium.status==="paid"?"Premium aktiv":premium.status==="lifetime"?"Master Premium":premium.status==="not_started"?"Testphase verfügbar":"Testphase beendet";
   const remaining=Number(premium.trial_remaining||0),used=Number(premium.trial_used||0),limit=Number(premium.trial_limit||25);
   panel.innerHTML="<h3>ULTIMA Network Premium</h3><p><b>"+esc(state)+"</b></p>"+
    "<p>"+(premium.status==="trial"?"Testnutzung: "+used+" / "+limit+" · verbleibend: "+remaining+" · Tage: "+esc(premium.trial_days_remaining):premium.status==="paid"?"Freigeschaltet bis: "+esc(premium.paid_until||""):"Gemeinsame Premium-Funktionen über alle angeschlossenen Websites.")+"</p>"+
    "<p><b>"+esc(premium.price_eur||"9.99")+" EUR</b> / "+esc(premium.period_days||30)+" Tage · Bitcoin mainnet · kein automatischer Einzug</p>"+
    (premium.status==="not_started"?"<button id='u-trial'>7-Tage-Testphase starten</button>":"")+
    (premium.checkout_ready?"<button id='u-invoice'>Premium für 30 Tage kaufen</button>":"<p><small>Bitcoin-Checkout wird erst aktiviert, wenn Wallet und die erforderlichen Anbieterangaben vollständig konfiguriert sind. Bitte noch kein Geld senden.</small></p>")+
    "<div id='u-invoice-list'></div><p role='status'></p><button class='secondary' id='u-renewal-off'>Verlängerung deaktivieren</button><button class='secondary' id='u-creditback'>Zurück zum Profil</button>";
   const list=panel.querySelector("#u-invoice-list");
   for(const x of items){
    const card=document.createElement("div");card.style.cssText="border:1px solid #33445f;border-radius:10px;padding:10px;margin:9px 0";
    const title=document.createElement("b");title.textContent="Rechnung "+x.invoice_code+" · "+x.amount_eur+" EUR";
    const detail=document.createElement("p");detail.textContent="Betrag: "+x.expected_btc+" BTC · Status: "+x.status+" · Bestätigungen: "+x.confirmations+" · Netzwerk: "+x.network;
    card.append(title,detail);
    if(x.wallet){const wallet=document.createElement("p");wallet.style.cssText="overflow-wrap:anywhere";wallet.textContent="Wallet: "+x.wallet;card.append(wallet);}
    if(x.status!=="paid"&&x.status!=="expired"&&x.status!=="cancelled"){
     const link=document.createElement("a");link.href="bitcoin:"+x.wallet+"?amount="+x.expected_btc;link.textContent="Bitcoin-Wallet öffnen";link.style.display="inline-block";link.style.margin="5px 0";card.append(link);
     const form=document.createElement("form");form.dataset.invoice=x.invoice_code;
     const input=document.createElement("input");input.name="txid";input.placeholder="Bitcoin-TXID (64 Zeichen)";input.minLength=64;input.maxLength=64;input.required=true;
     const submit=document.createElement("button");submit.type="submit";submit.textContent="TXID prüfen und Premium freischalten";
     form.append(input,submit);card.append(form);
     form.onsubmit=async e=>{e.preventDefault();submit.disabled=true;try{const result=await apiCall("/premium/invoices/"+encodeURIComponent(x.invoice_code)+"/submit","POST",{txid:input.value.trim()});status(result.result?.message||"Zahlung geprüft.");await creditsView()}catch(err){status(err.message);submit.disabled=false}};
    }
    list.append(card);
   }
   panel.querySelector("#u-creditback").onclick=render;
   panel.querySelector("#u-renewal-off").onclick=async()=>{try{const d=await apiCall("/premium/cancel","POST",{});status(d.message);await creditsView()}catch(e){status(e.message)}};
   const trial=panel.querySelector("#u-trial");if(trial)trial.onclick=async()=>{try{await apiCall("/premium/trial/start","POST",{});await creditsView()}catch(e){status(e.message)}};
   const invoice=panel.querySelector("#u-invoice");if(invoice)invoice.onclick=async()=>{invoice.disabled=true;try{const d=await apiCall("/premium/invoices","POST",{});status("Rechnung erstellt: "+d.invoice.expected_btc+" BTC");await creditsView()}catch(e){status(e.message);invoice.disabled=false}};
  }catch(e){panel.innerHTML="<h3>ULTIMA Network Premium</h3><p role='status'>"+esc(e.message)+"</p><button class='secondary' id='u-creditback'>Zurück</button>";panel.querySelector("#u-creditback").onclick=render}
 }
 function register(){panel.innerHTML="<h3>Konto erstellen</h3><p role='status'></p><form id='u-reg'><input name='registration_code' placeholder='Einmaliger Registrierungscode' autocomplete='off' required><input name='email' type='email' placeholder='E-Mail' required><input name='username' placeholder='Benutzername' required minlength='3' maxlength='32'><input name='display_name' placeholder='Anzeigename'><input name='password' type='password' placeholder='Passwort (mind. 12 Zeichen)' required minlength='12'><button>Konto anlegen</button><button type='button' class='secondary' id='u-back'>Zurück</button></form><small>Mit der Registrierung gilt die Datenschutzerklärung dieser Webseite.</small>";panel.querySelector("#u-back").onclick=render;panel.querySelector("#u-reg").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{const d=await apiCall("/register","POST",{email:f.get("email"),username:f.get("username"),display_name:f.get("display_name"),password:f.get("password"),registration_code:f.get("registration_code")});if(d.approval_required){save("");panel.innerHTML="<h3>Registrierung eingegangen</h3><p>"+esc(d.message||"Dein Konto wartet auf die Freigabe durch die Administration.")+"</p><p><small>Du kannst dich anmelden, sobald dein Konto freigegeben wurde.</small></p><button class=secondary id=u-regback>Zur Anmeldung</button>";panel.querySelector("#u-regback").onclick=render;return;}save(d.token);render()}catch(err){status(err.message)}}}
 function edit(m){panel.innerHTML="<h3>Profil bearbeiten</h3><p role='status'></p><form id='u-profile'><input name='display_name' maxlength='120' value='"+esc(m.display_name||"")+"' placeholder='Anzeigename'><textarea name='bio' maxlength='1000' placeholder='Über mich'>"+esc(m.bio||"")+"</textarea><input name='avatar_url' value='"+esc(m.avatar_url||"")+"' placeholder='HTTPS-Profilbild-URL'><button>Speichern</button><button type='button' class='secondary' id='u-cancel'>Abbrechen</button></form>";panel.querySelector("#u-cancel").onclick=render;panel.querySelector("#u-profile").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{await apiCall("/profile","PATCH",{display_name:f.get("display_name"),bio:f.get("bio"),avatar_url:f.get("avatar_url")});render()}catch(err){status(err.message)}}}

 if(!window.__ultimaBillingFetchPatched){
  window.__ultimaBillingFetchPatched=true;
  const nativeFetch=window.fetch.bind(window);
  const paidFeature=function(path){
   const p=path.toLowerCase();
   if(/\\/(auth|login|register|profile|logout|payment|payments|credits|checkout|orders|upload|webhook|search|like|comment|message|settings|premium)(\\/|$)/.test(p))return null;
   if(/(?:^|\\/)(?:image|images|img2img)(?:\\/|$)|generate[-_]image|image[-_]generate/.test(p))return "image_generation";
   if(/(?:^|\\/)(?:video|clip)(?:\\/|$)|generate[-_]video|video[-_]generate/.test(p))return "video_generation";
   if(/(?:^|\\/)(?:music|audio|song)(?:\\/|$)|generate[-_](?:music|audio|song)/.test(p))return "music_generation";
   if(/(?:^|\\/)(?:game|dlc)(?:\\/|$)|generate[-_]game/.test(p))return "game_generation";
   if(/(?:^|\\/)mod(?:\\/|$)|generate[-_]mod/.test(p))return "mod_generation";
   if(/(?:^|\\/)(?:chat|completion|generate|generation)(?:\\/|$)|\\/ai\\/(?:chat|generate)/.test(p))return "ai_generation";
   return null;
  };
  window.fetch=async function(input,init={}){
   const rawUrl=typeof input==="string"?input:(input&&input.url)||String(input);
   let parsed;try{parsed=new URL(rawUrl,location.href)}catch(e){return nativeFetch(input,init)}
   if(parsed.origin===api)return nativeFetch(input,init);
   const method=String(init.method||(input&&input.method)||"GET").toUpperCase();
   const feature=method==="POST"?paidFeature(parsed.pathname):null;
   if(!feature)return nativeFetch(input,init);
   if(!token()){render();throw new Error("Für diese Premium-Funktion bitte zuerst anmelden.");}
   const requestId=(crypto&&crypto.randomUUID)?crypto.randomUUID():"gen-"+Date.now()+"-"+Math.random().toString(36).slice(2);
   try{await apiCall("/premium/authorize","POST",{feature:feature,request_id:requestId});}
   catch(e){creditsView();throw new Error(e.message||"Premium-Limit erreicht.");}
   let response;
   try{response=await nativeFetch(input,init);}
   catch(e){try{await apiCall("/premium/refund","POST",{request_id:requestId})}catch(_){}throw e;}
   let failed=!response.ok;
   if(!failed){try{const body=await response.clone().json();failed=!!(body&&body.error)}catch(e){}}
   if(failed){
    try{await apiCall("/premium/refund","POST",{request_id:requestId})}catch(e){}
   }else{
    try{await apiCall("/premium/complete","POST",{request_id:requestId});await apiCall("/credits/consume","POST",{feature:feature,request_id:requestId})}
    catch(e){window.dispatchEvent(new CustomEvent("ultima:billing-error",{detail:{message:e.message,feature:feature}}));}
   }
   return response;
  };
 }
 window.UltimaMembership.chargeSuccessfulGeneration=async function(feature,requestId){
  await apiCall("/premium/authorize","POST",{feature:feature,request_id:requestId});
  return await apiCall("/premium/complete","POST",{request_id:requestId});
 };
 window.UltimaMembership.getCreditBalance=async function(){return await apiCall("/credits/balance")};
 async function consumeSsoCode(){
  const params=new URLSearchParams(location.search),code=params.get("ultima_sso");
  if(!code)return;
  params.delete("ultima_sso");
  const clean=location.pathname+(params.toString()?"?"+params.toString():"")+location.hash;
  history.replaceState({},document.title,clean);
  try{
   const r=await fetch(api+"/api/global/sso/exchange",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code:code,slug:slug}),mode:"cors"});
   const d=await r.json().catch(()=>({error:"ULTIMA-Anmeldung fehlgeschlagen."}));
   if(!r.ok)throw Error(d.error||"ULTIMA-Anmeldung fehlgeschlagen.");
   save(d.token);panel.hidden=false;await render();
  }catch(e){panel.hidden=false;panel.innerHTML="<h3>ULTIMA-Anmeldung</h3><p role='status'>"+esc(e.message)+"</p><a href='https://ultima-membership-api.onrender.com/portal' target='_blank' rel='noopener noreferrer'>Zentrales ULTIMA-Konto öffnen ↗</a>";}
 }
 consumeSsoCode();
 btn.onclick=()=>{if(panel.hidden)render();else panel.hidden=true};
 aiBtn.onclick=()=>{if(!panel.hidden){copilotView();return;}if(token()){copilotView();panel.hidden=false;}else{render();}};
 document.addEventListener("keydown",e=>{if(e.key==="Escape")panel.hidden=true});
}
window.UltimaMembership={init};
})();