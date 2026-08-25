(function(){
  "use strict";

  const ALL_ID = "__all__";
  let data = { folders: [], links: [] };
  let fileHandle = null;
  let activeFolder = ALL_ID;
  let editingLinkId = null;
  let removeCredFlag = false;
  let saveTimer = null;
  let hasFSAccess = "showSaveFilePicker" in window;

  let masterKey = null;          // CryptoKey held in memory for the session
  let revealedCreds = {};        // { linkId: {user, pass} } decrypted temporarily

  const $ = (id) => document.getElementById(id);
  const folderList = $("folderList");
  const linkList = $("linkList");
  const statusDot = $("statusDot");
  const fileNameEl = $("fileName");

  function uid(){ return Date.now().toString(36) + Math.random().toString(36).slice(2,7); }

  function newData(){
    return { folders: [{ id: uid(), name: "General" }], links: [] };
  }

  function setStatus(state){ statusDot.className = "dot " + state; }

  // ===== Crypto (identifiants) =====
  function b64enc(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
  function b64dec(str){ return Uint8Array.from(atob(str), c=>c.charCodeAt(0)).buffer; }

  async function deriveKey(password, saltB64){
    const salt = new Uint8Array(b64dec(saltB64));
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name:"PBKDF2", salt, iterations:250000, hash:"SHA-256" },
      baseKey, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]
    );
  }
  async function encryptJSON(key, obj){
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, enc.encode(JSON.stringify(obj)));
    return { iv: b64enc(iv), data: b64enc(ct) };
  }
  async function decryptJSON(key, payload){
    const iv = new Uint8Array(b64dec(payload.iv));
    const ct = b64dec(payload.data);
    const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ct);
    return JSON.parse(new TextDecoder().decode(pt));
  }

  let pwResolver = null;
  function promptMasterPassword(mode){
    return new Promise((resolve)=>{
      pwResolver = resolve;
      $("pwModalTitle").textContent = mode === "create" ? "Create a master password" : "Master password";
      $("pwHint").style.display = mode === "create" ? "block" : "none";
      $("pwConfirmField").style.display = mode === "create" ? "block" : "none";
      $("pwInput").value = ""; $("pwConfirmInput").value = "";
      $("pwOverlay").dataset.mode = mode;
      $("pwOverlay").classList.add("show");
      setTimeout(()=>$("pwInput").focus(), 30);
    });
  }
  $("pwSaveBtn").addEventListener("click", ()=>{
    const mode = $("pwOverlay").dataset.mode;
    const pw = $("pwInput").value;
    if(!pw){ alert("Password required."); return; }
    if(mode === "create" && pw !== $("pwConfirmInput").value){ alert("Passwords do not match."); return; }
    $("pwOverlay").classList.remove("show");
    if(pwResolver){ pwResolver(pw); pwResolver = null; }
  });
  $("pwCancel").addEventListener("click", ()=>{
    $("pwOverlay").classList.remove("show");
    if(pwResolver){ pwResolver(null); pwResolver = null; }
  });

  async function ensureMasterKey(){
    if(masterKey) return masterKey;
    if(data.security){
      const pw = await promptMasterPassword("unlock");
      if(pw === null) return null;
      const key = await deriveKey(pw, data.security.salt);
      try{ await decryptJSON(key, data.security.verifier); }
      catch(e){ alert("Incorrect password."); return ensureMasterKey(); }
      masterKey = key;
      $("btnLock").style.display = "inline-block";
      return key;
    }else{
      const pw = await promptMasterPassword("create");
      if(pw === null) return null;
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const saltB64 = b64enc(salt);
      const key = await deriveKey(pw, saltB64);
      data.security = { salt: saltB64, verifier: await encryptJSON(key, {check:"ok"}) };
      masterKey = key;
      $("btnLock").style.display = "inline-block";
      scheduleSave();
      return key;
    }
  }

  function pendingCredCount(){
    return data.links.filter(l => l.pendingCred && !l.cred).length;
  }

  function updatePendingBanner(){
    const n = pendingCredCount();
    const btn = $("btnEncryptPending");
    if(n > 0){
      btn.style.display = "inline-block";
      btn.textContent = "🔐 Encrypt " + n + " imported credential" + (n>1?"s":"");
    }else{
      btn.style.display = "none";
    }
  }

  async function encryptAllPending(){
    const pending = data.links.filter(l => l.pendingCred && !l.cred);
    if(pending.length === 0) return;
    const key = await ensureMasterKey();
    if(!key) return;
    for(const l of pending){
      l.cred = await encryptJSON(key, l.pendingCred);
      delete l.pendingCred;
    }
    scheduleSave();
    render();
  }
  $("btnEncryptPending").addEventListener("click", encryptAllPending);

  $("btnLock").addEventListener("click", ()=>{
    masterKey = null;
    revealedCreds = {};
    $("btnLock").style.display = "none";
    render();
  });

  // ===== Persistence (File System Access API) =====
  async function openFile(){
    if(!hasFSAccess){ alert("File System Access API unavailable in this context."); return; }
    try{
      const [handle] = await window.showOpenFilePicker({
        types: [{ description: "Link Vault data", accept: {"application/json": [".json"]} }]
      });
      await idbSetHandle(handle);
      await loadFromHandle(handle);
    }catch(e){ if(e.name !== "AbortError") console.error(e); }
  }

  function importFile(){
    $("importInput").click();
  }

  function loadImportedData(parsed, sourceName){
    data = parsed;
    if(!data.folders) data.folders = [];
    if(!data.links) data.links = [];
    masterKey = null; revealedCreds = {};
    $("btnLock").style.display = "none";
    activeFolder = ALL_ID;
    if(fileHandle){
      // A file is already linked (via "Open"): import replaces its content
      // and will be written to it on next save.
      fileNameEl.textContent = fileHandle.name + " (content imported from " + sourceName + ")";
      scheduleSave();
    }else{
      fileNameEl.textContent = "Imported: " + sourceName + " (not linked — use Export or Open to save)";
      setStatus("dirty");
    }
    render();
  }

  function exportFile(){
    const blob = new Blob([JSON.stringify(data, null, 2)], {type:"application/json"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "Rep.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  async function persist(){
    setStatus("dirty");
    try{
      if(fileHandle){
        const writable = await fileHandle.createWritable();
        await writable.write(JSON.stringify(data, null, 2));
        await writable.close();
        setStatus("saved");
      }else{
        setStatus("error");
      }
    }catch(e){ console.error(e); setStatus("error"); }
  }

  function scheduleSave(){
    setStatus("dirty");
    clearTimeout(saveTimer);
    saveTimer = setTimeout(persist, 600);
  }

  // ===== IndexedDB: remember the file handle across sessions =====
  function idbOpen(){
    return new Promise((resolve, reject)=>{
      const req = indexedDB.open("repertoire-liens-db", 1);
      req.onupgradeneeded = () => req.result.createObjectStore("handles");
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  async function idbSetHandle(handle){
    const db = await idbOpen();
    return new Promise((resolve, reject)=>{
      const tx = db.transaction("handles", "readwrite");
      tx.objectStore("handles").put(handle, "lastFile");
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
  async function idbGetHandle(){
    const db = await idbOpen();
    return new Promise((resolve, reject)=>{
      const tx = db.transaction("handles", "readonly");
      const req = tx.objectStore("handles").get("lastFile");
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }

  async function loadFromHandle(handle){
    const file = await handle.getFile();
    const text = await file.text();
    data = JSON.parse(text);
    if(!data.folders) data.folders = [];
    if(!data.links) data.links = [];
    fileHandle = handle;
    masterKey = null; revealedCreds = {};
    $("btnLock").style.display = "none";
    fileNameEl.textContent = handle.name;
    activeFolder = ALL_ID;
    setStatus("saved");
    $("btnReconnect").style.display = "none";
    render();
  }

  async function tryRestoreLastFile(){
    if(!hasFSAccess) return;
    try{
      const handle = await idbGetHandle();
      if(!handle) return;
      const perm = await handle.queryPermission({mode:"readwrite"});
      if(perm === "granted"){
        await loadFromHandle(handle);
      }else{
        fileNameEl.textContent = handle.name + " (permission needs to be reconfirmed)";
        $("btnReconnect").style.display = "inline-block";
        $("btnReconnect").onclick = async () => {
          try{
            const p = await handle.requestPermission({mode:"readwrite"});
            if(p === "granted") await loadFromHandle(handle);
          }catch(e){ console.error(e); }
        };
      }
    }catch(e){ console.error(e); }
  }

  // ===== Rendering =====
  function render(){ renderFolders(); renderFolderSelect(); renderLinks(); updatePendingBanner(); }

  function renderFolders(){
    folderList.innerHTML = "";
    const items = [{id: ALL_ID, name: "All links"}, ...data.folders];
    items.forEach(f => {
      const count = f.id === ALL_ID ? data.links.length : data.links.filter(l => l.folderId === f.id).length;
      const div = document.createElement("div");
      div.className = "folder-item" + (activeFolder === f.id ? " active" : "");
      div.innerHTML = `
        <span class="tab"></span>
        <span>${escapeHtml(f.name)}</span>
        <span class="folder-count">${count}</span>
        <span class="folder-actions">${f.id !== ALL_ID ? `<button class="icon-btn" data-del="${f.id}" title="Supprimer">&times;</button>` : ""}</span>
      `;
      div.addEventListener("click", (e) => { if(e.target.dataset.del) return; activeFolder = f.id; render(); });
      folderList.appendChild(div);
    });
    folderList.querySelectorAll("[data-del]").forEach(btn=>{
      btn.addEventListener("click", (e)=>{
        e.stopPropagation();
        const id = btn.dataset.del;
        if(confirm("Delete this folder and move its links to 'All'?")){
          data.folders = data.folders.filter(f=>f.id!==id);
          data.links.forEach(l=>{ if(l.folderId===id) l.folderId = null; });
          if(activeFolder===id) activeFolder = ALL_ID;
          scheduleSave(); render();
        }
      });
    });
  }

  function renderFolderSelect(){
    $("linkFolderInput").innerHTML = data.folders.map(f=>`<option value="${f.id}">${escapeHtml(f.name)}</option>`).join("");
  }

  function renderLinks(){
    const q = $("search").value.trim().toLowerCase();
    let items = data.links.filter(l => activeFolder === ALL_ID || l.folderId === activeFolder);
    if(q){
      items = items.filter(l =>
        (l.title||"").toLowerCase().includes(q) ||
        (l.url||"").toLowerCase().includes(q) ||
        (l.tags||[]).some(t=>t.toLowerCase().includes(q))
      );
    }
    items.sort((a,b)=> (b.createdAt||0) - (a.createdAt||0));

    linkList.innerHTML = "";
    if(items.length === 0){
      linkList.innerHTML = `
        <div class="empty-state">
          <div class="big">No links here</div>
          <p>${data.links.length === 0 && !q ? "Start by opening or importing a file, then add your first link." : "No results for this search or folder."}</p>
        </div>`;
      return;
    }
    items.forEach(l => {
      let hostname = "";
      try{ hostname = new URL(l.url).hostname; }catch(e){ hostname = ""; }
      const revealed = revealedCreds[l.id];
      const card = document.createElement("div");
      card.className = "link-card";
      card.innerHTML = `
        <div class="favicon">${hostname ? `<img src="https://www.google.com/s2/favicons?sz=64&domain=${hostname}" alt="">` : "?"}</div>
        <div class="link-info">
          <a class="link-title" href="${escapeAttr(l.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(l.title || l.url)}</a>
          <div class="link-url">${escapeHtml(l.url)}</div>
          ${(l.tags && l.tags.length) ? `<div class="link-tags">${l.tags.map(t=>`<span class="tag">${escapeHtml(t)}</span>`).join("")}</div>` : ""}
          ${revealed ? `
          <div class="cred-row">
            <span class="cred-item">👤 <b>${escapeHtml(revealed.user || "—")}</b></span>
            <button class="icon-btn" data-copyuser="${l.id}" style="color:var(--accent)">copier</button>
            <span class="cred-item">🔒 <b>${escapeHtml(revealed.pass || "—")}</b></span>
            <button class="icon-btn" data-copypass="${l.id}" style="color:var(--accent)">copier</button>
          </div>` : ""}
        </div>
        <div class="link-actions">
          ${(l.cred || l.pendingCred) ? `<button class="btn small" data-cred="${l.id}">🔑 ${revealed ? "Hide" : (l.pendingCred && !l.cred ? "Encrypt & view" : "Credentials")}</button>` : ""}
          <button class="btn small" data-edit="${l.id}">Edit</button>
          <button class="btn small" data-del="${l.id}">Delete</button>
        </div>
      `;
      linkList.appendChild(card);
    });
    linkList.querySelectorAll("[data-edit]").forEach(btn=> btn.addEventListener("click", ()=> openLinkModal(btn.dataset.edit)));
    linkList.querySelectorAll("[data-del]").forEach(btn=>{
      btn.addEventListener("click", ()=>{
        if(confirm("Delete this link?")){
          data.links = data.links.filter(l=>l.id!==btn.dataset.del);
          delete revealedCreds[btn.dataset.del];
          scheduleSave(); render();
        }
      });
    });
    linkList.querySelectorAll("[data-cred]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = btn.dataset.cred;
        if(revealedCreds[id]){ delete revealedCreds[id]; render(); return; }
        const link = data.links.find(l=>l.id===id);
        const key = await ensureMasterKey();
        if(!key) return;
        try{
          if(link.pendingCred && !link.cred){
            link.cred = await encryptJSON(key, link.pendingCred);
            revealedCreds[id] = link.pendingCred;
            delete link.pendingCred;
            scheduleSave();
          }else{
            revealedCreds[id] = await decryptJSON(key, link.cred);
          }
        }catch(e){ alert("Could not decrypt (wrong password?)."); return; }
        render();
      });
    });
    linkList.querySelectorAll("[data-copyuser]").forEach(btn=>{
      btn.addEventListener("click", ()=> navigator.clipboard.writeText(revealedCreds[btn.dataset.copyuser]?.user || ""));
    });
    linkList.querySelectorAll("[data-copypass]").forEach(btn=>{
      btn.addEventListener("click", ()=> navigator.clipboard.writeText(revealedCreds[btn.dataset.copypass]?.pass || ""));
    });
  }

  function escapeHtml(s){ return (s||"").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
  function escapeAttr(s){ return escapeHtml(s); }

  // ===== Link modal =====
  function openLinkModal(id){
    editingLinkId = id || null;
    removeCredFlag = false;
    const link = id ? data.links.find(l=>l.id===id) : null;
    $("linkModalTitle").textContent = link ? "Edit link" : "New link";
    $("linkTitleInput").value = link ? link.title : "";
    $("linkUrlInput").value = link ? link.url : "";
    $("linkTagsInput").value = link ? (link.tags||[]).join(", ") : "";
    $("linkUserInput").value = "";
    $("linkPassInput").value = "";
    $("credRemoveWrap").style.display = "none";

    if(link && link.cred){
      const rev = revealedCreds[link.id];
      if(rev){
        $("linkUserInput").value = rev.user || "";
        $("linkPassInput").value = rev.pass || "";
      }else{
        $("linkUserInput").placeholder = "•••• (saved — leave blank to keep)";
        $("linkPassInput").placeholder = "•••• (saved — leave blank to keep)";
      }
      $("credRemoveWrap").style.display = "block";
    }else{
      $("linkUserInput").placeholder = "Utilisateur";
      $("linkPassInput").placeholder = "Mot de passe";
    }

    renderFolderSelect();
    $("linkFolderInput").value = link ? (link.folderId || data.folders[0]?.id) : (activeFolder !== ALL_ID ? activeFolder : data.folders[0]?.id);
    $("linkOverlay").classList.add("show");
    $("linkTitleInput").focus();
  }
  function closeLinkModal(){ $("linkOverlay").classList.remove("show"); editingLinkId = null; }

  $("btnAddLink").addEventListener("click", ()=>{
    if(data.folders.length === 0){ alert("Create a folder first."); return; }
    openLinkModal(null);
  });
  $("linkCancel").addEventListener("click", closeLinkModal);
  $("linkOverlay").addEventListener("click", (e)=>{ if(e.target.id==="linkOverlay") closeLinkModal(); });
  $("btnRemoveCred").addEventListener("click", ()=>{
    removeCredFlag = true;
    $("linkUserInput").value = ""; $("linkUserInput").placeholder = "Utilisateur";
    $("linkPassInput").value = ""; $("linkPassInput").placeholder = "Mot de passe";
    $("credRemoveWrap").style.display = "none";
  });

  $("linkSaveBtn").addEventListener("click", async ()=>{
    let url = $("linkUrlInput").value.trim();
    const title = $("linkTitleInput").value.trim();
    if(!url){ alert("URL is required."); return; }
    if(!/^https?:\/\//i.test(url)) url = "https://" + url;
    const tags = $("linkTagsInput").value.split(",").map(t=>t.trim()).filter(Boolean);
    const folderId = $("linkFolderInput").value;
    const userVal = $("linkUserInput").value;
    const passVal = $("linkPassInput").value;

    const existing = editingLinkId ? data.links.find(l=>l.id===editingLinkId) : null;
    let cred = existing ? existing.cred : undefined;

    if(removeCredFlag){
      cred = undefined;
      if(editingLinkId) delete revealedCreds[editingLinkId];
    }else if(userVal || passVal){
      const key = await ensureMasterKey();
      if(!key) return;
      cred = await encryptJSON(key, { user: userVal, pass: passVal });
      if(editingLinkId) revealedCreds[editingLinkId] = { user: userVal, pass: passVal };
    }

    if(editingLinkId){
      existing.title = title || url; existing.url = url; existing.tags = tags; existing.folderId = folderId; existing.cred = cred;
    }else{
      data.links.push({ id: uid(), title: title || url, url, tags, folderId, cred, createdAt: Date.now() });
    }
    closeLinkModal();
    scheduleSave();
    render();
  });

  // ===== Folder modal =====
  $("btnAddFolder").addEventListener("click", ()=>{
    $("folderNameInput").value = "";
    $("folderOverlay").classList.add("show");
    $("folderNameInput").focus();
  });
  $("folderCancel").addEventListener("click", ()=> $("folderOverlay").classList.remove("show"));
  $("folderOverlay").addEventListener("click", (e)=>{ if(e.target.id==="folderOverlay") $("folderOverlay").classList.remove("show"); });
  $("folderSaveBtn").addEventListener("click", ()=>{
    const name = $("folderNameInput").value.trim();
    if(!name) return;
    data.folders.push({ id: uid(), name });
    $("folderOverlay").classList.remove("show");
    scheduleSave(); render();
  });

  // ===== Top bar =====
  $("btnImport").addEventListener("click", importFile);
  $("btnExport").addEventListener("click", exportFile);
  $("btnOpen").addEventListener("click", openFile);
  $("btnSave").addEventListener("click", persist);
  $("search").addEventListener("input", renderLinks);

  $("importInput").addEventListener("change", async (e)=>{
    const file = e.target.files[0];
    e.target.value = "";
    if(!file) return;
    try{
      const text = await file.text();
      const parsed = JSON.parse(text);
      if(confirm("Importing \"" + file.name + "\" will replace the links currently loaded. Continue?")){
        loadImportedData(parsed, file.name);
      }
    }catch(err){ alert("Invalid JSON file."); }
  });

  // Init
  data = newData();
  fileNameEl.textContent = hasFSAccess ? "No file open" : "File System Access unavailable";
  render();
  tryRestoreLastFile();

})();