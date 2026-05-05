import { useState, useCallback, useRef, useEffect } from "react";

// ─── Crypto Utilities ──────────────────────────────────────────────────────
const CryptoUtils = {
  async generateKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false, ["encrypt", "decrypt"]
    );
  },
  async encrypt(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(data))
    );
    return { iv: Array.from(iv), data: Array.from(new Uint8Array(encrypted)) };
  },
  async decrypt(encrypted, key) {
    const dec = new TextDecoder();
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(encrypted.iv) },
      key, new Uint8Array(encrypted.data)
    );
    return JSON.parse(dec.decode(decrypted));
  },
  async hashPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw", enc.encode(password + salt), "PBKDF2", false, ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
      keyMaterial, 256
    );
    return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
  },
  generateSalt: () => Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2,"0")).join(""),
  generateId: () => crypto.randomUUID(),
};

// ─── Initial Data ──────────────────────────────────────────────────────────
const INITIAL_USERS = [
  { id: "u1", username: "admin", role: "admin", salt: "adminsalt123", passwordHash: null, createdAt: new Date().toISOString() },
  { id: "u2", username: "alice", role: "editor", salt: "alicesalt456", passwordHash: null, createdAt: new Date().toISOString() },
  { id: "u3", username: "bob", role: "viewer", salt: "bobsalt789", passwordHash: null, createdAt: new Date().toISOString() },
];
const DEMO_PASSWORDS = { admin: "Admin@123", alice: "Alice@456", bob: "Bob@789" };
const DEMO_FILES = [
  { id: "f1", name: "Q4_Financial_Report.pdf", size: 2457600, type: "pdf", ownerId: "u1", permissions: { u1: "owner", u2: "edit", u3: "view" }, tags: ["finance", "confidential"], encrypted: true, createdAt: new Date(Date.now() - 86400000 * 7).toISOString(), modifiedAt: new Date(Date.now() - 86400000).toISOString(), checksum: "a3f2b1c4d5e6f789" },
  { id: "f2", name: "Project_Roadmap_2025.docx", size: 892416, type: "docx", ownerId: "u2", permissions: { u1: "owner", u2: "owner", u3: "view" }, tags: ["planning"], encrypted: true, createdAt: new Date(Date.now() - 86400000 * 3).toISOString(), modifiedAt: new Date(Date.now() - 3600000 * 2).toISOString(), checksum: "b4c3d2e1f0a9b8c7" },
  { id: "f3", name: "Team_Contacts.xlsx", size: 45056, type: "xlsx", ownerId: "u1", permissions: { u1: "owner", u2: "edit", u3: "view" }, tags: ["team", "hr"], encrypted: true, createdAt: new Date(Date.now() - 86400000 * 14).toISOString(), modifiedAt: new Date(Date.now() - 86400000 * 2).toISOString(), checksum: "c5d4e3f2a1b0c9d8" },
  { id: "f4", name: "Security_Audit_Log.txt", size: 128000, type: "txt", ownerId: "u1", permissions: { u1: "owner" }, tags: ["security", "restricted"], encrypted: true, createdAt: new Date(Date.now() - 86400000 * 2).toISOString(), modifiedAt: new Date().toISOString(), checksum: "d6e5f4a3b2c1d0e9" },
  { id: "f5", name: "Product_Design_v3.png", size: 5242880, type: "png", ownerId: "u2", permissions: { u1: "owner", u2: "owner", u3: "view" }, tags: ["design"], encrypted: false, createdAt: new Date(Date.now() - 3600000 * 5).toISOString(), modifiedAt: new Date(Date.now() - 3600000).toISOString(), checksum: "e7f6a5b4c3d2e1f0" },
];
const INITIAL_AUDIT = [
  { id: "a1", userId: "u1", action: "LOGIN", resource: "system", timestamp: new Date(Date.now() - 3600000 * 2).toISOString(), ip: "192.168.1.1", success: true },
  { id: "a2", userId: "u2", action: "FILE_VIEW", resource: "f2", timestamp: new Date(Date.now() - 3600000).toISOString(), ip: "192.168.1.5", success: true },
  { id: "a3", userId: "u3", action: "FILE_VIEW", resource: "f4", timestamp: new Date(Date.now() - 1800000).toISOString(), ip: "192.168.1.8", success: false },
  { id: "a4", userId: "u1", action: "FILE_UPLOAD", resource: "f5", timestamp: new Date(Date.now() - 900000).toISOString(), ip: "192.168.1.1", success: true },
];

// ─── App Shell ─────────────────────────────────────────────────────────────
export default function App() {
  const [view, setView] = useState("login"); // login | main
  const [session, setSession] = useState(null);
  const [users, setUsers] = useState([]);
  const [files, setFiles] = useState([]);
  const [auditLog, setAuditLog] = useState(INITIAL_AUDIT);
  const [activeTab, setActiveTab] = useState("files");
  const [selectedFile, setSelectedFile] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterTag, setFilterTag] = useState("all");
  const [toast, setToast] = useState(null);
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [shareModalFile, setShareModalFile] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState(null);
  const [initialized, setInitialized] = useState(false);
  const sessionTimerRef = useRef(null);

  useEffect(() => {
    const init = async () => {
      const usersWithHashes = await Promise.all(
        INITIAL_USERS.map(async u => ({
          ...u,
          passwordHash: await CryptoUtils.hashPassword(DEMO_PASSWORDS[u.username], u.salt)
        }))
      );
      setUsers(usersWithHashes);
      setFiles(DEMO_FILES);
      setInitialized(true);
    };
    init();
  }, []);

  const showToast = useCallback((msg, type = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  }, []);

  const addAudit = useCallback((userId, action, resource, success = true) => {
    setAuditLog(prev => [{
      id: CryptoUtils.generateId(), userId, action, resource,
      timestamp: new Date().toISOString(), ip: "192.168.1." + Math.floor(Math.random() * 254 + 1), success
    }, ...prev].slice(0, 100));
  }, []);

  const resetSessionTimer = useCallback(() => {
    if (sessionTimerRef.current) clearTimeout(sessionTimerRef.current);
    sessionTimerRef.current = setTimeout(() => {
      setSession(null); setView("login");
      showToast("Session expired. Please login again.", "warning");
    }, 15 * 60 * 1000);
  }, [showToast]);

  const handleLogin = useCallback(async (username, password) => {
    const user = users.find(u => u.username === username);
    if (!user) return false;
    const hash = await CryptoUtils.hashPassword(password, user.salt);
    if (hash !== user.passwordHash) {
      addAudit(user.id, "LOGIN_FAILED", "system", false);
      return false;
    }
    const sessionKey = await CryptoUtils.generateKey(password, user.salt);
    const token = { userId: user.id, role: user.role, expires: Date.now() + 15 * 60 * 1000 };
    setSession({ ...user, sessionKey, token });
    setView("main");
    addAudit(user.id, "LOGIN", "system", true);
    resetSessionTimer();
    return true;
  }, [users, addAudit, resetSessionTimer]);

  const handleLogout = useCallback(() => {
    if (session) addAudit(session.id, "LOGOUT", "system", true);
    if (sessionTimerRef.current) clearTimeout(sessionTimerRef.current);
    setSession(null); setView("login"); setSelectedFile(null);
  }, [session, addAudit]);

  const canAccess = useCallback((file, level = "view") => {
    if (!session) return false;
    if (session.role === "admin") return true;
    const perm = file.permissions[session.id];
    if (!perm) return false;
    if (level === "view") return true;
    if (level === "edit") return perm === "edit" || perm === "owner";
    if (level === "delete") return perm === "owner";
    return false;
  }, [session]);

  const handleFileAction = useCallback((file, action) => {
    if (!canAccess(file, action === "delete" ? "delete" : action === "share" ? "edit" : "view")) {
      addAudit(session.id, `FILE_${action.toUpperCase()}`, file.id, false);
      showToast("Access denied: insufficient permissions", "error");
      return;
    }
    addAudit(session.id, `FILE_${action.toUpperCase()}`, file.id, true);
    if (action === "view") setSelectedFile(file);
    else if (action === "delete") setDeleteConfirm(file);
    else if (action === "share") setShareModalFile(file);
    else if (action === "download") showToast(`Downloading "${file.name}" (encrypted transfer)...`);
  }, [canAccess, session, addAudit, showToast]);

  const handleDeleteConfirm = useCallback(() => {
    if (!deleteConfirm) return;
    setFiles(prev => prev.filter(f => f.id !== deleteConfirm.id));
    addAudit(session.id, "FILE_DELETE", deleteConfirm.id, true);
    showToast(`"${deleteConfirm.name}" deleted permanently`);
    setDeleteConfirm(null);
    if (selectedFile?.id === deleteConfirm.id) setSelectedFile(null);
  }, [deleteConfirm, session, addAudit, showToast, selectedFile]);

  const handleUpload = useCallback((fileName, encrypt) => {
    const ext = fileName.split(".").pop().toLowerCase();
    const newFile = {
      id: CryptoUtils.generateId(), name: fileName,
      size: Math.floor(Math.random() * 5000000 + 100000), type: ext,
      ownerId: session.id,
      permissions: { [session.id]: "owner" },
      tags: [], encrypted: encrypt,
      createdAt: new Date().toISOString(), modifiedAt: new Date().toISOString(),
      checksum: Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b=>b.toString(16).padStart(2,"0")).join("")
    };
    setFiles(prev => [newFile, ...prev]);
    addAudit(session.id, "FILE_UPLOAD", newFile.id, true);
    showToast(`"${fileName}" uploaded${encrypt ? " with encryption" : ""}`);
    setUploadModalOpen(false);
  }, [session, addAudit, showToast]);

  const filteredFiles = files.filter(f => {
    const accessible = session?.role === "admin" || f.permissions[session?.id];
    if (!accessible) return false;
    if (searchQuery && !f.name.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    if (filterTag !== "all" && !f.tags.includes(filterTag)) return false;
    return true;
  });

  const allTags = [...new Set(files.flatMap(f => f.tags))];
  const stats = {
    total: filteredFiles.length,
    encrypted: filteredFiles.filter(f => f.encrypted).length,
    myFiles: filteredFiles.filter(f => f.ownerId === session?.id).length,
    shared: filteredFiles.filter(f => Object.keys(f.permissions).length > 1).length,
  };

  if (!initialized) return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100vh", fontFamily:"'IBM Plex Mono', monospace", background:"#0a0e1a", color:"#4ade80" }}>
      <div style={{ textAlign:"center" }}>
        <div style={{ fontSize:24, marginBottom:8 }}>INITIALIZING CRYPTO ENGINE</div>
        <div style={{ fontSize:12, color:"#22d3ee", animation:"pulse 1s infinite" }}>Generating key material...</div>
      </div>
    </div>
  );

  if (view === "login") return <LoginView onLogin={handleLogin} />;

  return (
    <div style={{ fontFamily:"'IBM Plex Mono', monospace", background:"#0a0e1a", minHeight:"100vh", color:"#e2e8f0", display:"flex", flexDirection:"column" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0a0e1a; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }
        .file-row:hover { background: rgba(34,211,238,0.05) !important; }
        .action-btn:hover { background: rgba(34,211,238,0.1) !important; color: #22d3ee !important; }
        .tab-btn.active { border-bottom: 2px solid #22d3ee; color: #22d3ee; }
        .tag-pill { display:inline-block; padding:2px 8px; border-radius:4px; font-size:10px; background:rgba(34,211,238,0.1); color:#22d3ee; border:1px solid rgba(34,211,238,0.2); }
        .modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.7); backdrop-filter:blur(4px); display:flex; align-items:center; justify-content:center; z-index:1000; }
        .encrypt-badge { padding:2px 6px; border-radius:3px; font-size:9px; font-family:'IBM Plex Mono',monospace; }
        .stat-card { background:rgba(15,23,42,0.8); border:1px solid rgba(34,211,238,0.2); border-radius:8px; padding:16px; }
        .perm-chip { padding:3px 8px; border-radius:4px; font-size:10px; font-weight:600; }
        input, select { background:#0f172a; border:1px solid rgba(34,211,238,0.3); color:#e2e8f0; padding:8px 12px; border-radius:6px; font-family:'IBM Plex Mono',monospace; font-size:13px; width:100%; outline:none; transition:border-color 0.2s; }
        input:focus, select:focus { border-color:#22d3ee; }
        .btn-primary { background:#22d3ee; color:#0a0e1a; border:none; padding:8px 20px; border-radius:6px; font-family:'IBM Plex Mono',monospace; font-weight:600; font-size:13px; cursor:pointer; transition:opacity 0.2s; }
        .btn-primary:hover { opacity:0.85; }
        .btn-ghost { background:transparent; border:1px solid rgba(34,211,238,0.3); color:#94a3b8; padding:6px 14px; border-radius:6px; font-family:'IBM Plex Mono',monospace; font-size:12px; cursor:pointer; transition:all 0.2s; }
        .btn-ghost:hover { border-color:#22d3ee; color:#22d3ee; }
        .btn-danger { background:transparent; border:1px solid rgba(239,68,68,0.4); color:#f87171; padding:6px 14px; border-radius:6px; font-family:'IBM Plex Mono',monospace; font-size:12px; cursor:pointer; }
        .btn-danger:hover { background:rgba(239,68,68,0.1); }
        @keyframes scanline { from{top:-100%} to{top:200%} }
        @keyframes blink { 0%,50%{opacity:1} 51%,100%{opacity:0} }
        @keyframes slideIn { from{transform:translateY(-10px);opacity:0} to{transform:translateY(0);opacity:1} }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
      `}</style>

      {/* ─ Topbar ─ */}
      <header style={{ background:"#060912", borderBottom:"1px solid rgba(34,211,238,0.15)", padding:"0 24px", height:56, display:"flex", alignItems:"center", justifyContent:"space-between", position:"sticky", top:0, zIndex:100 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <div style={{ width:32, height:32, background:"rgba(34,211,238,0.1)", border:"1px solid rgba(34,211,238,0.4)", borderRadius:6, display:"flex", alignItems:"center", justifyContent:"center" }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </div>
          <span style={{ fontSize:15, fontWeight:600, color:"#22d3ee", letterSpacing:"0.05em" }}>SECUREVAULT</span>
          <span style={{ fontSize:10, color:"#475569", padding:"2px 6px", border:"1px solid #1e293b", borderRadius:3 }}>v2.4.1</span>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <div style={{ width:8, height:8, borderRadius:"50%", background:"#4ade80", boxShadow:"0 0 6px #4ade80" }}></div>
            <span style={{ fontSize:12, color:"#94a3b8" }}>AES-256 Active</span>
          </div>
          <div style={{ display:"flex", alignItems:"center", gap:8, padding:"4px 12px", background:"rgba(34,211,238,0.05)", border:"1px solid rgba(34,211,238,0.15)", borderRadius:6 }}>
            <div style={{ width:24, height:24, borderRadius:"50%", background:"rgba(34,211,238,0.15)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:10, color:"#22d3ee", fontWeight:600 }}>
              {session.username[0].toUpperCase()}
            </div>
            <span style={{ fontSize:12, color:"#cbd5e1" }}>{session.username}</span>
            <span style={{ fontSize:9, padding:"1px 5px", background:session.role==="admin"?"rgba(239,68,68,0.15)":session.role==="editor"?"rgba(34,211,238,0.1)":"rgba(100,116,139,0.2)", color:session.role==="admin"?"#f87171":session.role==="editor"?"#22d3ee":"#94a3b8", border:`1px solid ${session.role==="admin"?"rgba(239,68,68,0.3)":session.role==="editor"?"rgba(34,211,238,0.3)":"rgba(100,116,139,0.3)"}`, borderRadius:3, letterSpacing:"0.05em" }}>{session.role.toUpperCase()}</span>
          </div>
          <button className="btn-ghost" onClick={handleLogout} style={{ padding:"4px 12px", fontSize:11 }}>LOGOUT</button>
        </div>
      </header>

      <div style={{ display:"flex", flex:1 }}>
        {/* ─ Sidebar ─ */}
        <aside style={{ width:220, background:"#060912", borderRight:"1px solid rgba(34,211,238,0.1)", padding:"20px 0", flexShrink:0 }}>
          {[
            { id:"files", icon:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>, label:"Files" },
            { id:"audit", icon:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>, label:"Audit Log" },
            ...(session.role === "admin" ? [{ id:"users", icon:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>, label:"Users" }] : []),
          ].map(tab => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)} style={{ width:"100%", background:activeTab===tab.id?"rgba(34,211,238,0.08)":"transparent", border:"none", borderLeft:activeTab===tab.id?"2px solid #22d3ee":"2px solid transparent", color:activeTab===tab.id?"#22d3ee":"#64748b", padding:"10px 20px", textAlign:"left", display:"flex", alignItems:"center", gap:10, cursor:"pointer", fontSize:12, fontFamily:"'IBM Plex Mono',monospace", letterSpacing:"0.05em", transition:"all 0.15s" }}>
              {tab.icon}{tab.label.toUpperCase()}
            </button>
          ))}
          <div style={{ margin:"20px 12px", padding:12, background:"rgba(15,23,42,0.6)", border:"1px solid rgba(34,211,238,0.1)", borderRadius:6 }}>
            <div style={{ fontSize:9, color:"#475569", marginBottom:8, letterSpacing:"0.1em" }}>ENCRYPTION STATUS</div>
            <div style={{ fontSize:11, color:"#22d3ee", marginBottom:4 }}>AES-256-GCM</div>
            <div style={{ fontSize:9, color:"#64748b", marginBottom:8 }}>PBKDF2 · 100K rounds</div>
            <div style={{ height:2, background:"#1e293b", borderRadius:1, overflow:"hidden" }}>
              <div style={{ height:"100%", width:`${stats.total?stats.encrypted/stats.total*100:0}%`, background:"#22d3ee", borderRadius:1, transition:"width 0.5s" }}></div>
            </div>
            <div style={{ fontSize:9, color:"#64748b", marginTop:4 }}>{stats.encrypted}/{stats.total} files encrypted</div>
          </div>
        </aside>

        {/* ─ Main Content ─ */}
        <main style={{ flex:1, overflow:"auto", padding:24 }}>
          {activeTab === "files" && (
            <>
              {/* Stats */}
              <div style={{ display:"grid", gridTemplateColumns:"repeat(4, 1fr)", gap:12, marginBottom:20 }}>
                {[
                  { label:"Total Files", val:stats.total, color:"#22d3ee" },
                  { label:"Encrypted", val:stats.encrypted, color:"#4ade80" },
                  { label:"Owned", val:stats.myFiles, color:"#a78bfa" },
                  { label:"Shared", val:stats.shared, color:"#fb923c" },
                ].map(s => (
                  <div key={s.label} className="stat-card">
                    <div style={{ fontSize:9, color:"#475569", letterSpacing:"0.1em", marginBottom:6 }}>{s.label.toUpperCase()}</div>
                    <div style={{ fontSize:28, fontWeight:600, color:s.color }}>{s.val}</div>
                  </div>
                ))}
              </div>

              {/* Toolbar */}
              <div style={{ display:"flex", gap:10, marginBottom:16, alignItems:"center" }}>
                <div style={{ flex:1, position:"relative" }}>
                  <svg style={{ position:"absolute", left:10, top:"50%", transform:"translateY(-50%)" }} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#475569" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                  <input value={searchQuery} onChange={e => setSearchQuery(e.target.value)} placeholder="Search files..." style={{ paddingLeft:32 }} />
                </div>
                <select value={filterTag} onChange={e => setFilterTag(e.target.value)} style={{ width:140 }}>
                  <option value="all">All tags</option>
                  {allTags.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                {(session.role === "admin" || session.role === "editor") && (
                  <button className="btn-primary" onClick={() => setUploadModalOpen(true)} style={{ display:"flex", alignItems:"center", gap:6, whiteSpace:"nowrap" }}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    UPLOAD
                  </button>
                )}
              </div>

              {/* File Table */}
              <div style={{ background:"#060912", border:"1px solid rgba(34,211,238,0.1)", borderRadius:8, overflow:"hidden" }}>
                <div style={{ display:"grid", gridTemplateColumns:"2fr 80px 100px 120px 80px 120px", padding:"8px 16px", background:"rgba(34,211,238,0.05)", borderBottom:"1px solid rgba(34,211,238,0.1)", fontSize:9, color:"#475569", letterSpacing:"0.1em" }}>
                  <span>FILE NAME</span><span>SIZE</span><span>TYPE</span><span>MODIFIED</span><span>STATUS</span><span style={{ textAlign:"right" }}>ACTIONS</span>
                </div>
                {filteredFiles.length === 0 ? (
                  <div style={{ padding:40, textAlign:"center", color:"#334155", fontSize:12 }}>NO FILES FOUND</div>
                ) : filteredFiles.map(file => (
                  <FileRow key={file.id} file={file} session={session} users={INITIAL_USERS} canAccess={canAccess} onAction={handleFileAction} />
                ))}
              </div>
            </>
          )}

          {activeTab === "audit" && <AuditLogView log={auditLog} users={INITIAL_USERS} files={files} />}
          {activeTab === "users" && session.role === "admin" && <UsersView users={users} files={files} />}
        </main>

        {/* ─ File Detail Panel ─ */}
        {selectedFile && (
          <FileDetailPanel file={selectedFile} session={session} users={INITIAL_USERS} canAccess={canAccess} onClose={() => setSelectedFile(null)} onAction={handleFileAction} />
        )}
      </div>

      {/* ─ Modals ─ */}
      {uploadModalOpen && <UploadModal onUpload={handleUpload} onClose={() => setUploadModalOpen(false)} />}
      {shareModalFile && <ShareModal file={shareModalFile} users={users} session={session} files={files} setFiles={setFiles} onClose={() => setShareModalFile(null)} showToast={showToast} addAudit={addAudit} />}
      {deleteConfirm && (
        <div className="modal-overlay">
          <div style={{ background:"#0f172a", border:"1px solid rgba(239,68,68,0.3)", borderRadius:10, padding:28, width:380, animation:"slideIn 0.2s ease" }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f87171" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              <span style={{ color:"#f87171", fontSize:14, fontWeight:600 }}>CONFIRM DELETION</span>
            </div>
            <p style={{ color:"#94a3b8", fontSize:12, marginBottom:20, lineHeight:1.6 }}>
              This will permanently delete <span style={{ color:"#e2e8f0" }}>"{deleteConfirm.name}"</span>. This action cannot be undone.
            </p>
            <div style={{ display:"flex", gap:10, justifyContent:"flex-end" }}>
              <button className="btn-ghost" onClick={() => setDeleteConfirm(null)}>CANCEL</button>
              <button className="btn-danger" onClick={handleDeleteConfirm}>DELETE PERMANENTLY</button>
            </div>
          </div>
        </div>
      )}
      {toast && (
        <div style={{ position:"fixed", bottom:24, right:24, background:toast.type==="error"?"rgba(239,68,68,0.15)":toast.type==="warning"?"rgba(251,146,60,0.15)":"rgba(74,222,128,0.15)", border:`1px solid ${toast.type==="error"?"rgba(239,68,68,0.4)":toast.type==="warning"?"rgba(251,146,60,0.4)":"rgba(74,222,128,0.4)"}`, color:toast.type==="error"?"#f87171":toast.type==="warning"?"#fb923c":"#4ade80", padding:"10px 16px", borderRadius:8, fontSize:12, fontFamily:"'IBM Plex Mono',monospace", animation:"slideIn 0.2s ease", zIndex:9999, maxWidth:360 }}>
          {toast.msg}
        </div>
      )}
    </div>
  );
}

// ─── Login View ─────────────────────────────────────────────────────────────
function LoginView({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [locked, setLocked] = useState(false);
  const lockTimer = useRef(null);

  const handleSubmit = async () => {
    if (locked) return;
    if (!username || !password) { setError("All fields required"); return; }
    setLoading(true); setError("");
    const ok = await onLogin(username, password);
    setLoading(false);
    if (!ok) {
      const newAttempts = attempts + 1;
      setAttempts(newAttempts);
      if (newAttempts >= 3) {
        setLocked(true); setError("Too many failed attempts. Locked for 30s.");
        lockTimer.current = setTimeout(() => { setLocked(false); setAttempts(0); setError(""); }, 30000);
      } else {
        setError(`Invalid credentials. ${3 - newAttempts} attempt(s) remaining.`);
      }
    }
  };

  return (
    <div style={{ fontFamily:"'IBM Plex Mono', monospace", background:"#0a0e1a", minHeight:"100vh", display:"flex", alignItems:"center", justifyContent:"center", position:"relative", overflow:"hidden" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        input { background:#0f172a; border:1px solid rgba(34,211,238,0.3); color:#e2e8f0; padding:10px 14px; border-radius:6px; font-family:'IBM Plex Mono',monospace; font-size:13px; width:100%; outline:none; transition:border-color 0.2s; }
        input:focus { border-color:#22d3ee; }
        @keyframes pulse { 0%,100%{opacity:0.3} 50%{opacity:0.8} }
        @keyframes slideIn { from{transform:translateY(-10px);opacity:0} to{transform:translateY(0);opacity:1} }
        @keyframes scanline { from{top:-100%} to{top:200%} }
      `}</style>

      {/* Grid bg */}
      <div style={{ position:"absolute", inset:0, backgroundImage:"linear-gradient(rgba(34,211,238,0.03) 1px, transparent 1px),linear-gradient(90deg, rgba(34,211,238,0.03) 1px, transparent 1px)", backgroundSize:"40px 40px" }}></div>
      {/* Glow */}
      <div style={{ position:"absolute", top:"30%", left:"50%", transform:"translate(-50%,-50%)", width:400, height:400, background:"radial-gradient(circle, rgba(34,211,238,0.06) 0%, transparent 70%)", pointerEvents:"none" }}></div>

      <div style={{ width:400, animation:"slideIn 0.3s ease" }}>
        <div style={{ textAlign:"center", marginBottom:32 }}>
          <div style={{ width:56, height:56, background:"rgba(34,211,238,0.1)", border:"2px solid rgba(34,211,238,0.4)", borderRadius:12, margin:"0 auto 16px", display:"flex", alignItems:"center", justifyContent:"center" }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </div>
          <h1 style={{ fontSize:22, fontWeight:600, color:"#22d3ee", letterSpacing:"0.1em" }}>SECUREVAULT</h1>
          <p style={{ fontSize:11, color:"#475569", marginTop:4, letterSpacing:"0.05em" }}>ENCRYPTED FILE MANAGEMENT SYSTEM</p>
        </div>

        <div style={{ background:"rgba(6,9,18,0.9)", border:"1px solid rgba(34,211,238,0.2)", borderRadius:12, padding:28, backdropFilter:"blur(10px)" }}>
          <div style={{ fontSize:9, color:"#22d3ee", letterSpacing:"0.15em", marginBottom:20, paddingBottom:8, borderBottom:"1px solid rgba(34,211,238,0.1)" }}>
            AUTHENTICATION REQUIRED
          </div>

          <div style={{ marginBottom:14 }}>
            <label style={{ display:"block", fontSize:10, color:"#475569", letterSpacing:"0.1em", marginBottom:6 }}>USERNAME</label>
            <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Enter username" onKeyDown={e => e.key==="Enter" && handleSubmit()} />
          </div>
          <div style={{ marginBottom:20 }}>
            <label style={{ display:"block", fontSize:10, color:"#475569", letterSpacing:"0.1em", marginBottom:6 }}>PASSWORD</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Enter password" onKeyDown={e => e.key==="Enter" && handleSubmit()} />
          </div>

          {error && <div style={{ background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.3)", borderRadius:6, padding:"8px 12px", fontSize:11, color:"#f87171", marginBottom:16 }}>{error}</div>}

          <button onClick={handleSubmit} disabled={loading || locked} style={{ width:"100%", background:"#22d3ee", color:"#0a0e1a", border:"none", padding:"10px", borderRadius:6, fontFamily:"'IBM Plex Mono',monospace", fontWeight:600, fontSize:13, cursor:loading||locked?"not-allowed":"pointer", opacity:loading||locked?0.5:1, letterSpacing:"0.1em" }}>
            {loading ? "AUTHENTICATING..." : locked ? "LOCKED" : "LOGIN"}
          </button>

          <div style={{ marginTop:20, padding:12, background:"rgba(34,211,238,0.03)", border:"1px solid rgba(34,211,238,0.1)", borderRadius:6 }}>
            <div style={{ fontSize:9, color:"#475569", letterSpacing:"0.1em", marginBottom:8 }}>DEMO CREDENTIALS</div>
            {[["admin","Admin@123","ADMIN"],["alice","Alice@456","EDITOR"],["bob","Bob@789","VIEWER"]].map(([u,p,r]) => (
              <div key={u} onClick={() => { setUsername(u); setPassword(p); }} style={{ display:"flex", justifyContent:"space-between", padding:"4px 0", cursor:"pointer", fontSize:11, color:"#64748b", borderBottom:"1px solid rgba(34,211,238,0.05)" }}>
                <span>{u} / {p}</span>
                <span style={{ fontSize:9, color:r==="ADMIN"?"#f87171":r==="EDITOR"?"#22d3ee":"#94a3b8" }}>{r}</span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ display:"flex", justifyContent:"center", gap:16, marginTop:16 }}>
          {[["AES-256","#4ade80"],["PBKDF2","#22d3ee"],["TLS 1.3","#a78bfa"]].map(([label, color]) => (
            <div key={label} style={{ display:"flex", alignItems:"center", gap:4 }}>
              <div style={{ width:5, height:5, borderRadius:"50%", background:color, animation:"pulse 2s infinite" }}></div>
              <span style={{ fontSize:9, color:"#475569", letterSpacing:"0.05em" }}>{label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── File Row ────────────────────────────────────────────────────────────────
function FileRow({ file, session, users, canAccess, onAction }) {
  const icons = { pdf:"📄", docx:"📝", xlsx:"📊", txt:"📋", png:"🖼️", jpg:"🖼️", default:"📁" };
  const formatSize = b => b > 1048576 ? (b/1048576).toFixed(1)+"MB" : (b/1024).toFixed(0)+"KB";
  const formatDate = d => { const dt = new Date(d); return dt.toLocaleDateString("en",{month:"short",day:"numeric"}); };
  const owner = users.find(u => u.id === file.ownerId);
  const myPerm = session.role === "admin" ? "admin" : file.permissions[session.id];

  return (
    <div className="file-row" style={{ display:"grid", gridTemplateColumns:"2fr 80px 100px 120px 80px 120px", padding:"10px 16px", borderBottom:"1px solid rgba(34,211,238,0.05)", alignItems:"center", cursor:"pointer", transition:"background 0.15s" }}>
      <div style={{ display:"flex", alignItems:"center", gap:10 }}>
        <span style={{ fontSize:16 }}>{icons[file.type] || icons.default}</span>
        <div>
          <div style={{ fontSize:12, color:"#e2e8f0", fontWeight:500 }}>{file.name}</div>
          <div style={{ display:"flex", gap:4, marginTop:3 }}>
            {file.tags.map(t => <span key={t} className="tag-pill">{t}</span>)}
            {owner && <span style={{ fontSize:9, color:"#475569" }}>by {owner.username}</span>}
          </div>
        </div>
      </div>
      <span style={{ fontSize:11, color:"#64748b" }}>{formatSize(file.size)}</span>
      <span style={{ fontSize:10, color:"#475569", textTransform:"uppercase", letterSpacing:"0.05em" }}>{file.type}</span>
      <span style={{ fontSize:11, color:"#64748b" }}>{formatDate(file.modifiedAt)}</span>
      <div>
        {file.encrypted
          ? <span className="encrypt-badge" style={{ background:"rgba(74,222,128,0.1)", color:"#4ade80", border:"1px solid rgba(74,222,128,0.3)" }}>ENC</span>
          : <span className="encrypt-badge" style={{ background:"rgba(251,146,60,0.1)", color:"#fb923c", border:"1px solid rgba(251,146,60,0.3)" }}>PLAIN</span>}
      </div>
      <div style={{ display:"flex", gap:6, justifyContent:"flex-end" }}>
        <button className="action-btn" onClick={() => onAction(file, "view")} title="View" style={{ background:"transparent", border:"1px solid rgba(34,211,238,0.15)", color:"#475569", padding:"4px 8px", borderRadius:4, cursor:"pointer", fontSize:10, transition:"all 0.15s" }}>VIEW</button>
        {canAccess(file, "edit") && <button className="action-btn" onClick={() => onAction(file, "share")} title="Share" style={{ background:"transparent", border:"1px solid rgba(34,211,238,0.15)", color:"#475569", padding:"4px 8px", borderRadius:4, cursor:"pointer", fontSize:10, transition:"all 0.15s" }}>SHARE</button>}
        {canAccess(file, "delete") && <button className="action-btn" onClick={() => onAction(file, "delete")} title="Delete" style={{ background:"transparent", border:"1px solid rgba(239,68,68,0.2)", color:"#ef4444", padding:"4px 8px", borderRadius:4, cursor:"pointer", fontSize:10, transition:"all 0.15s" }}>DEL</button>}
      </div>
    </div>
  );
}

// ─── File Detail Panel ───────────────────────────────────────────────────────
function FileDetailPanel({ file, session, users, canAccess, onClose, onAction }) {
  const formatSize = b => b > 1048576 ? (b/1048576).toFixed(2)+" MB" : (b/1024).toFixed(1)+" KB";
  const owner = users.find(u => u.id === file.ownerId);

  return (
    <aside style={{ width:300, background:"#060912", borderLeft:"1px solid rgba(34,211,238,0.1)", padding:20, overflowY:"auto", flexShrink:0 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:20 }}>
        <span style={{ fontSize:10, color:"#22d3ee", letterSpacing:"0.1em" }}>FILE DETAILS</span>
        <button onClick={onClose} style={{ background:"transparent", border:"none", color:"#475569", cursor:"pointer", fontSize:18, lineHeight:1 }}>×</button>
      </div>

      <div style={{ textAlign:"center", padding:"20px 0", marginBottom:16, background:"rgba(34,211,238,0.03)", border:"1px solid rgba(34,211,238,0.1)", borderRadius:8 }}>
        <div style={{ fontSize:40, marginBottom:8 }}>📄</div>
        <div style={{ fontSize:12, color:"#e2e8f0", fontWeight:500, wordBreak:"break-all" }}>{file.name}</div>
      </div>

      {[
        ["Size", formatSize(file.size)],
        ["Type", file.type.toUpperCase()],
        ["Owner", owner?.username || "unknown"],
        ["Created", new Date(file.createdAt).toLocaleString()],
        ["Modified", new Date(file.modifiedAt).toLocaleString()],
        ["Checksum", file.checksum],
        ["Encryption", file.encrypted ? "AES-256-GCM" : "None"],
      ].map(([k, v]) => (
        <div key={k} style={{ display:"flex", justifyContent:"space-between", padding:"6px 0", borderBottom:"1px solid rgba(34,211,238,0.06)", fontSize:11 }}>
          <span style={{ color:"#475569" }}>{k}</span>
          <span style={{ color:"#94a3b8", maxWidth:160, textAlign:"right", wordBreak:"break-all" }}>{v}</span>
        </div>
      ))}

      <div style={{ marginTop:16 }}>
        <div style={{ fontSize:9, color:"#475569", letterSpacing:"0.1em", marginBottom:10 }}>PERMISSIONS</div>
        {Object.entries(file.permissions).map(([uid, perm]) => {
          const u = users.find(x => x.id === uid);
          const colors = { owner:["rgba(239,68,68,0.1)","#f87171","rgba(239,68,68,0.3)"], edit:["rgba(34,211,238,0.1)","#22d3ee","rgba(34,211,238,0.3)"], view:["rgba(100,116,139,0.1)","#94a3b8","rgba(100,116,139,0.3)"] };
          const c = colors[perm] || colors.view;
          return (
            <div key={uid} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:6 }}>
              <span style={{ fontSize:11, color:"#64748b" }}>{u?.username || uid}</span>
              <span style={{ fontSize:9, padding:"2px 8px", background:c[0], color:c[1], border:`1px solid ${c[2]}`, borderRadius:3 }}>{perm.toUpperCase()}</span>
            </div>
          );
        })}
      </div>

      <div style={{ display:"flex", flexDirection:"column", gap:8, marginTop:20 }}>
        <button onClick={() => onAction(file, "download")} style={{ background:"rgba(34,211,238,0.1)", border:"1px solid rgba(34,211,238,0.3)", color:"#22d3ee", padding:"8px", borderRadius:6, cursor:"pointer", fontSize:11, fontFamily:"'IBM Plex Mono',monospace" }}>DOWNLOAD (ENCRYPTED)</button>
        {canAccess(file, "edit") && <button onClick={() => onAction(file, "share")} style={{ background:"transparent", border:"1px solid rgba(34,211,238,0.2)", color:"#64748b", padding:"8px", borderRadius:6, cursor:"pointer", fontSize:11, fontFamily:"'IBM Plex Mono',monospace" }}>MANAGE SHARING</button>}
      </div>
    </aside>
  );
}

// ─── Audit Log View ──────────────────────────────────────────────────────────
function AuditLogView({ log, users, files }) {
  const getUser = id => users.find(u => u.id === id)?.username || id;
  const getFile = id => files.find(f => f.id === id)?.name || id;
  const actionColors = { LOGIN:"#22d3ee", LOGOUT:"#64748b", FILE_VIEW:"#a78bfa", FILE_UPLOAD:"#4ade80", FILE_DELETE:"#f87171", FILE_SHARE:"#fb923c", FILE_DOWNLOAD:"#22d3ee", LOGIN_FAILED:"#f87171", FILE_VIEW_FAILED:"#f87171" };

  return (
    <div>
      <div style={{ fontSize:10, color:"#22d3ee", letterSpacing:"0.15em", marginBottom:16 }}>SECURITY AUDIT LOG</div>
      <div style={{ background:"#060912", border:"1px solid rgba(34,211,238,0.1)", borderRadius:8, overflow:"hidden" }}>
        <div style={{ display:"grid", gridTemplateColumns:"160px 100px 120px 1fr 80px", padding:"8px 16px", background:"rgba(34,211,238,0.05)", borderBottom:"1px solid rgba(34,211,238,0.1)", fontSize:9, color:"#475569", letterSpacing:"0.1em" }}>
          <span>TIMESTAMP</span><span>USER</span><span>ACTION</span><span>RESOURCE</span><span>STATUS</span>
        </div>
        {log.map(entry => (
          <div key={entry.id} style={{ display:"grid", gridTemplateColumns:"160px 100px 120px 1fr 80px", padding:"8px 16px", borderBottom:"1px solid rgba(34,211,238,0.05)", fontSize:11, alignItems:"center" }}>
            <span style={{ color:"#475569", fontFamily:"'IBM Plex Mono',monospace", fontSize:10 }}>{new Date(entry.timestamp).toLocaleString()}</span>
            <span style={{ color:"#64748b" }}>{getUser(entry.userId)}</span>
            <span style={{ color:actionColors[entry.action] || "#94a3b8", fontSize:10 }}>{entry.action}</span>
            <span style={{ color:"#475569", fontSize:10 }}>{entry.resource === "system" ? "—" : getFile(entry.resource) || entry.resource}</span>
            <span style={{ fontSize:9, padding:"2px 6px", background:entry.success?"rgba(74,222,128,0.1)":"rgba(239,68,68,0.1)", color:entry.success?"#4ade80":"#f87171", border:`1px solid ${entry.success?"rgba(74,222,128,0.3)":"rgba(239,68,68,0.3)"}`, borderRadius:3, textAlign:"center" }}>{entry.success?"OK":"DENIED"}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Users View (Admin Only) ─────────────────────────────────────────────────
function UsersView({ users, files }) {
  return (
    <div>
      <div style={{ fontSize:10, color:"#22d3ee", letterSpacing:"0.15em", marginBottom:16 }}>USER MANAGEMENT</div>
      <div style={{ display:"grid", gridTemplateColumns:"repeat(3, 1fr)", gap:12 }}>
        {users.map(user => {
          const userFiles = files.filter(f => f.ownerId === user.id);
          const accessFiles = files.filter(f => f.permissions[user.id]);
          const roleColors = { admin:["rgba(239,68,68,0.1)","#f87171","rgba(239,68,68,0.3)"], editor:["rgba(34,211,238,0.1)","#22d3ee","rgba(34,211,238,0.3)"], viewer:["rgba(100,116,139,0.1)","#94a3b8","rgba(100,116,139,0.3)"] };
          const c = roleColors[user.role];
          return (
            <div key={user.id} style={{ background:"#060912", border:"1px solid rgba(34,211,238,0.1)", borderRadius:8, padding:16 }}>
              <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
                <div style={{ width:40, height:40, borderRadius:"50%", background:"rgba(34,211,238,0.1)", border:"1px solid rgba(34,211,238,0.3)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:16, fontWeight:600, color:"#22d3ee" }}>
                  {user.username[0].toUpperCase()}
                </div>
                <div>
                  <div style={{ fontSize:13, fontWeight:500, color:"#e2e8f0" }}>{user.username}</div>
                  <span style={{ fontSize:9, padding:"1px 6px", background:c[0], color:c[1], border:`1px solid ${c[2]}`, borderRadius:3 }}>{user.role.toUpperCase()}</span>
                </div>
              </div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8 }}>
                {[["Files Owned", userFiles.length, "#a78bfa"], ["Has Access", accessFiles.length, "#22d3ee"]].map(([label, val, color]) => (
                  <div key={label} style={{ background:"rgba(15,23,42,0.6)", borderRadius:6, padding:"8px 10px", textAlign:"center" }}>
                    <div style={{ fontSize:18, fontWeight:600, color }}>{val}</div>
                    <div style={{ fontSize:9, color:"#475569", marginTop:2 }}>{label}</div>
                  </div>
                ))}
              </div>
              <div style={{ marginTop:12, padding:"6px 10px", background:"rgba(15,23,42,0.4)", borderRadius:6 }}>
                <div style={{ fontSize:9, color:"#475569", marginBottom:4 }}>PBKDF2 SALT</div>
                <div style={{ fontSize:9, color:"#334155", fontFamily:"'IBM Plex Mono',monospace", wordBreak:"break-all" }}>{user.salt}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Upload Modal ─────────────────────────────────────────────────────────────
function UploadModal({ onUpload, onClose }) {
  const [fileName, setFileName] = useState("");
  const [encrypt, setEncrypt] = useState(true);

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ background:"#0f172a", border:"1px solid rgba(34,211,238,0.2)", borderRadius:10, padding:28, width:420, animation:"slideIn 0.2s ease", fontFamily:"'IBM Plex Mono',monospace" }}>
        <div style={{ fontSize:11, color:"#22d3ee", letterSpacing:"0.1em", marginBottom:20 }}>UPLOAD FILE</div>
        <div style={{ border:"2px dashed rgba(34,211,238,0.2)", borderRadius:8, padding:32, textAlign:"center", marginBottom:20, color:"#475569" }}>
          <svg style={{ margin:"0 auto 10px", display:"block" }} width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
          <div style={{ fontSize:11 }}>Drop files here or</div>
          <div style={{ fontSize:10, color:"#22d3ee", marginTop:4 }}>click to browse</div>
        </div>
        <div style={{ marginBottom:14 }}>
          <label style={{ display:"block", fontSize:9, color:"#475569", letterSpacing:"0.1em", marginBottom:6 }}>FILE NAME (demo)</label>
          <input value={fileName} onChange={e => setFileName(e.target.value)} placeholder="e.g. report_2025.pdf" style={{ background:"#0f172a", border:"1px solid rgba(34,211,238,0.3)", color:"#e2e8f0", padding:"8px 12px", borderRadius:6, fontFamily:"'IBM Plex Mono',monospace", fontSize:12, width:"100%", outline:"none" }} />
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:20, padding:"10px 14px", background:"rgba(34,211,238,0.05)", borderRadius:6, cursor:"pointer" }} onClick={() => setEncrypt(!encrypt)}>
          <div style={{ width:36, height:20, borderRadius:10, background:encrypt?"#22d3ee":"#1e293b", transition:"background 0.2s", position:"relative", flexShrink:0 }}>
            <div style={{ width:14, height:14, borderRadius:"50%", background:"white", position:"absolute", top:3, left:encrypt?18:3, transition:"left 0.2s" }}></div>
          </div>
          <div>
            <div style={{ fontSize:11, color:"#e2e8f0" }}>Encrypt with AES-256-GCM</div>
            <div style={{ fontSize:9, color:"#475569" }}>Recommended for sensitive files</div>
          </div>
        </div>
        <div style={{ display:"flex", gap:10, justifyContent:"flex-end" }}>
          <button className="btn-ghost" onClick={onClose}>CANCEL</button>
          <button className="btn-primary" onClick={() => fileName && onUpload(fileName, encrypt)} style={{ opacity:fileName?1:0.5 }}>UPLOAD{encrypt?" (ENCRYPTED)":""}</button>
        </div>
      </div>
    </div>
  );
}

// ─── Share Modal ──────────────────────────────────────────────────────────────
function ShareModal({ file, users, session, files, setFiles, onClose, showToast, addAudit }) {
  const [perms, setPerms] = useState({ ...file.permissions });

  const save = () => {
    setFiles(prev => prev.map(f => f.id === file.id ? { ...f, permissions: perms } : f));
    addAudit(session.id, "FILE_SHARE", file.id, true);
    showToast("Permissions updated");
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ background:"#0f172a", border:"1px solid rgba(34,211,238,0.2)", borderRadius:10, padding:28, width:420, animation:"slideIn 0.2s ease", fontFamily:"'IBM Plex Mono',monospace" }}>
        <div style={{ fontSize:11, color:"#22d3ee", letterSpacing:"0.1em", marginBottom:20 }}>MANAGE ACCESS — {file.name}</div>
        {users.map(u => (
          <div key={u.id} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"10px 0", borderBottom:"1px solid rgba(34,211,238,0.06)" }}>
            <div style={{ display:"flex", alignItems:"center", gap:8 }}>
              <div style={{ width:28, height:28, borderRadius:"50%", background:"rgba(34,211,238,0.1)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:11, color:"#22d3ee" }}>{u.username[0].toUpperCase()}</div>
              <span style={{ fontSize:12, color:"#cbd5e1" }}>{u.username}</span>
            </div>
            <select value={perms[u.id] || "none"} onChange={e => setPerms(prev => e.target.value === "none" ? Object.fromEntries(Object.entries(prev).filter(([k]) => k !== u.id)) : { ...prev, [u.id]: e.target.value })}
              disabled={u.id === file.ownerId} style={{ width:120, background:"#0a0e1a", border:"1px solid rgba(34,211,238,0.2)", color:"#94a3b8", padding:"4px 8px", borderRadius:4, fontFamily:"'IBM Plex Mono',monospace", fontSize:11 }}>
              <option value="none">No Access</option>
              <option value="view">View</option>
              <option value="edit">Edit</option>
              <option value="owner">Owner</option>
            </select>
          </div>
        ))}
        <div style={{ display:"flex", gap:10, justifyContent:"flex-end", marginTop:20 }}>
          <button className="btn-ghost" onClick={onClose}>CANCEL</button>
          <button className="btn-primary" onClick={save}>SAVE PERMISSIONS</button>
        </div>
      </div>
    </div>
  );
}
