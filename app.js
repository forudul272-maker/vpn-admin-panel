import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js";
import { getAuth, onAuthStateChanged, signInWithEmailAndPassword, signOut } from "https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js";
import {
  collection,
  doc,
  getDoc,
  getDocs,
  getFirestore,
  increment,
  orderBy,
  query,
  runTransaction,
  serverTimestamp,
  setDoc
} from "https://www.gstatic.com/firebasejs/10.12.5/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyA53ff_1_jHgJnv8mpOrV60-YAkYEziGNw",
  authDomain: "my-vpn-admin.firebaseapp.com",
  projectId: "my-vpn-admin",
  storageBucket: "my-vpn-admin.firebasestorage.app",
  messagingSenderId: "905648048611",
  appId: "1:905648048611:web:801236a9cc830c1914f8d6",
  measurementId: "G-RXJC2MMF43"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

const configRef = doc(db, "app_config", "main");
const serversCol = collection(db, "servers_v3");
const profilesCol = collection(db, "profiles_v3");

const state = {
  servers: [],
  profiles: [],
  config: { config_version: 0, app_notice: "", force_update: false, minimum_app_version: "" }
};

const $ = (id) => document.getElementById(id);
const els = {
  loginView: $("loginView"),
  appView: $("appView"),
  loginForm: $("loginForm"),
  loginBtn: $("loginBtn"),
  logoutBtn: $("logoutBtn"),
  refreshBtn: $("refreshBtn"),
  userEmail: $("userEmail"),
  title: $("title"),
  serverList: $("serverList"),
  profileList: $("profileList"),
  toast: $("toast")
};

function toast(msg, err = false) {
  els.toast.textContent = msg;
  els.toast.className = `toast show${err ? " err" : ""}`;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => { els.toast.className = "toast"; }, 3200);
}
function setBtn(btn, loading, text = "Loading...") {
  if (!btn) return;
  if (loading) { btn.dataset.t = btn.textContent; btn.textContent = text; btn.disabled = true; }
  else { btn.textContent = btn.dataset.t || btn.textContent; btn.disabled = false; }
}
const n = (v) => Number.isFinite(Number(v)) ? Number(v) : 0;
const b = (v) => String(v) === "true" || v === true;
const esc = (v) => String(v ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");
const safeId = (v) => String(v || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
const mask = (v) => {
  const s = String(v || "");
  if (!s) return "empty";
  if (s.length <= 8) return `${s.slice(0, 2)}...`;
  return `${s.slice(0, 4)}...${s.slice(-3)}`;
};

function normalizeProtocol(raw) {
  const v = String(raw || "").trim();
  const map = {
    "vmess": "V2Ray VMess",
    "vless": "V2Ray VLESS",
    "v2ray vmess": "V2Ray VMess",
    "v2ray vless": "V2Ray VLESS",
    "ssh": "SSH",
    "ovpn": "OVPN",
    "openvpn": "OpenVPN",
    "trojan": "Trojan",
    "shadowsocks": "Shadowsocks",
    "ss": "Shadowsocks"
  };
  const key = v.toLowerCase().replace(/[-_/]+/g, " ").replace(/\s+/g, " ");
  return map[key] || v;
}
function isV2Ray(protocol) { return protocol === "V2Ray VMess" || protocol === "V2Ray VLESS"; }
function normalizeNetwork(net) {
  const x = String(net || "").trim().toLowerCase();
  if (x === "websocket") return "ws";
  if (x === "http-upgrade" || x === "httpupgrade" || x === "http") return "httpupgrade";
  if (x === "tcp" || x === "ws" || x === "grpc") return x;
  return x || "tcp";
}
function normalizePath(net, path) {
  const p = String(path || "").trim();
  if (net !== "ws" && net !== "httpupgrade") return p;
  if (!p) return "/";
  return p.startsWith("/") ? p : `/${p}`;
}
function looksLikeSshWs(payload) {
  const x = String(payload || "").toLowerCase();
  return x.includes("upgrade: websocket") || x.includes("connection: upgrade") || x.includes("get / http/1.1");
}

const SSH_MODE_LABELS = {
  ssh_ssl: "SSH - SSL",
  ssh_payload: "SSH - Payload",
  ssh_proxy_payload: "SSH Proxy - Payload"
};
const V2RAY_PROTOCOL_LABELS = {
  vless: "V2Ray VLESS",
  vmess: "V2Ray VMess",
  trojan: "Trojan"
};
const COUNTRY_CODES = "AF AX AL DZ AS AD AO AI AQ AG AR AM AW AU AT AZ BS BH BD BB BY BE BZ BJ BM BT BO BQ BA BW BV BR IO BN BG BF BI CV KH CM CA KY CF TD CL CN CX CC CO KM CG CD CK CR CI HR CU CW CY CZ DK DJ DM DO EC EG SV GQ ER EE SZ ET FK FO FJ FI FR GF PF TF GA GM GE DE GH GI GR GL GD GP GU GT GG GN GW GY HT HM VA HN HK HU IS IN ID IR IQ IE IM IL IT JM JP JE JO KZ KE KI KP KR KW KG LA LV LB LS LR LY LI LT LU MO MG MW MY MV ML MT MH MQ MR MU YT MX FM MD MC MN ME MS MA MZ MM NA NR NP NL NC NZ NI NE NG NU NF MK MP NO OM PK PW PS PA PG PY PE PH PN PL PT PR QA RE RO RU RW BL SH KN LC MF PM VC WS SM ST SA SN RS SC SL SG SX SK SI SB SO ZA GS SS ES LK SD SR SJ SE CH SY TW TJ TZ TH TL TG TK TO TT TN TR TM TC TV UG UA AE GB US UM UY UZ VU VE VN VG VI WF EH YE ZM ZW XK".split(" ");
const COUNTRY_NAME_OVERRIDES = {
  XK: "Kosovo"
};
const regionNames = typeof Intl !== "undefined" && Intl.DisplayNames
  ? new Intl.DisplayNames(["en"], { type: "region" })
  : null;
const PROFILE_ICON_GROUPS = [
  {
    label: "SIM / Carrier",
    options: [
      ["ryze", "Ryze SIM"],
      ["grameenphone", "Grameenphone"],
      ["robi", "Robi"],
      ["airtel", "Airtel"],
      ["banglalink", "Banglalink"],
      ["teletalk", "Teletalk"],
      ["skitto", "Skitto"]
    ]
  },
  {
    label: "Social Media",
    options: [
      ["youtube", "YouTube"],
      ["facebook", "Facebook"],
      ["messenger", "Messenger"],
      ["whatsapp", "WhatsApp"],
      ["instagram", "Instagram"],
      ["tiktok", "TikTok"],
      ["telegram", "Telegram"],
      ["imo", "IMO"],
      ["twitter", "X / Twitter"],
      ["linkedin", "LinkedIn"],
      ["snapchat", "Snapchat"],
      ["discord", "Discord"],
      ["reddit", "Reddit"],
      ["pinterest", "Pinterest"],
      ["viber", "Viber"],
      ["signal", "Signal"],
      ["skype", "Skype"],
      ["wechat", "WeChat"],
      ["line", "Line"]
    ]
  }
];

function isV2RayFamily(protocol) { return isV2Ray(protocol) || protocol === "Trojan"; }
function startsWithV2rayLink(v) {
  const x = String(v || "").trim().toLowerCase();
  return x.startsWith("vless://") || x.startsWith("vmess://") || x.startsWith("trojan://");
}
function putShareFields(d, share) {
  d.payload = share;
  d.config = share;
  d.link = share;
  d.url = share;
  d.shareLink = share;
  d.v2rayLink = share;
}
function safeDecode(v) {
  try { return decodeURIComponent(String(v || "")); }
  catch { return String(v || ""); }
}
function boolParam(v) {
  const x = String(v ?? "").trim().toLowerCase();
  return x === "1" || x === "true" || x === "yes" || x === "on";
}
function decodeBase64Utf8(raw) {
  const clean = String(raw || "").trim().replace(/-/g, "+").replace(/_/g, "/");
  const padded = clean + "=".repeat((4 - (clean.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
function parseV2rayLink(link) {
  const raw = String(link || "").trim();
  const lower = raw.toLowerCase();
  if (!raw) throw new Error("Import config required.");

  if (lower.startsWith("vmess://")) {
    let cfg;
    try {
      cfg = JSON.parse(decodeBase64Utf8(raw.slice("vmess://".length)));
    } catch {
      throw new Error("Invalid vmess:// config.");
    }
    const net = normalizeNetwork(cfg.net || "tcp");
    const tls = String(cfg.tls || "").toLowerCase() === "tls" || boolParam(cfg.tls);
    const parsed = {
      protocol: "V2Ray VMess",
      server_name: String(cfg.ps || "").trim(),
      host: String(cfg.add || "").trim(),
      port: n(cfg.port),
      uuid: String(cfg.id || "").trim(),
      alter_id: n(cfg.aid),
      security: String(cfg.scy || cfg.type || "").trim(),
      network_type: net,
      path: normalizePath(net, cfg.path || ""),
      host_header: String(cfg.host || "").trim(),
      tls,
      allow_insecure: boolParam(cfg.allowInsecure),
      sni: String(cfg.sni || cfg.host || "").trim(),
      flow: "",
      public_key: "",
      short_id: "",
      spider_x: "",
      trojan_password: ""
    };
    putShareFields(parsed, raw);
    return parsed;
  }

  if (lower.startsWith("vless://") || lower.startsWith("trojan://")) {
    let u;
    try { u = new URL(raw); }
    catch { throw new Error("Invalid V2Ray import link."); }
    const isTrojan = lower.startsWith("trojan://");
    const net = normalizeNetwork(u.searchParams.get("type") || u.searchParams.get("network") || u.searchParams.get("net") || "tcp");
    const security = u.searchParams.get("security") || u.searchParams.get("encryption") || "";
    const tls = ["tls", "reality"].includes(security.toLowerCase()) || boolParam(u.searchParams.get("tls"));
    const hostHeader = u.searchParams.get("host") || u.searchParams.get("authority") || "";
    const parsed = {
      protocol: isTrojan ? "Trojan" : "V2Ray VLESS",
      server_name: safeDecode(u.hash.replace(/^#/, "")).trim(),
      host: u.hostname,
      port: n(u.port),
      uuid: isTrojan ? "" : safeDecode(u.username).trim(),
      trojan_password: isTrojan ? safeDecode(u.username).trim() : "",
      alter_id: 0,
      security,
      network_type: net,
      path: normalizePath(net, u.searchParams.get("path") || u.searchParams.get("serviceName") || ""),
      host_header: hostHeader,
      tls,
      allow_insecure: boolParam(u.searchParams.get("allowInsecure") || u.searchParams.get("allow_insecure")),
      sni: u.searchParams.get("sni") || u.searchParams.get("serverName") || u.searchParams.get("peer") || hostHeader || "",
      flow: u.searchParams.get("flow") || "",
      public_key: u.searchParams.get("pbk") || u.searchParams.get("publicKey") || "",
      short_id: u.searchParams.get("sid") || u.searchParams.get("shortId") || "",
      spider_x: u.searchParams.get("spx") || u.searchParams.get("spiderX") || ""
    };
    putShareFields(parsed, raw);
    return parsed;
  }

  throw new Error("Only vless://, vmess://, or trojan:// import supported.");
}
function v2rayValueFromProtocol(protocol) {
  const proto = normalizeProtocol(protocol);
  if (proto === "V2Ray VMess") return "vmess";
  if (proto === "Trojan") return "trojan";
  return "vless";
}
function sshModeFromLabel(value) {
  const x = String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
  if (x.includes("proxy")) return "ssh_proxy_payload";
  if (x.includes("payload")) return "ssh_payload";
  return "ssh_ssl";
}
function serverLogo(s) {
  return s.logo || s.server_logo || s.logo_url || "";
}
function flagEmojiForCode(value) {
  const code = String(value || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return "";
  return Array.from(code).map((ch) => String.fromCodePoint(127397 + ch.charCodeAt(0))).join("");
}
function countryCodeFromEmoji(value) {
  const chars = Array.from(String(value || "").trim());
  if (chars.length !== 2) return "";
  const code = chars.map((ch) => {
    const offset = ch.codePointAt(0) - 0x1F1E6;
    return offset >= 0 && offset <= 25 ? String.fromCharCode(65 + offset) : "";
  }).join("");
  return /^[A-Z]{2}$/.test(code) ? code : "";
}
function normalizeCountryCode(value) {
  const raw = String(value || "").trim().toUpperCase();
  if (/^[A-Z]{2}$/.test(raw)) return raw;
  return countryCodeFromEmoji(value);
}
function countryNameForCode(value) {
  const code = normalizeCountryCode(value);
  if (!code) return "";
  if (COUNTRY_NAME_OVERRIDES[code]) return COUNTRY_NAME_OVERRIDES[code];
  try { return regionNames?.of(code) || code; }
  catch { return code; }
}
function normalizeCountryName(value) {
  return String(value || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, " ");
}
function countryCodeFromName(value) {
  const wanted = normalizeCountryName(value);
  if (!wanted) return "";
  return COUNTRY_CODES.find((code) => normalizeCountryName(countryNameForCode(code)) === wanted) || "";
}
function populateServerFlagSelect() {
  const select = $("serverFlag");
  const selected = select.value;
  const countries = COUNTRY_CODES
    .map((code) => ({ code, name: countryNameForCode(code), flag: flagEmojiForCode(code) }))
    .sort((a, b) => a.name.localeCompare(b.name));
  select.innerHTML = '<option value="">Select country flag</option>';
  countries.forEach(({ code, name, flag }) => {
    const opt = document.createElement("option");
    opt.value = code;
    opt.dataset.country = name;
    opt.textContent = `${flag} ${name}`;
    select.appendChild(opt);
  });
  if (selected) setServerFlagValue(selected);
}
function setServerFlagValue(value, countryFallback = "") {
  const select = $("serverFlag");
  const code = normalizeCountryCode(value) || countryCodeFromName(countryFallback || value);
  if (code && [...select.options].some((opt) => opt.value === code)) {
    select.value = code;
  } else {
    select.value = "";
  }
}
function selectedServerFlag() {
  const select = $("serverFlag");
  const code = normalizeCountryCode(select.value);
  const option = select.selectedOptions[0];
  return {
    code,
    country: option?.dataset.country || countryNameForCode(code),
    flag: flagEmojiForCode(code)
  };
}
function populateProfileIconSelect() {
  const select = $("profileIcon");
  const selected = select.value;
  select.innerHTML = '<option value="">Auto / No icon</option>';
  PROFILE_ICON_GROUPS.forEach((group) => {
    const optGroup = document.createElement("optgroup");
    optGroup.label = group.label;
    group.options.forEach(([value, label]) => {
      const opt = document.createElement("option");
      opt.value = value;
      opt.textContent = label;
      optGroup.appendChild(opt);
    });
    select.appendChild(optGroup);
  });
  if (selected) setProfileIconValue(selected);
}
function profileIconLabel(value) {
  const found = PROFILE_ICON_GROUPS.flatMap((group) => group.options).find(([key]) => key === value);
  return found ? found[1] : value;
}
function setProfileIconValue(value) {
  const select = $("profileIcon");
  const clean = String(value || "").trim();
  if (!clean) {
    select.value = "";
    return;
  }
  if (![...select.options].some((opt) => opt.value === clean)) {
    const opt = document.createElement("option");
    opt.value = clean;
    opt.textContent = `Current custom: ${clean}`;
    select.appendChild(opt);
  }
  select.value = clean;
}
function detectServerKind(s) {
  const proto = normalizeProtocol(s.protocol || "");
  const share = s.payload || s.shareLink || s.link || s.url || s.v2rayLink || "";
  if (s.server_type === "ssh" || proto === "SSH") return "ssh";
  if (s.server_type === "v2ray" || isV2RayFamily(proto) || startsWithV2rayLink(share)) return "v2ray";
  return "other";
}
function setSelectValue(id, value) {
  const el = $(id);
  const wanted = String(value || "");
  if (!wanted) return;
  const exists = [...el.options].some((opt) => opt.value === wanted || opt.textContent === wanted);
  if (!exists) {
    const opt = document.createElement("option");
    opt.value = wanted;
    opt.textContent = wanted;
    el.appendChild(opt);
  }
  el.value = wanted;
}
function applyImportedV2rayToForm(parsed) {
  $("serverV2rayProtocol").value = v2rayValueFromProtocol(parsed.protocol);
  if (!$("serverName").value.trim() && parsed.server_name) $("serverName").value = parsed.server_name;
  $("serverHost").value = parsed.host || "";
  $("serverPort").value = parsed.port || "";
  $("serverUuid").value = parsed.uuid || "";
  $("serverTrojanPassword").value = parsed.trojan_password || "";
  $("serverAlterId").value = n(parsed.alter_id);
  $("serverSecurity").value = parsed.security || "";
  $("serverNetworkType").value = parsed.network_type || "";
  $("serverPath").value = parsed.path || "";
  $("serverHostHeader").value = parsed.host_header || "";
  $("serverTls").value = String(!!parsed.tls);
  $("serverAllowInsecure").value = String(!!parsed.allow_insecure);
  $("serverSni").value = parsed.sni || "";
  $("serverFlow").value = parsed.flow || "";
  $("serverPublicKey").value = parsed.public_key || "";
  $("serverShortId").value = parsed.short_id || "";
  $("serverSpiderX").value = parsed.spider_x || "";
}

async function ensureConfig() {
  const snap = await getDoc(configRef);
  if (snap.exists()) return snap.data();
  const base = { config_version: 0, app_notice: "", force_update: false, minimum_app_version: "", updated_at: serverTimestamp() };
  await setDoc(configRef, base);
  return base;
}

async function bumpVersion(tx) {
  tx.set(configRef, { config_version: increment(1), updated_at: serverTimestamp() }, { merge: true });
}
async function withVersion(writer) {
  await runTransaction(db, async (tx) => {
    await writer(tx);
    await bumpVersion(tx);
  });
  await loadAll();
}

async function loadAll() {
  const [cfg, srvSnap, proSnap] = await Promise.all([
    ensureConfig(),
    getDocs(query(serversCol, orderBy("sort_order", "asc"))),
    getDocs(query(profilesCol, orderBy("sort_order", "asc")))
  ]);
  state.config = {
    config_version: n(cfg.config_version),
    app_notice: cfg.app_notice || "",
    force_update: !!cfg.force_update,
    minimum_app_version: cfg.minimum_app_version || ""
  };
  state.servers = srvSnap.docs.map((d) => ({ id: d.id, ...d.data() }));
  state.profiles = proSnap.docs.map((d) => ({ id: d.id, ...d.data() }));
  renderAll();
}

function renderAll() {
  $("dashVersion").textContent = state.config.config_version;
  $("dashServers").textContent = state.servers.length;
  $("dashProfiles").textContent = state.profiles.length;
  $("dashNotice").textContent = state.config.app_notice || "-";
  $("settingsNotice").value = state.config.app_notice || "";
  $("settingsForceUpdate").value = String(!!state.config.force_update);
  $("settingsMinVersion").value = state.config.minimum_app_version || "";
  $("settingsConfigVersion").value = String(state.config.config_version);

  const profileSelect = $("serverProfile");
  const selected = selectedServerProfileIds();
  profileSelect.innerHTML = state.profiles.length ? "" : '<option value="" disabled>No profiles found</option>';
  state.profiles.forEach((p) => {
    const opt = document.createElement("option");
    opt.value = p.id;
    opt.textContent = p.profile_name || "Unnamed";
    profileSelect.appendChild(opt);
  });
  setServerProfileValue(selected);

  renderLinkOptions();
  renderServerList();
  renderProfileList();
}

function profileLabel(p) {
  return p.profile_name || "Unnamed";
}
function serverLabel(s) {
  const proto = normalizeProtocol(s.protocol || "Server");
  return `${s.server_name || "Unnamed"} (${proto || "Server"})`;
}
function serverLinkedProfileIds(s) {
  const ids = new Set();
  if (s.profile_id) ids.add(s.profile_id);
  if (Array.isArray(s.linkedProfileIds)) {
    s.linkedProfileIds.forEach((id) => { if (id) ids.add(id); });
  }
  if (Array.isArray(s.linked_profile_ids)) {
    s.linked_profile_ids.forEach((id) => { if (id) ids.add(id); });
  }
  if (Array.isArray(s.profile_ids)) {
    s.profile_ids.forEach((id) => { if (id) ids.add(id); });
  }
  return Array.from(ids);
}
function profileLinkedServerIds(p) {
  const ids = new Set();
  if (Array.isArray(p.linkedServerIds)) {
    p.linkedServerIds.forEach((id) => { if (id) ids.add(id); });
  }
  if (Array.isArray(p.linked_server_ids)) {
    p.linked_server_ids.forEach((id) => { if (id) ids.add(id); });
  }
  if (Array.isArray(p.server_ids)) {
    p.server_ids.forEach((id) => { if (id) ids.add(id); });
  }
  return Array.from(ids);
}
function selectedServerProfileIds() {
  const select = $("serverProfile");
  if (!select) return [];
  return Array.from(select.selectedOptions).map((option) => option.value).filter(Boolean);
}
function setServerProfileValue(profileIds) {
  const selected = new Set(profileIds || []);
  Array.from($("serverProfile").options).forEach((option) => {
    option.selected = selected.has(option.value);
  });
}
function primaryProfileFor(profileIds) {
  return profileIds.map((id) => state.profiles.find((p) => p.id === id)).find(Boolean) || null;
}
function serverProfileLinkPatch(profileIds) {
  const linkedProfileIds = Array.from(new Set((profileIds || []).filter(Boolean)));
  const primary = primaryProfileFor(linkedProfileIds);
  return {
    profile_id: primary ? primary.id : "",
    profile_name: primary ? (primary.profile_name || "") : "",
    linkedProfileIds,
    linked_profile_ids: linkedProfileIds,
    profile_ids: linkedProfileIds
  };
}
function syncProfilesForServer(tx, serverId, selectedProfileIds) {
  const selected = new Set(selectedProfileIds || []);
  state.profiles.forEach((profile) => {
    const next = profileLinkedServerIds(profile).filter((id) => id !== serverId);
    if (selected.has(profile.id)) next.push(serverId);
    const linkedServerIds = Array.from(new Set(next));
    tx.set(doc(db, "profiles_v3", profile.id), {
      linkedServerIds,
      linked_server_ids: linkedServerIds,
      server_ids: linkedServerIds,
      updated_at: serverTimestamp()
    }, { merge: true });
  });
}
function renderLinkOptions() {
  const profileSelect = $("linkProfileSelect");
  const serverSelect = $("linkServerSelect");
  if (!profileSelect || !serverSelect) return;
  const selectedProfile = profileSelect.value;
  const selectedServer = serverSelect.value;

  profileSelect.innerHTML = state.profiles.length ? "" : '<option value="">No profiles found</option>';
  state.profiles.forEach((p) => {
    const opt = document.createElement("option");
    opt.value = p.id;
    opt.textContent = profileLabel(p);
    profileSelect.appendChild(opt);
  });
  if (selectedProfile && state.profiles.some((p) => p.id === selectedProfile)) profileSelect.value = selectedProfile;

  serverSelect.innerHTML = state.servers.length ? "" : '<option value="">No servers found</option>';
  state.servers.forEach((s) => {
    const opt = document.createElement("option");
    opt.value = s.id;
    opt.textContent = serverLabel(s);
    serverSelect.appendChild(opt);
  });
  if (selectedServer && state.servers.some((s) => s.id === selectedServer)) serverSelect.value = selectedServer;
  renderLinkPreview();
}
function renderLinkPreview() {
  const profileId = $("linkProfileSelect")?.value || "";
  const preview = $("linkPreview");
  if (!preview) return;
  const linked = state.servers.filter((s) => profileId && serverLinkedProfileIds(s).includes(profileId));
  preview.innerHTML = linked.length ? linked.map((s) => `
    <article class="item">
      <strong>${esc(s.server_name || "Unnamed")}</strong>
      <div class="meta">${esc(normalizeProtocol(s.protocol || "Server"))} | ${esc(s.host || "-")}:${esc(s.port || "-")}</div>
    </article>
  `).join("") : `<div class="item">No linked servers.</div>`;

  const canLink = !!profileId && !!($("linkServerSelect")?.value || "");
  if ($("linkServerBtn")) $("linkServerBtn").disabled = !canLink;
  if ($("unlinkServerBtn")) $("unlinkServerBtn").disabled = !canLink;
}
async function linkSelectedServer() {
  const profile = state.profiles.find((p) => p.id === $("linkProfileSelect").value);
  const server = state.servers.find((s) => s.id === $("linkServerSelect").value);
  if (!profile || !server) throw new Error("Select profile and server.");

  const linkedProfileIds = Array.from(new Set([...serverLinkedProfileIds(server), profile.id]));

  await withVersion(async (tx) => {
    tx.set(doc(db, "servers_v3", server.id), {
      ...serverProfileLinkPatch(linkedProfileIds),
      updated_at: serverTimestamp()
    }, { merge: true });
    syncProfilesForServer(tx, server.id, linkedProfileIds);
  });
}
async function unlinkSelectedServer() {
  const profile = state.profiles.find((p) => p.id === $("linkProfileSelect").value);
  const server = state.servers.find((s) => s.id === $("linkServerSelect").value);
  if (!profile || !server) throw new Error("Select profile and server.");
  if (!serverLinkedProfileIds(server).includes(profile.id)) {
    throw new Error("Selected server is not linked with this profile.");
  }

  const linkedProfileIds = serverLinkedProfileIds(server).filter((id) => id !== profile.id);

  await withVersion(async (tx) => {
    tx.set(doc(db, "servers_v3", server.id), {
      ...serverProfileLinkPatch(linkedProfileIds),
      updated_at: serverTimestamp()
    }, { merge: true });
    syncProfilesForServer(tx, server.id, linkedProfileIds);
  });
}

function serverBase(protocol) {
  const linkedProfileIds = selectedServerProfileIds();
  const profilePatch = serverProfileLinkPatch(linkedProfileIds);
  const selectedFlag = selectedServerFlag();
  const logo = selectedFlag.flag;
  return {
    server_name: $("serverName").value.trim(),
    country: selectedFlag.country,
    flag: selectedFlag.flag,
    flagCode: selectedFlag.code,
    flag_code: selectedFlag.code,
    logo,
    server_logo: logo,
    logo_url: logo,
    server_type: $("serverKind").value,
    ssh_mode: "",
    ssh_type: "",
    v2ray_mode: "",
    v2ray_protocol: "",
    protocol,
    host: $("serverHost").value.trim(),
    port: n($("serverPort").value),
    username: $("serverUsername").value.trim(),
    password: $("serverPassword").value.trim(),
    sni: $("serverSni").value.trim(),
    status: $("serverStatus").value,
    premium: b($("serverPremium").value),
    ...profilePatch,
    sort_order: n($("serverSortOrder").value),
    uuid: $("serverUuid").value.trim(),
    alter_id: n($("serverAlterId").value),
    security: $("serverSecurity").value.trim(),
    network_type: normalizeNetwork($("serverNetworkType").value),
    path: "",
    host_header: $("serverHostHeader").value.trim(),
    tls: b($("serverTls").value),
    allow_insecure: b($("serverAllowInsecure").value),
    flow: $("serverFlow").value.trim(),
    public_key: $("serverPublicKey").value.trim(),
    short_id: $("serverShortId").value.trim(),
    spider_x: $("serverSpiderX").value.trim(),
    trojan_password: $("serverTrojanPassword").value.trim(),
    ss_method: $("serverSsMethod").value.trim(),
    ovpn_config: $("serverOvpnConfig").value.trim(),
    proxy_host: $("serverProxyHost").value.trim(),
    proxy_port: n($("serverProxyPort").value),
    payload: "",
    config: "",
    link: "",
    url: "",
    shareLink: "",
    v2rayLink: "",
    updated_at: serverTimestamp()
  };
}

function validateBaseServer(d) {
  if (!d.server_name || !d.status || $("serverSortOrder").value === "") {
    throw new Error("Server Name, Status, Sort Order required.");
  }
  if (!d.flagCode) throw new Error("Flag country required.");
}
function validateHostPort(d) {
  if (!d.host) throw new Error("Host required.");
  if (d.port < 1 || d.port > 65535) throw new Error("Valid port required (1-65535).");
}
function validateV2rayServer(d) {
  validateHostPort(d);
  if (d.protocol === "V2Ray VMess" || d.protocol === "V2Ray VLESS") {
    if (!d.uuid) throw new Error("UUID required for V2Ray.");
  }
  if (d.protocol === "Trojan" && !d.trojan_password) throw new Error("Trojan password required.");
  if (!d.network_type) d.network_type = "tcp";
  d.path = normalizePath(d.network_type, d.path);
  if (d.tls && !d.sni) d.sni = d.host;
}
function buildSshServerPayload() {
  const mode = $("serverSshMode").value;
  const d = serverBase("SSH");
  const payload = mode === "ssh_ssl" ? "" : $("serverPayload").value.trim();
  d.server_type = "ssh";
  d.ssh_mode = mode;
  d.ssh_type = SSH_MODE_LABELS[mode] || "SSH - SSL";
  d.connection_type = d.ssh_type;
  d.ssh_ssl = mode === "ssh_ssl";
  d.proxy_payload = mode === "ssh_proxy_payload";
  d.tls = mode === "ssh_ssl";
  d.payload = payload;
  d.config = payload;
  validateBaseServer(d);
  validateHostPort(d);
  if (!d.username || !d.password) throw new Error("SSH username/password required.");
  if (mode !== "ssh_ssl" && !payload) throw new Error(`${d.ssh_type} payload required.`);
  if (mode === "ssh_proxy_payload") {
    if (!d.proxy_host) throw new Error("Proxy Host required for SSH Proxy - Payload.");
    if (d.proxy_port < 1 || d.proxy_port > 65535) throw new Error("Valid Proxy Port required (1-65535).");
  }
  return d;
}
function buildCustomV2rayServerPayload() {
  const v2Type = $("serverV2rayProtocol").value;
  const d = serverBase(V2RAY_PROTOCOL_LABELS[v2Type] || "V2Ray VLESS");
  d.server_type = "v2ray";
  d.v2ray_mode = "custom";
  d.v2ray_protocol = v2Type;
  d.path = normalizePath(d.network_type, $("serverPath").value.trim());
  validateBaseServer(d);
  validateV2rayServer(d);
  return d;
}
function buildImportedV2rayServerPayload() {
  const parsed = parseV2rayLink($("serverImportLink").value);
  const d = serverBase(parsed.protocol);
  const typedName = d.server_name;
  Object.assign(d, parsed);
  d.server_name = typedName || parsed.server_name || `${parsed.protocol} ${parsed.host || ""}`.trim();
  d.server_type = "v2ray";
  d.v2ray_mode = "import";
  d.v2ray_protocol = v2rayValueFromProtocol(parsed.protocol);
  validateBaseServer(d);
  validateV2rayServer(d);
  return d;
}
function buildOtherServerPayload() {
  const protocol = normalizeProtocol($("serverProtocol").value);
  const d = serverBase(protocol);
  const share = $("serverPayload").value.trim();
  d.server_type = "other";
  d.path = normalizePath(d.network_type, $("serverPath").value.trim());
  if (share) {
    if (startsWithV2rayLink(share) || share.toLowerCase().startsWith("ss://")) putShareFields(d, share);
    else { d.payload = share; d.config = share; }
  }
  validateBaseServer(d);
  if (protocol !== "OVPN" && protocol !== "OpenVPN") validateHostPort(d);
  if ((protocol === "OVPN" || protocol === "OpenVPN") && !d.host && !d.ovpn_config) {
    throw new Error("OpenVPN needs Host or OVPN Config.");
  }
  if (protocol === "Shadowsocks" && (!d.ss_method || !d.password)) throw new Error("Shadowsocks method/password required.");
  return d;
}
function buildServerPayload() {
  const kind = $("serverKind").value;
  if (kind === "ssh") return buildSshServerPayload();
  if (kind === "v2ray") {
    return $("serverV2rayMode").value === "import" ? buildImportedV2rayServerPayload() : buildCustomV2rayServerPayload();
  }
  return buildOtherServerPayload();
}

function resetServerForm() {
  $("serverForm").reset();
  $("serverDocId").value = "";
  $("serverCustomId").disabled = false;
  setServerProfileValue([]);
  $("serverSortOrder").value = 0;
  $("serverFlag").value = "";
  $("serverAlterId").value = 0;
  $("serverKind").value = "ssh";
  $("serverSshMode").value = "ssh_ssl";
  $("serverV2rayMode").value = "custom";
  $("serverV2rayProtocol").value = "vless";
  $("serverProtocol").value = "OVPN";
  $("serverTls").value = "false";
  $("serverAllowInsecure").value = "false";
  $("serverFormTitle").textContent = "Add Server";
  updateServerFormMode();
}

function fillServerForm(s) {
  const proto = normalizeProtocol(s.protocol || "SSH");
  const kind = detectServerKind(s);
  const share = s.payload || s.shareLink || s.link || s.url || s.v2rayLink || "";
  $("serverDocId").value = s.id || "";
  $("serverCustomId").value = s.id || "";
  $("serverCustomId").disabled = true;
  $("serverName").value = s.server_name || "";
  setServerFlagValue(s.flagCode || s.flag_code || s.flag || serverLogo(s), s.country || "");
  $("serverKind").value = kind;
  $("serverStatus").value = s.status || "active";
  $("serverPremium").value = String(!!s.premium);
  $("serverSortOrder").value = n(s.sort_order);
  setServerProfileValue(serverLinkedProfileIds(s));
  $("serverHost").value = s.host || "";
  $("serverPort").value = s.port || "";
  $("serverUsername").value = s.username || "";
  $("serverPassword").value = s.password || "";
  $("serverSni").value = s.sni || "";
  $("serverProxyHost").value = s.proxy_host || "";
  $("serverProxyPort").value = s.proxy_port || "";
  $("serverUuid").value = s.uuid || "";
  $("serverAlterId").value = n(s.alter_id);
  $("serverSecurity").value = s.security || "";
  $("serverNetworkType").value = s.network_type || "";
  $("serverPath").value = s.path || "";
  $("serverHostHeader").value = s.host_header || "";
  $("serverTls").value = String(!!s.tls);
  $("serverAllowInsecure").value = String(!!s.allow_insecure);
  $("serverFlow").value = s.flow || "";
  $("serverPublicKey").value = s.public_key || "";
  $("serverShortId").value = s.short_id || "";
  $("serverSpiderX").value = s.spider_x || "";
  $("serverTrojanPassword").value = s.trojan_password || "";
  $("serverSsMethod").value = s.ss_method || "";
  $("serverOvpnConfig").value = s.ovpn_config || "";
  $("serverPayload").value = kind === "ssh" || kind === "other" ? share : "";
  $("serverImportLink").value = kind === "v2ray" ? share : "";
  if (kind === "ssh") $("serverSshMode").value = s.ssh_mode || sshModeFromLabel(s.ssh_type || (share ? "payload" : ""));
  if (kind === "v2ray") {
    $("serverV2rayMode").value = s.v2ray_mode === "import" || startsWithV2rayLink(share) ? "import" : "custom";
    $("serverV2rayProtocol").value = v2rayValueFromProtocol(proto);
  }
  if (kind === "other") setSelectValue("serverProtocol", proto);
  $("serverFormTitle").textContent = "Edit Server";
  updateServerFormMode();
  showScreen("servers");
}

function logoHtml(s) {
  const raw = serverLogo(s) || s.flag || "";
  const text = Array.from(String(raw || s.server_name || "?").trim()).slice(0, 3).join("").toUpperCase();
  if (/^(https?:\/\/|data:image\/)/i.test(raw)) {
    return `<span class="logo-mark"><img src="${esc(raw)}" alt=""></span>`;
  }
  return `<span class="logo-mark">${esc(text || "?")}</span>`;
}
function serverModeLabel(s, proto) {
  if (proto === "SSH") return s.ssh_type || SSH_MODE_LABELS[sshModeFromLabel(s.ssh_mode)] || "SSH";
  if (isV2RayFamily(proto)) return s.v2ray_mode === "import" ? "Imported V2Ray" : "Custom V2Ray";
  return s.server_type === "other" ? "Legacy" : "Server";
}
function serverCard(s) {
  const active = s.status === "active";
  const proto = normalizeProtocol(s.protocol || "");
  const secret = isV2Ray(proto) ? `UUID ${mask(s.uuid)}` : (proto === "Trojan" ? `Pass ${mask(s.trojan_password)}` : (proto === "SSH" ? `User ${esc(s.username || "-")}` : "-"));
  const linkedNames = serverLinkedProfileIds(s)
    .map((id) => state.profiles.find((p) => p.id === id))
    .filter(Boolean)
    .map(profileLabel);
  const profileBadge = linkedNames.length ? `Profiles: ${linkedNames.join(", ")}` : "Profiles: none";
  return `<article class="item">
    <div class="item-head">
      ${logoHtml(s)}
      <div>
        <strong>${esc(s.server_name || "Unnamed")}</strong>
        <div class="meta">${esc(proto)} | ${esc(s.host || "-")}:${esc(s.port || "-")}</div>
      </div>
    </div>
    <div class="badges">
      <span class="badge ${active ? "ok" : "off"}">${esc(s.status || "inactive")}</span>
      <span class="badge">${s.premium ? "Premium" : "Free"}</span>
      <span class="badge">Sort ${n(s.sort_order)}</span>
      <span class="badge">${esc(serverModeLabel(s, proto))}</span>
      <span class="badge">${esc(secret)}</span>
      <span class="badge">${esc(profileBadge)}</span>
    </div>
    <div class="actions">
      <button type="button" data-act="edit" data-id="${esc(s.id)}">Edit</button>
      <button type="button" data-act="dup" data-id="${esc(s.id)}">Duplicate</button>
      <button type="button" data-act="toggle" data-id="${esc(s.id)}">${active ? "Disable" : "Enable"}</button>
      <button type="button" class="danger" data-act="del" data-id="${esc(s.id)}">Delete</button>
    </div>
  </article>`;
}
function renderServerList() {
  const q = $("serverSearch").value.trim().toLowerCase();
  const rows = state.servers.filter((s) =>
    `${s.server_name || ""} ${s.country || ""} ${s.host || ""} ${s.protocol || ""} ${serverLogo(s)} ${s.ssh_type || ""}`.toLowerCase().includes(q)
  );
  els.serverList.innerHTML = rows.length ? rows.map(serverCard).join("") : `<div class="item">No servers found.</div>`;
}

function profilePayload() {
  const icon = $("profileIcon").value.trim();
  const data = {
    profile_name: $("profileName").value.trim(),
    icon,
    profileIcon: icon,
    profile_icon: icon,
    status: $("profileStatus").value,
    sort_order: n($("profileSortOrder").value),
    updated_at: serverTimestamp()
  };
  if (!data.profile_name) throw new Error("Profile Name required.");
  if ($("profileSortOrder").value === "") throw new Error("Profile Sort Order required.");
  return data;
}
function resetProfileForm() {
  $("profileForm").reset();
  $("profileDocId").value = "";
  $("profileCustomId").disabled = false;
  $("profileIcon").value = "";
  $("profileSortOrder").value = 0;
  $("profileFormTitle").textContent = "Add Profile";
}
function fillProfileForm(p) {
  $("profileDocId").value = p.id;
  $("profileCustomId").value = p.id;
  $("profileCustomId").disabled = true;
  $("profileName").value = p.profile_name || "";
  setProfileIconValue(p.icon || p.profileIcon || p.profile_icon || "");
  $("profileStatus").value = p.status || "active";
  $("profileSortOrder").value = n(p.sort_order);
  $("profileFormTitle").textContent = "Edit Profile";
  showScreen("profiles");
  showProfileView("add");
}
function renderProfileList() {
  const q = $("profileSearch").value.trim().toLowerCase();
  const rows = state.profiles.filter((p) =>
    `${p.profile_name || ""} ${p.icon || ""} ${p.profileIcon || ""} ${p.profile_icon || ""}`.toLowerCase().includes(q)
  );
  els.profileList.innerHTML = rows.length ? rows.map((p) => `
    <article class="item">
      <strong>${esc(p.profile_name || "Unnamed")}</strong>
      <div class="badges">
        <span class="badge">${esc(profileIconLabel(p.icon || p.profileIcon || p.profile_icon || "Auto"))}</span>
        <span class="badge ${p.status === "active" ? "ok" : "off"}">${esc(p.status || "inactive")}</span>
        <span class="badge">Sort ${n(p.sort_order)}</span>
      </div>
      <div class="actions">
        <button type="button" data-pact="edit" data-id="${esc(p.id)}">Edit</button>
        <button type="button" data-pact="link" data-id="${esc(p.id)}">Link Server</button>
        <button type="button" data-pact="toggle" data-id="${esc(p.id)}">${p.status === "active" ? "Disable" : "Enable"}</button>
        <button type="button" class="danger" data-pact="del" data-id="${esc(p.id)}">Delete</button>
      </div>
    </article>
  `).join("") : `<div class="item">No profiles found.</div>`;
}

function showScreen(id) {
  document.querySelectorAll(".screen").forEach((x) => x.classList.toggle("show", x.id === id));
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x.dataset.screen === id));
  els.appView.classList.toggle("home-mode", id === "home");
  const titles = {
    home: "Home",
    dashboard: "Dashboard",
    servers: "Add Server",
    profiles: "Profiles",
    settings: "Settings"
  };
  $("title").textContent = titles[id] || id.charAt(0).toUpperCase() + id.slice(1);
}
function showProfileView(view) {
  document.querySelectorAll(".profile-panel").forEach((x) => x.classList.toggle("show", x.dataset.profilePanel === view));
  document.querySelectorAll(".profile-tool").forEach((x) => x.classList.toggle("active", x.dataset.profileView === view));
  if (view === "link") renderLinkPreview();
}
function openHomeTarget(target, mode) {
  if (target === "profiles") {
    if (mode === "addProfile") resetProfileForm();
    showScreen("profiles");
    showProfileView(mode === "linkServer" ? "link" : "add");
    return;
  }
  if (target === "servers") {
    if (mode === "addServer") resetServerForm();
    showScreen("servers");
  }
}

const CONNECTION_WRAPS = [
  "serverHostWrap",
  "serverPortWrap",
  "serverUsernameWrap",
  "serverPasswordWrap",
  "serverSniWrap",
  "serverProxyHostWrap",
  "serverProxyPortWrap",
  "serverUuidWrap",
  "serverTrojanPasswordWrap",
  "serverAlterIdWrap",
  "serverSecurityWrap",
  "serverNetworkTypeWrap",
  "serverPathWrap",
  "serverHostHeaderWrap",
  "serverTlsWrap",
  "serverAllowInsecureWrap",
  "serverFlowWrap",
  "serverPublicKeyWrap",
  "serverShortIdWrap",
  "serverSpiderXWrap",
  "serverSsMethodWrap",
  "serverOvpnConfigWrap",
  "serverPayloadWrap"
];
function setVisible(id, visible) {
  const el = $(id);
  if (el) el.classList.toggle("hidden", !visible);
}
function updateServerFormMode() {
  const kind = $("serverKind").value;
  const isSsh = kind === "ssh";
  const isV2ray = kind === "v2ray";
  const isOther = kind === "other";
  const sshMode = $("serverSshMode").value;
  const v2Mode = $("serverV2rayMode").value;
  const v2Type = $("serverV2rayProtocol").value;
  const otherProtocol = normalizeProtocol($("serverProtocol").value);
  const customV2 = isV2ray && v2Mode === "custom";
  const importV2 = isV2ray && v2Mode === "import";

  setVisible("sshChooser", isSsh);
  setVisible("v2rayChooser", isV2ray);
  setVisible("otherChooser", isOther);
  setVisible("v2rayCustomBox", customV2);
  setVisible("v2rayImportBox", importV2);
  setVisible("v2rayImportActions", importV2);

  const visible = {
    serverHostWrap: isSsh || customV2 || isOther,
    serverPortWrap: isSsh || customV2 || isOther,
    serverUsernameWrap: isSsh || isOther,
    serverPasswordWrap: isSsh || isOther,
    serverSniWrap: isSsh || customV2 || isOther,
    serverProxyHostWrap: isSsh && sshMode === "ssh_proxy_payload",
    serverProxyPortWrap: isSsh && sshMode === "ssh_proxy_payload",
    serverUuidWrap: customV2 && v2Type !== "trojan",
    serverTrojanPasswordWrap: customV2 && v2Type === "trojan",
    serverAlterIdWrap: customV2 && v2Type === "vmess",
    serverSecurityWrap: customV2,
    serverNetworkTypeWrap: customV2,
    serverPathWrap: customV2,
    serverHostHeaderWrap: customV2,
    serverTlsWrap: customV2,
    serverAllowInsecureWrap: customV2,
    serverFlowWrap: customV2 && v2Type === "vless",
    serverPublicKeyWrap: customV2 && v2Type === "vless",
    serverShortIdWrap: customV2 && v2Type === "vless",
    serverSpiderXWrap: customV2 && v2Type === "vless",
    serverSsMethodWrap: isOther && otherProtocol === "Shadowsocks",
    serverOvpnConfigWrap: isOther && (otherProtocol === "OVPN" || otherProtocol === "OpenVPN"),
    serverPayloadWrap: (isSsh && sshMode !== "ssh_ssl") || isOther
  };
  CONNECTION_WRAPS.forEach((id) => setVisible(id, !!visible[id]));
  setVisible("connectionFields", Object.values(visible).some(Boolean));

  if (isSsh) {
    $("connectionHint").textContent = sshMode === "ssh_ssl" ? "Host, port, username, password, and optional SNI." : "Payload mode saves payload with the SSH server.";
    $("serverPayloadLabel").textContent = sshMode === "ssh_proxy_payload" ? "Proxy Payload" : "SSH Payload";
    $("serverPayload").placeholder = "HTTP payload / custom payload";
  } else if (customV2) {
    $("connectionHint").textContent = `Custom ${V2RAY_PROTOCOL_LABELS[v2Type] || "V2Ray"} fields.`;
  } else if (importV2) {
    $("connectionHint").textContent = "Paste a V2Ray share link and save.";
  } else {
    $("connectionHint").textContent = "Legacy server fields.";
    $("serverPayloadLabel").textContent = "Payload / Share Link";
    $("serverPayload").placeholder = "ss:// or legacy payload/config";
  }
}

els.loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  setBtn(els.loginBtn, true, "Logging in...");
  try {
    await signInWithEmailAndPassword(auth, $("loginEmail").value.trim(), $("loginPassword").value);
  } catch (err) {
    toast(err.message || "Login failed", true);
  } finally { setBtn(els.loginBtn, false); }
});
els.logoutBtn.addEventListener("click", async () => { await signOut(auth); });
els.refreshBtn.addEventListener("click", async () => { await loadAll(); toast("Refreshed."); });
["serverKind", "serverSshMode", "serverV2rayMode", "serverV2rayProtocol", "serverProtocol"].forEach((id) => {
  $(id).addEventListener("change", updateServerFormMode);
});
$("importV2rayBtn").addEventListener("click", () => {
  try {
    const parsed = parseV2rayLink($("serverImportLink").value);
    applyImportedV2rayToForm(parsed);
    toast(`Imported ${parsed.protocol} ${parsed.host || ""}`.trim());
  } catch (err) {
    toast(err.message || "Import failed", true);
  }
});

$("serverForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  setBtn($("saveServerBtn"), true, "Saving...");
  try {
    const data = buildServerPayload();
    const id = $("serverDocId").value.trim();
    const custom = safeId($("serverCustomId").value);
    const ref = id ? doc(db, "servers_v3", id) : (custom ? doc(db, "servers_v3", custom) : doc(serversCol));
    await withVersion(async (tx) => {
      tx.set(ref, data, { merge: !!id });
      syncProfilesForServer(tx, ref.id, data.linkedProfileIds);
    });
    resetServerForm();
    toast("Server saved. config_version increased.");
  } catch (err) {
    toast(err.message || "Save failed", true);
  } finally { setBtn($("saveServerBtn"), false); }
});
$("resetServerBtn").addEventListener("click", resetServerForm);
$("serverSearch").addEventListener("input", renderServerList);
els.serverList.addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  const id = btn.dataset.id;
  const row = state.servers.find((x) => x.id === id);
  if (!row) return;
  try {
    if (btn.dataset.act === "edit") return fillServerForm(row);
    if (btn.dataset.act === "dup") {
      const { id: _, ...copy } = row;
      copy.server_name = `${row.server_name || "Server"} Copy`;
      copy.sort_order = n(row.sort_order) + 1;
      copy.updated_at = serverTimestamp();
      const copyRef = doc(serversCol);
      await withVersion(async (tx) => {
        tx.set(copyRef, copy);
        syncProfilesForServer(tx, copyRef.id, serverLinkedProfileIds(copy));
      });
      return toast("Server duplicated.");
    }
    if (btn.dataset.act === "toggle") {
      await withVersion(async (tx) => tx.update(doc(db, "servers_v3", id), { status: row.status === "active" ? "inactive" : "active", updated_at: serverTimestamp() }));
      return toast("Server status updated.");
    }
    if (btn.dataset.act === "del" && window.confirm(`Delete ${row.server_name || id}?`)) {
      await withVersion(async (tx) => {
        tx.delete(doc(db, "servers_v3", id));
        syncProfilesForServer(tx, id, []);
      });
      if ($("serverDocId").value === id) resetServerForm();
      toast("Server deleted.");
    }
  } catch (err) { toast(err.message || "Action failed", true); }
});

$("profileForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  setBtn($("saveProfileBtn"), true, "Saving...");
  try {
    const data = profilePayload();
    const id = $("profileDocId").value.trim();
    const custom = safeId($("profileCustomId").value);
    const ref = id ? doc(db, "profiles_v3", id) : (custom ? doc(db, "profiles_v3", custom) : doc(profilesCol));
    await withVersion(async (tx) => tx.set(ref, data, { merge: !!id }));
    resetProfileForm();
    toast("Profile saved. config_version increased.");
  } catch (err) {
    toast(err.message || "Save failed", true);
  } finally { setBtn($("saveProfileBtn"), false); }
});
$("resetProfileBtn").addEventListener("click", resetProfileForm);
$("profileSearch").addEventListener("input", renderProfileList);
els.profileList.addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-pact]");
  if (!btn) return;
  const id = btn.dataset.id;
  const row = state.profiles.find((x) => x.id === id);
  if (!row) return;
  try {
    if (btn.dataset.pact === "edit") return fillProfileForm(row);
    if (btn.dataset.pact === "link") {
      showScreen("profiles");
      showProfileView("link");
      $("linkProfileSelect").value = id;
      renderLinkPreview();
      return;
    }
    if (btn.dataset.pact === "toggle") {
      await withVersion(async (tx) => tx.update(doc(db, "profiles_v3", id), { status: row.status === "active" ? "inactive" : "active", updated_at: serverTimestamp() }));
      return toast("Profile status updated.");
    }
    if (btn.dataset.pact === "del" && window.confirm(`Delete ${row.profile_name || id}?`)) {
      await withVersion(async (tx) => {
        tx.delete(doc(db, "profiles_v3", id));
        state.servers.forEach((server) => {
          const linkedProfileIds = serverLinkedProfileIds(server);
          if (!linkedProfileIds.includes(id)) return;
          tx.set(doc(db, "servers_v3", server.id), {
            ...serverProfileLinkPatch(linkedProfileIds.filter((profileId) => profileId !== id)),
            updated_at: serverTimestamp()
          }, { merge: true });
        });
      });
      if ($("profileDocId").value === id) resetProfileForm();
      toast("Profile deleted.");
    }
  } catch (err) { toast(err.message || "Action failed", true); }
});

$("settingsForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  setBtn($("saveSettingsBtn"), true, "Saving...");
  try {
    await withVersion(async (tx) => tx.set(configRef, {
      app_notice: $("settingsNotice").value.trim(),
      force_update: b($("settingsForceUpdate").value),
      minimum_app_version: $("settingsMinVersion").value.trim(),
      updated_at: serverTimestamp()
    }, { merge: true }));
    toast("Settings saved. config_version increased.");
  } catch (err) {
    toast(err.message || "Save failed", true);
  } finally { setBtn($("saveSettingsBtn"), false); }
});

$("increaseVersionBtn").addEventListener("click", async () => {
  setBtn($("increaseVersionBtn"), true, "Increasing...");
  try {
    await runTransaction(db, async (tx) => { await bumpVersion(tx); });
    await loadAll();
    toast("config_version increased.");
  } catch (err) {
    toast(err.message || "Failed", true);
  } finally { setBtn($("increaseVersionBtn"), false); }
});

document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => showScreen(t.dataset.screen));
});
document.querySelectorAll("[data-home-target]").forEach((btn) => {
  btn.addEventListener("click", () => openHomeTarget(btn.dataset.homeTarget, btn.dataset.homeMode));
});
document.querySelectorAll("[data-profile-view]").forEach((btn) => {
  btn.addEventListener("click", () => showProfileView(btn.dataset.profileView));
});
$("linkProfileSelect").addEventListener("change", renderLinkPreview);
$("linkServerSelect").addEventListener("change", renderLinkPreview);
$("linkServerBtn").addEventListener("click", async () => {
  setBtn($("linkServerBtn"), true, "Linking...");
  try {
    await linkSelectedServer();
    toast("Server linked. config_version increased.");
  } catch (err) {
    toast(err.message || "Link failed", true);
  } finally {
    setBtn($("linkServerBtn"), false);
    renderLinkPreview();
  }
});
$("unlinkServerBtn").addEventListener("click", async () => {
  setBtn($("unlinkServerBtn"), true, "Unlinking...");
  try {
    await unlinkSelectedServer();
    toast("Server unlinked. config_version increased.");
  } catch (err) {
    toast(err.message || "Unlink failed", true);
  } finally {
    setBtn($("unlinkServerBtn"), false);
    renderLinkPreview();
  }
});

populateServerFlagSelect();
populateProfileIconSelect();
updateServerFormMode();
showProfileView("add");
showScreen("home");

onAuthStateChanged(auth, async (user) => {
  if (!user) {
    els.appView.classList.add("hidden");
    els.loginView.classList.remove("hidden");
    return;
  }
  els.userEmail.textContent = user.email || "-";
  els.loginView.classList.add("hidden");
  els.appView.classList.remove("hidden");
  try {
    await loadAll();
    showScreen("home");
  } catch (err) {
    toast(err.message || "Load failed", true);
  }
});
