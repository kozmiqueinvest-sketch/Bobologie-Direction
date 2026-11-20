/* Bobologie Direction — tableau de suivi des directeurs.
   Reçoit les liens verrouillés envoyés par l'appli animateur, les déchiffre avec le
   mot de passe direction et range les suivis. Tout reste sur ce téléphone, aucun serveur. */
(() => {
  'use strict';

  const VERSION = '1.1';
  const STORE_KEY = 'bobologie-direction.v1';
  // Cadenas officiel de la structure. Une fois renseigné, un mot de passe qui ne
  // donne pas ce cadenas est refusé (protège des fautes de frappe).
  const EXPECTED_PUB = '';
  const PBKDF2_ROUNDS = 250000;
  const PBKDF2_SALT = 'bobologie-direction/v1';
  const HKDF_INFO = 'bobologie-direction/v1';

  const FLAGS = {
    parents: { label: 'Parents prévenus', emoji: '📞' },
    direction: { label: 'Direction prévenue', emoji: '📣' },
    watch: { label: 'À surveiller', emoji: '👀' },
    txParents: { label: 'Transmission parents', emoji: '💬' },
    txTeacher: { label: 'Transmission enseignant', emoji: '🏫' },
  };
  const FOLLOW = [
    { key: 'txTeacher', title: 'À transmettre aux enseignants', todo: 'Marquer transmis', done: 'Transmis' },
    { key: 'txParents', title: 'À transmettre aux parents', todo: 'Marquer transmis', done: 'Transmis' },
    { key: 'watch', title: 'À surveiller', todo: 'Fin de surveillance', done: 'Surveillance terminée' },
  ];

  const ICON = {
    journal: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="4.5" width="14" height="16.5" rx="3"/><path d="M9 3h6v3H9zM8.5 11.5h7M8.5 15.5h4.5"/></svg>',
    kids: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8.5" r="3.2"/><path d="M3.5 19.5c.6-3.2 2.7-5 5.5-5s4.9 1.8 5.5 5"/><circle cx="17" cy="9.5" r="2.4"/><path d="M16.8 14.6c2 .3 3.3 1.8 3.7 4.4"/></svg>',
    right: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9.5 5.5 16 12l-6.5 6.5"/></svg>',
    pin: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3.5h12v17l-6-4-6 4z"/></svg>',
    settings: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/></svg>',
    paste: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="4.5" width="14" height="16.5" rx="3"/><path d="M9 3h6v3H9zM12 10v7M8.5 13.5 12 17l3.5-3.5"/></svg>',
  };
  const TABS = [
    { id: 'follow', label: 'Suivis', icon: ICON.pin },
    { id: 'journal', label: 'Journal', icon: ICON.journal },
    { id: 'children', label: 'Enfants', icon: ICON.kids },
    { id: 'settings', label: 'Réglages', icon: ICON.settings },
  ];

  /* ---------- Petits outils ---------- */
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const plural = (n, word) => `${n} ${word}${n > 1 ? 's' : ''}`;
  const str = (v) => (typeof v === 'string' ? v : '');
  const arr = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x) : []);
  const norm = (s) => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/\s+/g, ' ').trim();
  const isTime = (v) => /^\d{2}:\d{2}$/.test(v || '');
  const isDate = (v) => /^\d{4}-\d{2}-\d{2}$/.test(v || '');
  const fmtTime = (hm) => (isTime(hm) ? hm.replace(':', 'h') : '—');
  function fmtLong(iso) {
    const [y, m, d] = iso.split('-').map(Number);
    return new Date(y, m - 1, d).toLocaleDateString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
  }
  function fmtShort(iso) {
    const [y, m, d] = iso.split('-').map(Number);
    return new Date(y, m - 1, d).toLocaleDateString('fr-FR', { weekday: 'short', day: 'numeric', month: 'short' });
  }
  const b64u = (bytes) => {
    let bin = '';
    bytes.forEach((v) => { bin += String.fromCharCode(v); });
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (ch) => ch.charCodeAt(0));

  /* ---------- Chiffrement ----------
     Le mot de passe donne, par calcul, une paire de clés P-256 : la clé privée reste
     ici, la clé publique est le « cadenas » confié aux applis animateur. */
  const P = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n;
  const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const G = [0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n];
  const mod = (a) => ((a % P) + P) % P;
  function inv(a) {
    let [r0, r1, s0, s1] = [mod(a), P, 1n, 0n];
    while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    return mod(s0);
  }
  function add(a, b) {
    if (!a) return b;
    if (!b) return a;
    const [x1, y1] = a;
    const [x2, y2] = b;
    let m;
    if (x1 === x2) {
      if (mod(y1 + y2) === 0n) return null;
      m = mod((3n * x1 * x1 - 3n) * inv(2n * y1));
    } else {
      m = mod((y2 - y1) * inv(x2 - x1));
    }
    const x3 = mod(m * m - x1 - x2);
    return [x3, mod(m * (x1 - x3) - y1)];
  }
  function mul(k, pt) {
    let out = null;
    let cur = pt;
    while (k > 0n) { if (k & 1n) out = add(out, cur); cur = add(cur, cur); k >>= 1n; }
    return out;
  }
  const toBig = (bytes) => bytes.reduce((n, v) => (n << 8n) | BigInt(v), 0n);
  const toBytes = (n) => Uint8Array.from({ length: 32 }, (_, i) => Number((n >> BigInt(8 * (31 - i))) & 255n));

  async function keyFromPassword(password) {
    const enc = new TextEncoder();
    const base = await crypto.subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(PBKDF2_SALT), iterations: PBKDF2_ROUNDS }, base, 256);
    const d = (toBig(new Uint8Array(bits)) % (N - 1n)) + 1n;
    const [x, y] = mul(d, G);
    return { d: b64u(toBytes(d)), x: b64u(toBytes(x)), y: b64u(toBytes(y)) };
  }
  function pubOf(key) {
    const out = new Uint8Array(64);
    out.set(unb64u(key.x), 0);
    out.set(unb64u(key.y), 32);
    return b64u(out);
  }
  async function decryptLink(code, key) {
    const data = unb64u(code);
    if (data.length < 77 + 16) throw new Error('lien trop court');
    const ephRaw = data.slice(0, 65);
    const mineRaw = new Uint8Array(65);
    mineRaw[0] = 4;
    mineRaw.set(unb64u(pubOf(key)), 1);
    const alg = { name: 'ECDH', namedCurve: 'P-256' };
    const priv = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', d: key.d, x: key.x, y: key.y, ext: true }, alg, false, ['deriveBits']);
    const eph = await crypto.subtle.importKey('raw', ephRaw, alg, false, []);
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: eph }, priv, 256);
    const salt = new Uint8Array(130);
    salt.set(ephRaw, 0);
    salt.set(mineRaw, 65);
    const hk = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const aes = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(HKDF_INFO) }, hk, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(65, 77) }, aes, data.slice(77));
    return JSON.parse(new TextDecoder().decode(plain));
  }

  /* ---------- Données ---------- */
  function splitName(name) {
    const parts = String(name || 'Enfant').trim().split(/\s+/);
    return { firstName: parts[0], lastName: parts.slice(1).join(' ') };
  }
  function normalize(d) {
    d = d && typeof d === 'object' ? d : {};
    const k = d.key && typeof d.key === 'object' && str(d.key.d) && str(d.key.x) && str(d.key.y) ? { d: d.key.d, x: d.key.x, y: d.key.y } : null;
    const items = (Array.isArray(d.items) ? d.items : []).filter((e) => e && e.id && isDate(e.date)).map((e) => ({
      id: String(e.id), date: e.date, time: isTime(e.time) ? e.time : '00:00',
      name: str(e.name) || 'Enfant', childKey: str(e.childKey) || norm(e.name), group: str(e.group), animator: str(e.animator), structure: str(e.structure),
      types: arr(e.types), zones: arr(e.zones), details: str(e.details),
      cares: (Array.isArray(e.cares) ? e.cares : []).filter((c) => Array.isArray(c)).map((c) => [str(c[0]), str(c[1])]),
      flags: arr(e.flags).filter((f) => FLAGS[f]), by: str(e.by),
      done: Object.fromEntries(FOLLOW.map((f) => [f.key, !!(e.done && e.done[f.key])])),
      receivedAt: +e.receivedAt || 0,
    }));
    const children = (Array.isArray(d.children) ? d.children : []).filter((c) => c && str(c.key) && str(c.firstName))
      .map((c) => ({ key: c.key, firstName: c.firstName, lastName: str(c.lastName), group: str(c.group), notes: str(c.notes) }));
    // Suivis reçus avant l'onglet Enfants : on recrée les fiches à partir des noms.
    items.forEach((e) => { if (!children.some((c) => c.key === e.childKey)) children.push(Object.assign({ key: e.childKey, group: e.group, notes: '' }, splitName(e.name))); });
    return { key: k, items, children, installAsked: !!d.installAsked };
  }
  function load() {
    try { return normalize(JSON.parse(localStorage.getItem(STORE_KEY) || '{}')); } catch (e) { return normalize({}); }
  }
  function save() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(db)); } catch (e) { toast('Enregistrement impossible sur ce téléphone'); }
  }

  let db = load();
  const ui = { tab: 'follow', all: false, childQuery: '' };
  let pendingHash = '';      // lien reçu avant la saisie du mot de passe
  let installPrompt = null;

  function followItems(key, all) {
    return db.items
      .filter((e) => e.flags.includes(key) && (all || !e.done[key]))
      .sort((a, b) => (b.date + b.time).localeCompare(a.date + a.time));
  }
  function childName(c) { return [c.firstName, c.lastName].filter(Boolean).join(' '); }
  function itemsOf(key) { return db.items.filter((e) => e.childKey === key).sort((a, b) => (b.date + b.time).localeCompare(a.date + a.time)); }
  function hue(text) { let h = 0; for (const ch of text) h = (h * 31 + ch.charCodeAt(0)) % 360; return h; }
  function avatar(c) {
    const ini = ((c.firstName || '?')[0] + ((c.lastName || '')[0] || '')).toUpperCase();
    return `<span class="avatar" style="--h:${hue(childName(c))}" aria-hidden="true">${esc(ini)}</span>`;
  }
  /* Crée ou complète la fiche d'un enfant à partir d'un bobo reçu. Deux animateurs qui
     envoient le même enfant (même prénom et nom) alimentent la même fiche. */
  function upsertChild(first, last, group, notes) {
    const key = norm(`${first} ${last}`);
    let c = db.children.find((x) => x.key === key);
    if (!c) { c = { key, firstName: first, lastName: last, group: '', notes: '' }; db.children.push(c); }
    if (group) c.group = group;
    if (notes) c.notes = notes;
    return key;
  }
  function pendingCount() { return FOLLOW.reduce((n, f) => n + followItems(f.key, false).length, 0); }

  /* Importe tous les liens direction trouvés dans un texte (un ou plusieurs messages). */
  async function importText(text) {
    const codes = [...new Set([...String(text || '').matchAll(/#e=([A-Za-z0-9_-]{100,})/g)].map((m) => m[1]))];
    if (!codes.length) return { links: 0, added: 0, updated: 0, failed: 0 };
    let added = 0;
    let updated = 0;
    let failed = 0;
    for (const code of codes) {
      let p;
      try { p = await decryptLink(code, db.key); } catch (e) { failed += 1; continue; }
      if (!p || !Array.isArray(p.e) || !isDate(p.d)) { failed += 1; continue; }
      p.e.forEach((e) => {
        if (!e || !e.i) return;
        const flags = arr(e.f).filter((f) => FLAGS[f]);
        // Les liens récents donnent prénom et nom séparés ; les anciens, seulement « Hugo R. ».
        const who = str(e.p) ? { firstName: str(e.p).trim(), lastName: str(e.l).trim() } : splitName(str(e.n));
        const childKey = upsertChild(who.firstName, who.lastName, str(e.g), str(e.o));
        const data = {
          id: String(e.i), date: p.d, time: isTime(e.t) ? e.t : '00:00',
          // Nom tel qu'il est écrit sur la fiche, même si un autre animateur l'a saisi autrement.
          name: childName(db.children.find((c) => c.key === childKey)), childKey, group: str(e.g), animator: str(p.a), structure: str(p.s),
          types: arr(e.y), zones: arr(e.z), details: str(e.x),
          cares: (Array.isArray(e.c) ? e.c : []).filter((c) => Array.isArray(c)).map((c) => [str(c[0]), str(c[1])]),
          flags, by: str(e.b),
        };
        const old = db.items.find((x) => x.id === data.id);
        if (old) {
          // Même bobo renvoyé : on met à jour sans perdre ce qui est déjà coché.
          Object.assign(old, data, { done: Object.fromEntries(FOLLOW.map((f) => [f.key, old.done[f.key] && flags.includes(f.key)])) });
          updated += 1;
        } else {
          db.items.push(Object.assign(data, { done: Object.fromEntries(FOLLOW.map((f) => [f.key, false])), receivedAt: Date.now() }));
          added += 1;
        }
      });
    }
    save();
    return { links: codes.length, added, updated, failed };
  }
  function reportImport(r) {
    if (!r.links) { toast('Aucun lien direction dans ce texte'); return; }
    const parts = [];
    if (r.added) parts.push(`${plural(r.added, 'suivi')} ajouté${r.added > 1 ? 's' : ''}`);
    if (r.updated) parts.push(`${r.updated} déjà reçu${r.updated > 1 ? 's' : ''}`);
    if (r.failed) parts.push(`${plural(r.failed, 'lien')} illisible${r.failed > 1 ? 's' : ''} avec ce mot de passe`);
    toast(parts.join(' · ') || 'Rien de nouveau');
  }

  /* ---------- Écrans ---------- */
  function isIOS() { return /iphone|ipad|ipod/i.test(navigator.userAgent); }
  function isStandalone() { return navigator.standalone === true || matchMedia('(display-mode: standalone)').matches; }

  function renderShell() {
    $('#app').innerHTML = `
      <main id="view" tabindex="-1"></main>
      <div id="actionbar"></div>
      <nav class="tabs" aria-label="Navigation principale">
        ${TABS.map((t) => `<button type="button" class="tab" data-action="tab" data-tab="${t.id}">${t.icon}<span>${t.label}</span></button>`).join('')}
      </nav>
      <div id="sheets"></div>
      <div id="toast" role="status" aria-live="polite"></div>`;
  }

  function render() {
    const view = $('#view');
    const bar = $('#actionbar');
    const tabs = $('.tabs');
    if (!db.key) {
      tabs.hidden = true;
      bar.innerHTML = '';
      view.innerHTML = setupHTML();
      return;
    }
    tabs.hidden = false;
    $$('.tab').forEach((b) => { if (b.dataset.tab === ui.tab) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
    const pending = pendingCount();
    $('.tab[data-tab="follow"] span').innerHTML = `Suivis${pending ? ` <b class="badge">${pending}</b>` : ''}`;
    if (ui.tab === 'follow') {
      view.innerHTML = followHTML();
      bar.innerHTML = `<button type="button" class="btn primary grow" data-action="paste">${ICON.paste}Coller les messages</button>`;
    } else if (ui.tab === 'journal') {
      view.innerHTML = journalHTML();
      bar.innerHTML = '';
    } else if (ui.tab === 'children') {
      view.innerHTML = childrenHTML();
      bar.innerHTML = '';
    } else {
      view.innerHTML = settingsHTML();
      bar.innerHTML = '';
    }
  }

  function flagsHTML(e, skip) {
    return e.flags.filter((k) => k !== skip).map((k) => {
      const fo = FOLLOW.find((f) => f.key === k);
      return `<span class="flag">${FLAGS[k].emoji} ${FLAGS[k].label}${fo && e.done[k] ? ' ✓' : ''}</span>`;
    }).join('');
  }

  function journalHTML() {
    if (!db.items.length) {
      return `<header class="masthead"><h1>Journal</h1></header>
        <div class="empty">${ICON.journal}<h2>Journal vide</h2><p>Les bobos reçus des animateurs s’affichent ici, jour par jour.</p></div>`;
    }
    const days = [...new Set(db.items.map((e) => e.date))].sort().reverse();
    return `<header class="masthead"><h1>Journal</h1><span class="brand-sub">${plural(db.items.length, 'bobo')} reçu${db.items.length > 1 ? 's' : ''}</span></header>
      <p class="hint" style="margin-bottom:4px">Seuls les bobos avec un suivi sont envoyés à la direction.</p>
      ${days.map((d) => {
        const list = db.items.filter((e) => e.date === d).sort((a, b) => a.time.localeCompare(b.time));
        return `<h2 class="group-title">${esc(fmtLong(d))} · ${list.length}</h2>
          <ol class="timeline">${list.map((e) => `<li class="entry">
            <time class="entry-time" datetime="${e.time}">${fmtTime(e.time)}</time>
            <button type="button" class="card entry-card" data-action="child-open" data-key="${esc(e.childKey)}">
              <span class="entry-head"><span class="entry-name">${esc(e.name)}</span>${e.group ? `<span class="tag">${esc(e.group)}</span>` : ''}</span>
              <span class="entry-what">${esc(e.types.join(' · ') || 'Bobo')}${e.zones.length ? ` <span class="muted">— ${esc(e.zones.join(', ').toLowerCase())}</span>` : ''}</span>
              ${e.details ? `<span class="entry-details">${esc(e.details)}</span>` : ''}
              ${e.cares.map((c) => `<span class="care-line"><span class="care-badge">${fmtTime(c[0])}</span><span>${esc(c[1])}</span></span>`).join('')}
              <span class="flags">${flagsHTML(e)}</span>
              ${e.animator || e.by ? `<span class="entry-by">${e.by ? `Soigné par ${esc(e.by)}` : ''}${e.by && e.animator ? ' · ' : ''}${e.animator ? `envoyé par ${esc(e.animator)}` : ''}</span>` : ''}
            </button>
          </li>`).join('')}</ol>`;
      }).join('')}`;
  }

  function childrenHTML() {
    if (!db.children.length) {
      return `<header class="masthead"><h1>Enfants</h1></header>
        <div class="empty">${ICON.kids}<h2>Aucun enfant</h2><p>Les fiches se créent toutes seules quand vous recevez un suivi : prénom, nom, groupe et infos utiles.</p></div>`;
    }
    return `<header class="masthead"><h1>Enfants</h1><span class="brand-sub">${plural(db.children.length, 'enfant')}</span></header>
      <div class="search"><input type="search" id="child-q" placeholder="Rechercher un enfant ou un groupe" value="${esc(ui.childQuery)}" aria-label="Rechercher" autocomplete="off"></div>
      <div id="child-list">${childListHTML()}</div>`;
  }
  function childListHTML() {
    const q = norm(ui.childQuery);
    const list = [...db.children].sort((a, b) => childName(a).localeCompare(childName(b), 'fr', { sensitivity: 'base' }))
      .filter((c) => !q || norm(`${childName(c)} ${c.group}`).includes(q));
    if (!list.length) return '<p class="hint center">Aucun enfant ne correspond à cette recherche.</p>';
    const byGroup = new Map();
    list.forEach((c) => { if (!byGroup.has(c.group)) byGroup.set(c.group, []); byGroup.get(c.group).push(c); });
    const names = [...byGroup.keys()].sort((a, b) => (a === '') - (b === '') || a.localeCompare(b, 'fr', { numeric: true }));
    const titles = names.length > 1 || names[0] !== '';
    return names.map((g) => `${titles ? `<h2 class="group-title">${esc(g || 'Sans groupe')}</h2>` : ''}
      <div class="card rows">${byGroup.get(g).map((c) => {
        const all = itemsOf(c.key);
        const todo = all.filter((e) => FOLLOW.some((f) => e.flags.includes(f.key) && !e.done[f.key])).length;
        return `<button type="button" class="row" data-action="child-open" data-key="${esc(c.key)}">
          ${avatar(c)}
          <span class="row-main"><strong>${esc(childName(c))}</strong><span>${plural(all.length, 'bobo')}${todo ? ` · ${todo} à traiter` : ''}${c.notes ? ' · ⚠️ infos' : ''}</span></span>
          ${ICON.right}
        </button>`;
      }).join('')}</div>`).join('');
  }
  function openChildSheet(key) {
    const c = db.children.find((x) => x.key === key);
    if (!c) return;
    const hist = itemsOf(key);
    openSheet('Fiche enfant', `
      <div class="card picked">${avatar(c)}<div class="picked-main"><strong>${esc(childName(c))}</strong>${c.group ? `<span>${esc(c.group)}</span>` : ''}</div></div>
      ${c.notes ? `<p class="alert" style="margin-top:0">⚠️ ${esc(c.notes)}</p>` : ''}
      <section><h3>Historique<small>${plural(hist.length, 'bobo')}</small></h3>
        ${hist.length ? `<ul class="history">${hist.map((e) => `<li><b>${esc(fmtShort(e.date))} · ${fmtTime(e.time)}</b><br>${esc(e.types.join(', ') || 'Bobo')}${e.zones.length ? ` — ${esc(e.zones.join(', ').toLowerCase())}` : ''}
          ${e.details ? `<br><span class="muted">${esc(e.details)}</span>` : ''}
          ${e.cares.length ? `<br><span class="muted">Soins : ${esc(e.cares.map((k) => `${fmtTime(k[0])} ${k[1]}`).join(' ; '))}</span>` : ''}
          <br><span class="flags" style="margin-top:6px">${flagsHTML(e)}</span></li>`).join('')}</ul>` : '<p class="hint">Aucun bobo reçu pour cet enfant.</p>'}
      </section>
      <button type="button" class="btn danger block" data-action="child-delete" data-key="${esc(c.key)}">Supprimer cette fiche</button>`);
  }

  function setupHTML() {
    return `<div class="setup">
      <img src="icons/icon-192.png" alt="" width="72" height="72">
      <h1>Espace direction</h1>
      <p class="hint">Cet espace est réservé aux directeurs. Saisissez le mot de passe direction : il sert à ouvrir les liens verrouillés envoyés par les animateurs.</p>
      ${pendingHash ? '<p class="alert">Un lien de suivi vous attend : il s’ouvrira dès que le mot de passe sera saisi.</p>' : ''}
      <label class="field"><span class="label">Mot de passe direction</span>
        <input type="password" id="pw" autocomplete="current-password" autocapitalize="off" enterkeyhint="go"></label>
      <button type="button" class="btn primary block" data-action="unlock">Ouvrir l’espace direction</button>
      <p class="hint">Premier directeur à l’installer ? Choisissez ici le mot de passe (une phrase de quatre ou cinq mots, difficile à deviner), puis donnez-le aux autres directeurs de vive voix. Il n’est demandé qu’une fois par téléphone.</p>
    </div>`;
  }

  function followHTML() {
    const sections = FOLLOW.map((f) => {
      const list = followItems(f.key, ui.all);
      if (!list.length) return '';
      return `<h2 class="group-title">${f.title} · ${list.length}</h2>
        <div class="follow-list">${list.map((e) => {
          const isDone = e.done[f.key];
          const others = flagsHTML(e, f.key);
          return `<article class="card follow${isDone ? ' is-done' : ''}">
            <div class="entry-head"><span class="entry-name">${esc(e.name)}</span>${e.group ? `<span class="tag">${esc(e.group)}</span>` : ''}</div>
            <p class="follow-when">${esc(fmtShort(e.date))} à ${fmtTime(e.time)}${e.animator ? ` · envoyé par ${esc(e.animator)}` : ''}</p>
            <p class="entry-what">${esc(e.types.join(' · ') || 'Bobo')}${e.zones.length ? ` <span class="muted">— ${esc(e.zones.join(', ').toLowerCase())}</span>` : ''}</p>
            ${e.details ? `<p class="entry-details">${esc(e.details)}</p>` : ''}
            ${(db.children.find((c) => c.key === e.childKey) || {}).notes ? `<p class="alert" style="margin-top:0">⚠️ ${esc(db.children.find((c) => c.key === e.childKey).notes)}</p>` : ''}
            ${e.cares.map((c) => `<p class="care-line"><span class="care-badge">${fmtTime(c[0])}</span><span>${esc(c[1])}</span></p>`).join('')}
            ${others ? `<p class="flags">${others}</p>` : ''}
            <div class="follow-actions">
              <button type="button" class="btn ${isDone ? 'ghost' : 'primary'}" data-action="done" data-id="${esc(e.id)}" data-key="${f.key}">${isDone ? `✓ ${f.done} · annuler` : f.todo}</button>
              <button type="button" class="link" data-action="remove" data-id="${esc(e.id)}">Supprimer</button>
            </div>
          </article>`;
        }).join('')}</div>`;
    }).join('');
    return `
      <header class="masthead"><h1>Suivis</h1><span class="brand-sub">Direction</span></header>
      <div class="seg" role="group" aria-label="Filtre">
        <button type="button" data-action="filter" data-value="todo" aria-pressed="${!ui.all}">À faire</button>
        <button type="button" data-action="filter" data-value="all" aria-pressed="${ui.all}">Tout, y compris fait</button>
      </div>
      ${sections || `<div class="empty">${ICON.pin}<h2>${db.items.length ? 'Tout est traité' : 'Aucun suivi reçu'}</h2>
        <p>Dans WhatsApp, copiez le ou les messages de bobologie des animateurs, puis touchez « Coller les messages » ci-dessous.</p></div>`}`;
  }

  function settingsHTML() {
    const doneCount = db.items.filter((e) => FOLLOW.every((f) => !e.flags.includes(f.key) || e.done[f.key])).length;
    return `
      <header class="masthead"><h1>Réglages</h1></header>
      <section class="card panel">
        <h2>Cadenas pour les animateurs</h2>
        <p class="hint">Ce code n’est pas secret. Il permet aux applis des animateurs de verrouiller leurs liens pour vous, sans pouvoir les rouvrir. Tous les directeurs qui ont le même mot de passe ont le même cadenas.</p>
        <p class="keybox" id="pub">${esc(pubOf(db.key))}</p>
        <button type="button" class="btn ghost block" data-action="copy-pub">Copier le cadenas</button>
      </section>
      ${isStandalone() ? '' : `
      <section class="card panel">
        <h2>Installation</h2>
        <p class="hint">L’appli n’est pas encore sur l’écran d’accueil de ce téléphone.</p>
        <button type="button" class="btn primary block" data-action="install-ask">Installer l’appli</button>
      </section>`}
      <section class="card panel">
        <h2>Ménage</h2>
        <button type="button" class="btn ghost block" data-action="purge"${doneCount ? '' : ' disabled'}>Supprimer les suivis terminés (${doneCount})</button>
      </section>
      <section class="card panel">
        <h2>Mot de passe et données</h2>
        <p class="hint">Les suivis restent uniquement sur ce téléphone. Pensez à le verrouiller : ces informations concernent des enfants.</p>
        <button type="button" class="btn ghost block" data-action="lock">Changer de mot de passe</button>
        <button type="button" class="btn danger block" data-action="wipe">Tout effacer</button>
      </section>
      <p class="version">Bobologie Direction ${VERSION} · ${plural(db.items.length, 'suivi')}</p>`;
  }

  /* ---------- Feuille, confirmation, toast ---------- */
  function openSheet(title, body) {
    closeSheet();
    const el = document.createElement('div');
    el.className = 'sheet';
    el.setAttribute('role', 'dialog');
    el.setAttribute('aria-modal', 'true');
    el.setAttribute('aria-label', title);
    el.innerHTML = `<div class="sheet-inner">
      <header class="sheet-head"><button type="button" data-action="sheet-close">Fermer</button><h2>${esc(title)}</h2><span></span></header>
      <div class="sheet-body">${body}</div>
    </div>`;
    $('#sheets').appendChild(el);
  }
  function openPasteSheet() {
    const el = document.createElement('div');
    el.className = 'sheet';
    el.setAttribute('role', 'dialog');
    el.setAttribute('aria-modal', 'true');
    el.setAttribute('aria-label', 'Coller les messages');
    el.innerHTML = `<div class="sheet-inner">
      <header class="sheet-head">
        <button type="button" data-action="sheet-close">Annuler</button>
        <h2>Coller les messages</h2>
        <button type="button" data-action="paste-import">Importer</button>
      </header>
      <div class="sheet-body">
        <p class="hint">Dans WhatsApp, appuyez longuement sur un message de bobologie, sélectionnez-en plusieurs si besoin, puis « Copier ». Collez ensuite ici.</p>
        <label class="field"><span class="label">Messages copiés</span><textarea id="paste-text" rows="10" placeholder="Appuyez longuement ici, puis « Coller »"></textarea></label>
        <button type="button" class="btn primary block" data-action="paste-import">Importer les suivis</button>
      </div>
    </div>`;
    $('#sheets').appendChild(el);
    $('#paste-text').focus();
  }
  function closeSheet() { const s = $('.sheet'); if (s) s.remove(); }

  function confirmDialog({ title, text, ok = 'OK', cancel = 'Annuler', danger = false }) {
    return new Promise((resolve) => {
      const back = document.createElement('div');
      back.className = 'dialog-back';
      back.innerHTML = `<div class="dialog" role="alertdialog" aria-modal="true" aria-labelledby="dlg-title">
        <h2 id="dlg-title">${esc(title)}</h2>
        ${text ? `<p>${esc(text)}</p>` : ''}
        <div class="grid2">
          <button type="button" class="btn ghost" data-r="0">${esc(cancel)}</button>
          <button type="button" class="btn ${danger ? 'danger-fill' : 'primary'}" data-r="1">${esc(ok)}</button>
        </div>
      </div>`;
      back.addEventListener('click', (ev) => {
        const b = ev.target.closest('[data-r]');
        if (!b && ev.target !== back) return;
        back.remove();
        resolve(!!b && b.dataset.r === '1');
      });
      document.body.appendChild(back);
      $('[data-r="0"]', back).focus();
    });
  }

  function installStepsHTML() {
    if (isIOS()) {
      return `<h2 id="dlg-title">Trois gestes sur l’iPhone</h2>
        <ol class="steps">
          <li>Touchez le bouton <b>Partager</b> de Safari (le carré avec une flèche vers le haut). Sur les iPhone récents, il est derrière « ••• ».</li>
          <li>Faites défiler la liste et touchez <b>« Sur l’écran d’accueil »</b>.</li>
          <li>Touchez <b>Ajouter</b>, puis ouvrez l’appli depuis sa nouvelle icône : c’est là qu’il faudra saisir le mot de passe.</li>
        </ol>
        <button type="button" class="btn primary block" data-r="close">J’ai compris</button>`;
    }
    return `<h2 id="dlg-title">Installer depuis le menu</h2>
      <ol class="steps">
        <li>Ouvrez le menu <b>⋮</b> du navigateur, en haut à droite.</li>
        <li>Touchez <b>« Installer l’application »</b> ou <b>« Ajouter à l’écran d’accueil »</b>.</li>
        <li>Confirmez, puis ouvrez l’appli depuis sa nouvelle icône.</li>
      </ol>
      <button type="button" class="btn primary block" data-r="close">J’ai compris</button>`;
  }
  function openInstallDialog() {
    if ($('.dialog-back')) return;
    const back = document.createElement('div');
    back.className = 'dialog-back';
    back.innerHTML = `<div class="dialog" role="alertdialog" aria-modal="true" aria-labelledby="dlg-title">
      <img src="icons/icon-192.png" alt="" class="dialog-icon" width="72" height="72">
      <h2 id="dlg-title">Installer l’appli Direction ?</h2>
      <p>Elle s’ajoute à votre écran d’accueil et fonctionne sans réseau. Sur iPhone, installez-la avant de saisir le mot de passe.</p>
      <div class="grid2">
        <button type="button" class="btn ghost" data-r="later">Pas maintenant</button>
        <button type="button" class="btn primary" data-r="yes">Installer</button>
      </div></div>`;
    back.addEventListener('click', async (ev) => {
      const b = ev.target.closest('[data-r]');
      if (!b) return;
      if (!db.installAsked) { db.installAsked = true; save(); }
      if (b.dataset.r === 'yes') {
        if (installPrompt) {
          back.remove();
          const p = installPrompt;
          installPrompt = null;
          p.prompt();
          return;
        }
        $('.dialog', back).innerHTML = installStepsHTML();
        $('[data-r="close"]', back).focus();
        return;
      }
      back.remove();
    });
    document.body.appendChild(back);
    $('[data-r]', back).focus();
  }

  let toastTimer;
  function toast(msg) {
    const el = $('#toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 3200);
  }

  /* ---------- Actions ---------- */
  const actions = {
    tab(el) { ui.tab = el.dataset.tab; render(); $('#view').scrollTop = 0; },
    filter(el) { ui.all = el.dataset.value === 'all'; render(); },
    async unlock(el) {
      const pw = $('#pw').value;
      if (pw.trim().length < 8) { toast('Mot de passe trop court (8 caractères au moins)'); return; }
      el.disabled = true;
      el.textContent = 'Vérification…';
      let key;
      try { key = await keyFromPassword(pw.trim()); } catch (e) { key = null; }
      if (!key) { toast('Ce navigateur ne permet pas le chiffrement'); render(); return; }
      if (EXPECTED_PUB && pubOf(key) !== EXPECTED_PUB) { toast('Mot de passe incorrect'); render(); return; }
      db.key = key;
      save();
      ui.tab = EXPECTED_PUB ? 'follow' : 'settings';
      render();
      if (pendingHash) {
        const r = await importText(pendingHash);
        pendingHash = '';
        ui.tab = 'follow';
        render();
        reportImport(r);
      } else if (!EXPECTED_PUB) {
        toast('Espace ouvert. Transmettez ce cadenas pour les animateurs.');
      }
    },
    async paste() {
      let text = '';
      try { text = await navigator.clipboard.readText(); } catch (e) { text = ''; }
      if (!/#e=[A-Za-z0-9_-]{100,}/.test(text)) { openPasteSheet(); return; }
      const r = await importText(text);
      render();
      reportImport(r);
    },
    async 'paste-import'() {
      const r = await importText($('#paste-text').value);
      if (!r.links) { reportImport(r); return; }
      closeSheet();
      render();
      reportImport(r);
    },
    'sheet-close'() { closeSheet(); },
    'child-open'(el) { openChildSheet(el.dataset.key); },
    async 'child-delete'(el) {
      const c = db.children.find((x) => x.key === el.dataset.key);
      if (!c) return;
      const n = itemsOf(c.key).length;
      const ok = await confirmDialog({ title: `Supprimer la fiche de ${c.firstName} ?`, text: n ? `Sa fiche et ses ${plural(n, 'bobo')} reçu${n > 1 ? 's' : ''} seront effacés de ce téléphone.` : 'Sa fiche sera effacée de ce téléphone.', ok: 'Supprimer', danger: true });
      if (!ok) return;
      db.items = db.items.filter((e) => e.childKey !== c.key);
      db.children = db.children.filter((x) => x.key !== c.key);
      save();
      closeSheet();
      render();
    },
    done(el) {
      const e = db.items.find((x) => x.id === el.dataset.id);
      if (!e) return;
      e.done[el.dataset.key] = !e.done[el.dataset.key];
      save();
      render();
    },
    async remove(el) {
      const e = db.items.find((x) => x.id === el.dataset.id);
      if (!e) return;
      const ok = await confirmDialog({ title: `Supprimer le suivi de ${e.name} ?`, text: 'Il disparaît aussi du journal. La fiche de l’enfant est conservée.', ok: 'Supprimer', danger: true });
      if (!ok) return;
      db.items = db.items.filter((x) => x.id !== e.id);
      save();
      render();
    },
    async 'copy-pub'() {
      const text = pubOf(db.key);
      try { await navigator.clipboard.writeText(text); toast('Cadenas copié'); } catch (e) {
        const range = document.createRange();
        range.selectNodeContents($('#pub'));
        const sel = getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        toast('Cadenas sélectionné : copiez-le');
      }
    },
    'install-ask'() { openInstallDialog(); },
    async purge() {
      const ok = await confirmDialog({ title: 'Supprimer les suivis terminés ?', text: 'Les bobos entièrement traités sont retirés des suivis et du journal. Les fiches enfants sont conservées.', ok: 'Supprimer', danger: true });
      if (!ok) return;
      db.items = db.items.filter((e) => !FOLLOW.every((f) => !e.flags.includes(f.key) || e.done[f.key]));
      save();
      render();
    },
    async lock() {
      const ok = await confirmDialog({ title: 'Changer de mot de passe ?', text: 'Vos suivis sont conservés. Avec un nouveau mot de passe, le cadenas change : il faudra le redonner aux animateurs, et les anciens liens ne s’ouvriront plus.', ok: 'Continuer', danger: true });
      if (!ok) return;
      db.key = null;
      save();
      render();
    },
    async wipe() {
      const ok = await confirmDialog({ title: 'Tout effacer ?', text: `${plural(db.items.length, 'suivi')}, ${plural(db.children.length, 'fiche')} enfant et le mot de passe seront supprimés de ce téléphone.`, ok: 'Tout effacer', danger: true });
      if (!ok) return;
      db = normalize({ installAsked: true });
      save();
      render();
    },
  };

  document.addEventListener('click', (ev) => {
    const el = ev.target.closest('[data-action]');
    if (!el || el.disabled) return;
    const fn = actions[el.dataset.action];
    if (fn) fn(el, ev);
  });
  document.addEventListener('input', (ev) => {
    if (ev.target.id === 'child-q') { ui.childQuery = ev.target.value; $('#child-list').innerHTML = childListHTML(); }
  });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && ev.target.id === 'pw') { ev.preventDefault(); actions.unlock($('[data-action="unlock"]')); }
    if (ev.key === 'Escape') closeSheet();
  });
  window.addEventListener('beforeinstallprompt', (ev) => { ev.preventDefault(); installPrompt = ev; });

  /* Lien ouvert directement (Android, ou navigateur) : on l'importe, puis on le retire
     de la barre d'adresse pour qu'il ne traîne pas dans l'historique. */
  async function takeHash() {
    if (!/^#e=/.test(location.hash)) return;
    const hash = location.hash;
    history.replaceState(null, '', location.pathname + location.search);
    if (!db.key) { pendingHash = hash; render(); return; }
    const r = await importText(hash);
    ui.tab = 'follow';
    render();
    reportImport(r);
  }
  window.addEventListener('hashchange', takeHash);

  renderShell();
  render();
  takeHash();
  if (!isStandalone() && !db.installAsked) openInstallDialog();

  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
})();
