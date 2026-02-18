/* ============================================================================
 GameZone — app.js
===============================================================================

Este archivo contiene la lógica de toda la web:

- Persistencia: localStorage (usuarios, sesión, comentarios, mensajes y récords)
- Autenticación: registro, login, logout, restablecimiento de contraseña
- Roles: usuario normal y administrador
- Comentarios: envío + moderación (aprobación/borrado)
- Contacto: formulario + bandeja en el panel admin
- Mini‑juegos: se abren en un modal y guardan récords (si hay sesión)

IMPORTANTE:
- Todo esto funciona sin servidor (solo front‑end). En un proyecto real,
  la autenticación/roles y el reseteo de contraseña se implementan en backend.
=============================================================================== */

(() => {
  "use strict";

  /* ==========================================================================
     1) CONFIGURACIÓN GENERAL
     - Aquí se agrupan ajustes que normalmente cambias con frecuencia.
  ========================================================================== */
  const CONFIG = {
    appName: "GameZone",            // Nombre de la aplicación (para textos/toasts).
    storagePrefix: "gz_",           // Prefijo de keys en localStorage.

    // Administrador “semilla” (se crea automáticamente si no existe).
    defaultAdmin: {
      name: "Admin",
      email: "admin@gamezone.local",
      password: "Admin123!",
      recovery: "adminRecovery"
    },

    // Reglas mínimas de contraseña.
    password: {
      minLen: 6
    },

    // Ajustes de mini‑juegos.
    games: {
      guessMax: 100,           // Máximo para “Adivina el número”.
      reactionMinDelay: 900,   // Delay mínimo (ms) para “Reflejos”.
      reactionMaxDelay: 2600,  // Delay máximo (ms) para “Reflejos”.
      whackSeconds: 20         // Duración de “Whack”.
    }
  };

  /* ==========================================================================
     2) HELPERS (UTILIDADES)
  ========================================================================== */

  // Selector corto (1 elemento).
  const $ = (sel, root = document) => root.querySelector(sel);

  // Selector corto (varios elementos → array).
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // Genera un ID simple (suficiente para front‑end).
  const uid = (prefix = "id") =>
    `${prefix}_${Math.random().toString(16).slice(2)}_${Date.now().toString(16)}`;

  // Fecha actual en ISO (útil para ordenar).
  const nowISO = () => new Date().toISOString();

  // Año actual (footer).
  const yearNow = () => new Date().getFullYear();

  // Convierte a email “normalizado”.
  const normalizeEmail = (email) => String(email || "").trim().toLowerCase();

  // Valida email de forma simple.
  const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  // Intenta parsear JSON de forma segura.
  const safeParse = (value, fallback) => {
    try { return JSON.parse(value); } catch { return fallback; }
  };

  // Baraja un array (Fisher–Yates).
  const shuffle = (arr) => {
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  };

  // Limita un número a un rango.
  const clamp = (n, min, max) => Math.max(min, Math.min(max, n));

  /* ==========================================================================
     3) STORAGE (localStorage con prefijo)
  ========================================================================== */
  const Keys = {
    users: "users",
    session: "session",
    comments: "comments",
    messages: "messages",
    ui: "ui",
    scores: "scores"
  };

  // Construye la key real que va a localStorage.
  const k = (name) => `${CONFIG.storagePrefix}${name}`;

  // API mínima para localStorage.
  const Store = {
    get(name, fallback) {
      const raw = localStorage.getItem(k(name));
      return raw ? safeParse(raw, fallback) : fallback;
    },
    set(name, value) {
      localStorage.setItem(k(name), JSON.stringify(value));
    },
    remove(name) {
      localStorage.removeItem(k(name));
    },
    update(name, fn, fallback) {
      const current = Store.get(name, fallback);
      const next = fn(current);
      Store.set(name, next);
      return next;
    }
  };

  /* ==========================================================================
     4) CRIPTO (HASH)
     - Se usa para no guardar contraseñas/frases en texto plano.
  ========================================================================== */

  // ArrayBuffer → hex (para guardar el hash).
  const bufferToHex = (buffer) =>
    Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

  // ¿Existe WebCrypto (SHA-256)?
  const HAS_WEBCRYPTO = !!(window.crypto && crypto.subtle && crypto.subtle.digest);

  // Hash de “emergencia” (no criptográfico). Solo se usa si no hay WebCrypto.
  const weakHash = (str) => {
    let h = 5381;
    for (let i = 0; i < str.length; i++) h = ((h << 5) + h) ^ str.charCodeAt(i);
    return (h >>> 0).toString(16).padStart(8, "0");
  };

  // Genera hex aleatorio.
  const randomHex = (bytes = 16) => {
    if (window.crypto && crypto.getRandomValues) {
      const arr = new Uint8Array(bytes);
      crypto.getRandomValues(arr);
      return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    let out = "";
    for (let i = 0; i < bytes; i++) out += Math.floor(Math.random() * 256).toString(16).padStart(2, "0");
    return out;
  };

  // SHA‑256 real (si hay WebCrypto); si no, weakHash.
  const sha256 = async (text) => {
    if (!HAS_WEBCRYPTO) return weakHash(text);
    const enc = new TextEncoder();
    const data = enc.encode(text);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return bufferToHex(hash);
  };

  // Hash con salt: SHA256(salt + ":" + secret).
  const saltedHash = async (secret, salt) => sha256(`${salt}:${secret}`);

  /* ==========================================================================
     5) AUTH (REGISTRO / LOGIN / ROLES / RESET)
  ========================================================================== */
  const Auth = {
    listUsers() {
      return Store.get(Keys.users, []);
    },

    saveUsers(users) {
      Store.set(Keys.users, users);
    },

    findByEmail(email) {
      const e = normalizeEmail(email);
      return Auth.listUsers().find((u) => u.email === e) || null;
    },

    findById(userId) {
      return Auth.listUsers().find((u) => u.id === userId) || null;
    },

    currentSession() {
      return Store.get(Keys.session, null);
    },

    currentUser() {
      const session = Auth.currentSession();
      if (!session) return null;

      const user = Auth.findById(session.userId);
      if (!user) {
        Auth.logout();
        return null;
      }
      return user;
    },

    async seedDefaultAdmin() {
      const users = Auth.listUsers();
      const adminEmail = normalizeEmail(CONFIG.defaultAdmin.email);

      const exists = users.some((u) => u.email === adminEmail);
      if (exists) return;

      const salt = randomHex(16);
      const recoverySalt = randomHex(16);

      const passHash = await saltedHash(CONFIG.defaultAdmin.password, salt);
      const recoveryHash = await saltedHash(CONFIG.defaultAdmin.recovery, recoverySalt);

      const admin = {
        id: uid("usr"),
        name: CONFIG.defaultAdmin.name,
        email: adminEmail,
        role: "admin",
        salt,
        passHash,
        recoverySalt,
        recoveryHash,
        createdAt: nowISO()
      };

      Auth.saveUsers([admin, ...users]);
    },

    async register({ name, email, password, recovery }) {
      const cleanName = String(name || "").trim();
      const cleanEmail = normalizeEmail(email);
      const cleanRecovery = String(recovery || "").trim();

      if (cleanName.length < 2) throw new Error("Escribe un nombre válido.");
      if (!isValidEmail(cleanEmail)) throw new Error("El email no parece válido.");
      if (String(password || "").length < CONFIG.password.minLen) {
        throw new Error(`La contraseña debe tener al menos ${CONFIG.password.minLen} caracteres.`);
      }
      if (cleanRecovery.length < 4) throw new Error("La frase de recuperación es demasiado corta.");
      if (Auth.findByEmail(cleanEmail)) throw new Error("Ese email ya está registrado.");

      const salt = randomHex(16);
      const recoverySalt = randomHex(16);

      const passHash = await saltedHash(password, salt);
      const recoveryHash = await saltedHash(cleanRecovery, recoverySalt);

      const user = {
        id: uid("usr"),
        name: cleanName,
        email: cleanEmail,
        role: "user",
        salt,
        passHash,
        recoverySalt,
        recoveryHash,
        createdAt: nowISO()
      };

      Auth.saveUsers([user, ...Auth.listUsers()]);
      return user;
    },

    async login(email, password) {
      const cleanEmail = normalizeEmail(email);
      const user = Auth.findByEmail(cleanEmail);

      if (!user) throw new Error("Email o contraseña incorrectos.");

      const hash = await saltedHash(password, user.salt);
      if (hash !== user.passHash) throw new Error("Email o contraseña incorrectos.");

      Store.set(Keys.session, { userId: user.id, createdAt: nowISO() });
      return user;
    },

    logout() {
      Store.remove(Keys.session);
    },

    async resetPassword({ email, recovery, newPassword }) {
      const cleanEmail = normalizeEmail(email);
      const user = Auth.findByEmail(cleanEmail);

      if (!user) throw new Error("No existe una cuenta con ese email.");

      const cleanRecovery = String(recovery || "").trim();
      const recoveryHash = await saltedHash(cleanRecovery, user.recoverySalt);

      if (recoveryHash !== user.recoveryHash) throw new Error("La frase de recuperación no coincide.");

      if (String(newPassword || "").length < CONFIG.password.minLen) {
        throw new Error(`La nueva contraseña debe tener al menos ${CONFIG.password.minLen} caracteres.`);
      }

      // Cambiamos salt + hash de contraseña.
      const newSalt = randomHex(16);
      const newHash = await saltedHash(newPassword, newSalt);

      const users = Auth.listUsers().map((u) =>
        u.id === user.id ? { ...u, salt: newSalt, passHash: newHash } : u
      );

      Auth.saveUsers(users);
      return true;
    }
  };

  /* ==========================================================================
     6) COMENTARIOS (ENVÍO + MODERACIÓN)
  ========================================================================== */
  const Comments = {
    listAll() {
      return Store.get(Keys.comments, []);
    },

    listPublic() {
      return Comments
        .listAll()
        .filter((c) => c.status === "approved")
        .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    },

    add({ author, text }) {
      const cleanText = String(text || "").trim();

      const comment = {
        id: uid("cmt"),
        authorId: author.id,
        authorName: author.name,
        text: cleanText,
        status: author.role === "admin" ? "approved" : "pending",
        createdAt: nowISO(),
        approvedAt: author.role === "admin" ? nowISO() : null
      };

      Store.update(Keys.comments, (all) => [comment, ...all], []);
      return comment;
    },

    approve(commentId) {
      Store.update(
        Keys.comments,
        (all) =>
          all.map((c) =>
            c.id === commentId ? { ...c, status: "approved", approvedAt: nowISO() } : c
          ),
        []
      );
    },

    remove(commentId) {
      Store.update(Keys.comments, (all) => all.filter((c) => c.id !== commentId), []);
    }
  };

  /* ==========================================================================
     7) MENSAJES (FORMULARIO DE CONTACTO)
  ========================================================================== */
  const Messages = {
    list() {
      return Store.get(Keys.messages, []).sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    },

    add({ name, email, subject, body }) {
      const msg = {
        id: uid("msg"),
        name: String(name || "").trim(),
        email: normalizeEmail(email),
        subject: String(subject || "").trim(),
        body: String(body || "").trim(),
        createdAt: nowISO()
      };

      Store.update(Keys.messages, (all) => [msg, ...all], []);
      return msg;
    }
  };

  /* ==========================================================================
     8) RÉCORDS (SCORES)
     - Se guardan por usuario. Si no hay sesión, se puede jugar igualmente,
       pero no se guarda el récord.
  ========================================================================== */
  const Scores = {
    getAll() {
      return Store.get(Keys.scores, {});
    },

    getUser(userId) {
      const all = Scores.getAll();
      return all[userId] || {};
    },

    updateUser(userId, updater) {
      return Store.update(
        Keys.scores,
        (all) => {
          const current = all[userId] || {};
          const next = updater(current);
          return { ...all, [userId]: next };
        },
        {}
      );
    },

    // “Más alto es mejor” (ej: racha, puntos).
    updateBestHigher(userId, gameId, key, value) {
      let improved = false;

      Scores.updateUser(userId, (userScores) => {
        const prev = userScores[gameId]?.[key];

        if (typeof prev !== "number" || value > prev) improved = true;

        return {
          ...userScores,
          [gameId]: {
            ...(userScores[gameId] || {}),
            [key]: typeof prev !== "number" ? value : Math.max(prev, value),
            updatedAt: nowISO()
          }
        };
      });

      return improved;
    },

    // “Más bajo es mejor” (ej: ms, intentos, movimientos).
    updateBestLower(userId, gameId, key, value) {
      let improved = false;

      Scores.updateUser(userId, (userScores) => {
        const prev = userScores[gameId]?.[key];

        if (typeof prev !== "number" || value < prev) improved = true;

        return {
          ...userScores,
          [gameId]: {
            ...(userScores[gameId] || {}),
            [key]: typeof prev !== "number" ? value : Math.min(prev, value),
            updatedAt: nowISO()
          }
        };
      });

      return improved;
    },

    formatMs(ms) {
      const s = (ms / 1000);
      return `${s.toFixed(3)}s`;
    },

    bestLabelForUser(userId) {
      const s = Scores.getUser(userId);

      // Prioridad: reacción → adivina → memory → whack → rps
      if (typeof s.reaction?.bestMs === "number") return `⚡ ${Scores.formatMs(s.reaction.bestMs)}`;
      if (typeof s.guess?.bestAttempts === "number") return `🎯 ${s.guess.bestAttempts} intentos`;
      if (typeof s.memory?.bestMoves === "number") return `🧠 ${s.memory.bestMoves} movimientos`;
      if (typeof s.whack?.bestScore === "number") return `👾 ${s.whack.bestScore} puntos`;
      if (typeof s.rps?.bestStreak === "number") return `🪨 ${s.rps.bestStreak} racha`;

      return "—";
    }
  };

  /* ==========================================================================
     9) UI (TOASTS, MODALES, NAV, TEMA, ANIMACIONES)
  ========================================================================== */
  const UI = {
    toastWrap() {
      let el = $("#toastWrap");
      if (!el) {
        el = document.createElement("div");
        el.id = "toastWrap";
        el.className = "toastWrap";
        document.body.appendChild(el);
      }
      return el;
    },

    toast({ title, message }) {
      const wrap = UI.toastWrap();

      const toast = document.createElement("div");
      toast.className = "toast";

      const b = document.createElement("b");
      b.textContent = title;

      const span = document.createElement("span");
      span.textContent = message;

      toast.appendChild(b);
      toast.appendChild(span);
      wrap.appendChild(toast);

      setTimeout(() => toast.remove(), 3500);
    },

    // Modal de confirmación (usa el modal HTML si existe, si no usa confirm()).
    confirm({ title, message, okText = "Aceptar", cancelText = "Cancelar" }) {
      return new Promise((resolve) => {
        const modal = $("#modal");
        const titleEl = $("#modalTitle");
        const textEl = $("#modalText");
        const btnOk = $("#modalOk");
        const btnCancel = $("#modalCancel");

        if (!modal || !titleEl || !textEl || !btnOk || !btnCancel) {
          resolve(confirm(message));
          return;
        }

        titleEl.textContent = title;
        textEl.textContent = message;
        btnOk.textContent = okText;
        btnCancel.textContent = cancelText;

        const close = (value) => {
          modal.classList.remove("is-open");
          modal.setAttribute("aria-hidden", "true");
          btnOk.onclick = null;
          btnCancel.onclick = null;
          resolve(value);
        };

        btnOk.onclick = () => close(true);
        btnCancel.onclick = () => close(false);

        modal.classList.add("is-open");
        modal.setAttribute("aria-hidden", "false");
      });
    },

    openGameModal({ title, subtitle, contentEl }) {
      const modal = $("#gameModal");
      const titleEl = $("#gameTitle");
      const subEl = $("#gameSubtitle");
      const content = $("#gameContent");

      if (!modal || !titleEl || !subEl || !content) return;

      titleEl.textContent = title;
      subEl.textContent = subtitle;

      content.innerHTML = "";
      content.appendChild(contentEl);

      modal.classList.add("is-open");
      modal.setAttribute("aria-hidden", "false");
    },

    closeGameModal() {
      const modal = $("#gameModal");
      const content = $("#gameContent");
      if (!modal) return;

      modal.classList.remove("is-open");
      modal.setAttribute("aria-hidden", "true");

      if (content) content.innerHTML = "";
    },

    updateNav() {
      const user = Auth.currentUser();

      // Elementos que dependen de sesión.
      const loggedInOnly = $$('[data-auth="loggedInOnly"]');
      const loggedOutOnly = $$('[data-auth="loggedOutOnly"]');

      loggedInOnly.forEach((el) => el.classList.toggle("is-hidden", !user));
      loggedOutOnly.forEach((el) => el.classList.toggle("is-hidden", !!user));

      // Elementos visibles solo para admins.
      const adminOnly = $$('[data-role="adminOnly"]');
      adminOnly.forEach((el) => el.classList.toggle("is-hidden", !(user && user.role === "admin")));

      // Badge “usuario”.
      const navUser = $("#navUser");
      if (navUser) {
        if (user) {
          navUser.textContent = user.role === "admin" ? `👤 ${user.name} • Admin` : `👤 ${user.name}`;
          navUser.classList.remove("is-hidden");
        } else {
          navUser.classList.add("is-hidden");
        }
      }
    },

    initTheme() {
      const ui = Store.get(Keys.ui, { theme: "dark" });
      document.documentElement.setAttribute("data-theme", ui.theme);

      const icon = $("#themeIcon");
      if (icon) icon.textContent = ui.theme === "light" ? "☀" : "☾";
    },

    toggleTheme() {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      const next = current === "dark" ? "light" : "dark";

      document.documentElement.setAttribute("data-theme", next);
      Store.update(Keys.ui, (ui) => ({ ...ui, theme: next }), { theme: "dark" });

      const icon = $("#themeIcon");
      if (icon) icon.textContent = next === "light" ? "☀" : "☾";
    },

    initReveal() {
      const els = $$(".reveal");
      if (!("IntersectionObserver" in window) || els.length === 0) {
        els.forEach((el) => el.classList.add("is-visible"));
        return;
      }

      const obs = new IntersectionObserver(
        (entries) => {
          entries.forEach((e) => {
            if (e.isIntersecting) {
              e.target.classList.add("is-visible");
              obs.unobserve(e.target);
            }
          });
        },
        { threshold: 0.12 }
      );

      els.forEach((el) => obs.observe(el));
    },

    initRipple() {
      document.addEventListener("click", (ev) => {
        const btn = ev.target.closest(".btn");
        if (!btn) return;

        const rect = btn.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = ev.clientX - rect.left - size / 2;
        const y = ev.clientY - rect.top - size / 2;

        const ripple = document.createElement("span");
        ripple.className = "ripple";
        ripple.style.width = ripple.style.height = `${size}px`;
        ripple.style.left = `${x}px`;
        ripple.style.top = `${y}px`;

        btn.appendChild(ripple);
        ripple.addEventListener("animationend", () => ripple.remove());
      });
    },

    toggleMenu() {
      const links = $("#navLinks");
      if (!links) return;
      links.classList.toggle("is-open");
    },

    bindCommon() {
      // Footer: año
      const y = $("#yearNow");
      if (y) y.textContent = String(yearNow());

      // Clicks globales por data-action
      document.addEventListener("click", async (ev) => {
        const el = ev.target.closest("[data-action]");
        if (!el) return;

        const action = el.getAttribute("data-action");

        if (action === "toggleTheme") UI.toggleTheme();

        if (action === "toggleMenu") UI.toggleMenu();

        if (action === "closeModal") {
          const modal = $("#modal");
          if (modal) {
            modal.classList.remove("is-open");
            modal.setAttribute("aria-hidden", "true");
          }
        }

        if (action === "closeGame") UI.closeGameModal();

        if (action === "logout") {
          const ok = await UI.confirm({
            title: "Cerrar sesión",
            message: "¿Seguro que quieres cerrar sesión?"
          });

          if (!ok) return;

          Auth.logout();
          UI.updateNav();
          UI.toast({ title: "Sesión cerrada", message: "Has salido correctamente." });

          // Si estamos en admin, volvemos al inicio
          if (document.body.dataset.page === "admin") window.location.href = "index.html";
        }

        if (action === "openGame") {
          const gameId = el.getAttribute("data-game");
          if (gameId) Games.open(gameId);
        }
      });

      // Cerrar modales con Escape
      document.addEventListener("keydown", (ev) => {
        if (ev.key !== "Escape") return;

        const confirmModal = $("#modal");
        if (confirmModal?.classList.contains("is-open")) {
          confirmModal.classList.remove("is-open");
          confirmModal.setAttribute("aria-hidden", "true");
        }

        const gameModal = $("#gameModal");
        if (gameModal?.classList.contains("is-open")) UI.closeGameModal();
      });

      // Cerrar el modal de juego si se hace click en el fondo oscuro
      const gameModal = $("#gameModal");
      if (gameModal) {
        gameModal.addEventListener("click", (ev) => {
          if (ev.target === gameModal) UI.closeGameModal();
        });
      }

      UI.initTheme();
      UI.initReveal();
      UI.initRipple();
      UI.updateNav();
    }
  };

  /* ==========================================================================
     10) MINI‑JUEGOS
     - Cada juego devuelve un elemento DOM listo para insertarse en el modal.
  ========================================================================== */
  const MiniGames = {
    // ----------------------------------------------------------
    // 10.1) Roca / Papel / Tijera
    // ----------------------------------------------------------
    rps(game, user) {
      const root = document.createElement("div");
      root.className = "gameWrap";

      let wins = 0;
      let losses = 0;
      let ties = 0;

      let streak = 0;
      let bestStreak = 0;

      const hud = document.createElement("div");
      hud.className = "gameHud";
      hud.innerHTML = `
        <span class="hudStat">🏆 Racha: <span id="rpsStreak">0</span></span>
        <span class="hudStat">✅ <span id="rpsWins">0</span></span>
        <span class="hudStat">➖ <span id="rpsTies">0</span></span>
        <span class="hudStat">❌ <span id="rpsLoss">0</span></span>
      `;

      const panel = document.createElement("div");
      panel.className = "gamePanel";
      panel.innerHTML = `
        <p class="muted" style="margin:0 0 12px;">
          Elige una opción. Si ganas, tu racha sube. Si pierdes, vuelve a 0.
        </p>

        <div class="rpsChoices">
          <button class="rpsBtn" data-pick="rock" type="button"><b>🪨</b><span>Piedra</span></button>
          <button class="rpsBtn" data-pick="paper" type="button"><b>📄</b><span>Papel</span></button>
          <button class="rpsBtn" data-pick="scissors" type="button"><b>✂️</b><span>Tijera</span></button>
        </div>

        <div class="spacer"></div>

        <div class="guessHint" id="rpsResult">Haz tu primera jugada.</div>
      `;

      const setHud = () => {
        $("#rpsWins", root).textContent = String(wins);
        $("#rpsTies", root).textContent = String(ties);
        $("#rpsLoss", root).textContent = String(losses);
        $("#rpsStreak", root).textContent = String(streak);
      };

      const winMap = {
        rock: "scissors",
        paper: "rock",
        scissors: "paper"
      };

      panel.addEventListener("click", (ev) => {
        const btn = ev.target.closest("[data-pick]");
        if (!btn) return;

        const pick = btn.getAttribute("data-pick");
        const cpu = ["rock", "paper", "scissors"][Math.floor(Math.random() * 3)];

        let result = "";
        if (pick === cpu) {
          ties++;
          streak = 0;
          result = `Empate 🤝 — ambos elegisteis ${labelPick(cpu)}.`;
        } else if (winMap[pick] === cpu) {
          wins++;
          streak++;
          bestStreak = Math.max(bestStreak, streak);
          result = `¡Ganaste! ✅ — ${labelPick(pick)} vence a ${labelPick(cpu)}.`;

          // Guardar mejor racha (si hay usuario).
          if (user) {
            const improved = Scores.updateBestHigher(user.id, "rps", "bestStreak", bestStreak);
            if (improved) {
              UI.toast({ title: "Nuevo récord", message: `Racha máxima: ${bestStreak}` });
              Home.updateBestStat();
            }
          }
        } else {
          losses++;
          streak = 0;
          result = `Perdiste ❌ — ${labelPick(cpu)} vence a ${labelPick(pick)}.`;
        }

        $("#rpsResult", root).textContent = result;
        setHud();
      });

      root.appendChild(hud);
      root.appendChild(panel);
      setHud();

      if (!user) {
        const tip = document.createElement("div");
        tip.className = "help";
        tip.textContent = "Inicia sesión para guardar tu mejor racha.";
        root.appendChild(tip);
      }

      return root;
    },

    // ----------------------------------------------------------
    // 10.2) Adivina el número
    // ----------------------------------------------------------
    guess(game, user) {
      const root = document.createElement("div");
      root.className = "gameWrap";

      let target = 1 + Math.floor(Math.random() * CONFIG.games.guessMax);
      let attempts = 0;
      let finished = false;

      const hud = document.createElement("div");
      hud.className = "gameHud";
      hud.innerHTML = `
        <span class="hudStat">🎯 Intentos: <span id="gAttempts">0</span></span>
        <span class="hudStat">🔢 1–${CONFIG.games.guessMax}</span>
      `;

      const panel = document.createElement("div");
      panel.className = "gamePanel";
      panel.innerHTML = `
        <p class="muted" style="margin:0 0 12px;">
          Adivina el número secreto. Te diré si es más alto o más bajo.
        </p>

        <div class="guessRow">
          <input class="input guessInput" id="gInput" type="number" min="1" max="${CONFIG.games.guessMax}" placeholder="Tu número..." />
          <button class="btn btn--primary" id="gBtn" type="button">Probar</button>
          <button class="btn btn--ghost" id="gNew" type="button">Nuevo</button>
        </div>

        <div class="spacer"></div>

        <div class="guessHint" id="gHint">Escribe un número y pulsa “Probar”.</div>
      `;

      const setAttempts = () => { $("#gAttempts", root).textContent = String(attempts); };

      const newGame = () => {
        target = 1 + Math.floor(Math.random() * CONFIG.games.guessMax);
        attempts = 0;
        finished = false;
        setAttempts();
        $("#gHint", root).textContent = "Nuevo número listo. ¡Suerte!";
        $("#gInput", root).value = "";
        $("#gInput", root).focus();
      };

      $("#gBtn", panel).addEventListener("click", () => {
        if (finished) return;

        const raw = $("#gInput", root).value;
        const n = Number(raw);

        if (!Number.isFinite(n)) {
          $("#gHint", root).textContent = "Escribe un número válido.";
          return;
        }

        const guess = clamp(Math.floor(n), 1, CONFIG.games.guessMax);
        attempts++;
        setAttempts();

        if (guess === target) {
          finished = true;
          $("#gHint", root).textContent = `¡Correcto! 🎉 Lo adivinaste en ${attempts} intentos.`;

          if (user) {
            const improved = Scores.updateBestLower(user.id, "guess", "bestAttempts", attempts);
            if (improved) {
              UI.toast({ title: "Nuevo récord", message: `Mejor marca: ${attempts} intentos` });
              Home.updateBestStat();
            }
          }
        } else if (guess < target) {
          $("#gHint", root).textContent = "Más alto ⬆️";
        } else {
          $("#gHint", root).textContent = "Más bajo ⬇️";
        }
      });

      $("#gNew", panel).addEventListener("click", newGame);

      root.appendChild(hud);
      root.appendChild(panel);

      if (!user) {
        const tip = document.createElement("div");
        tip.className = "help";
        tip.textContent = "Inicia sesión para guardar tu mejor número de intentos.";
        root.appendChild(tip);
      }

      return root;
    },

    // ----------------------------------------------------------
    // 10.3) Reflejos (reaction timer)
    // ----------------------------------------------------------
    reaction(game, user) {
      const root = document.createElement("div");
      root.className = "gameWrap";

      let state = "idle";     // idle | waiting | ready
      let startTime = 0;
      let timeoutId = 0;

      const hud = document.createElement("div");
      hud.className = "gameHud";
      hud.innerHTML = `
        <span class="hudStat">⚡ Mejor: <span id="rxBest">—</span></span>
      `;

      const panel = document.createElement("div");
      panel.className = "gamePanel";
      panel.innerHTML = `
        <div class="reactionArea" id="rxArea" role="button" tabindex="0">
          <div>
            <b id="rxTitle">Pulsa para empezar</b>
            <p id="rxText">Cuando cambie a “¡Ahora!”, haz click lo más rápido posible.</p>
          </div>
        </div>
      `;

      // Cargar mejor marca
      if (user) {
        const best = Scores.getUser(user.id)?.reaction?.bestMs;
        if (typeof best === "number") $("#rxBest", hud).textContent = Scores.formatMs(best);
      }

      const setArea = (cls, title, text) => {
        const area = $("#rxArea", panel);
        area.className = `reactionArea ${cls || ""}`.trim();
        $("#rxTitle", panel).textContent = title;
        $("#rxText", panel).textContent = text;
      };

      const reset = () => {
        state = "idle";
        startTime = 0;
        clearTimeout(timeoutId);
        timeoutId = 0;
        setArea("", "Pulsa para empezar", "Cuando cambie a “¡Ahora!”, haz click lo más rápido posible.");
      };

      const start = () => {
        state = "waiting";
        setArea("is-ready", "Espera…", "No pulses todavía.");
        const delay = CONFIG.games.reactionMinDelay +
          Math.floor(Math.random() * (CONFIG.games.reactionMaxDelay - CONFIG.games.reactionMinDelay));

        timeoutId = window.setTimeout(() => {
          state = "ready";
          startTime = performance.now();
          setArea("is-go", "¡Ahora!", "Haz click (o pulsa Enter).");
        }, delay);
      };

      const hit = () => {
        if (state === "idle") {
          start();
          return;
        }

        if (state === "waiting") {
          // Pulsó demasiado pronto
          UI.toast({ title: "Ups", message: "Demasiado pronto. Inténtalo otra vez." });
          reset();
          return;
        }

        if (state === "ready") {
          const ms = Math.round(performance.now() - startTime);
          UI.toast({ title: "Tiempo", message: `${Scores.formatMs(ms)}` });

          setArea("", "¡Bien!", `Tu tiempo: ${Scores.formatMs(ms)}. Pulsa para jugar otra vez.`);
          state = "idle";

          if (user) {
            const improved = Scores.updateBestLower(user.id, "reaction", "bestMs", ms);
            if (improved) {
              $("#rxBest", hud).textContent = Scores.formatMs(ms);
              UI.toast({ title: "Nuevo récord", message: `Mejor tiempo: ${Scores.formatMs(ms)}` });
              Home.updateBestStat();
            }
          }
        }
      };

      const area = $("#rxArea", panel);
      area.addEventListener("click", hit);
      area.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          hit();
        }
      });

      root.appendChild(hud);
      root.appendChild(panel);

      if (!user) {
        const tip = document.createElement("div");
        tip.className = "help";
        tip.textContent = "Inicia sesión para guardar tu mejor tiempo de reacción.";
        root.appendChild(tip);
      }

      return root;
    },

    // ----------------------------------------------------------
    // 10.4) Memory (parejas)
    // ----------------------------------------------------------
    memory(game, user) {
      const root = document.createElement("div");
      root.className = "gameWrap";

      const icons = ["🍓","🍋","🍇","🍒","🥝","🍑","🍉","🍍"];
      const deck = shuffle([...icons, ...icons]);

      let first = null;
      let second = null;
      let lock = false;

      let moves = 0;
      let matched = 0;

      const hud = document.createElement("div");
      hud.className = "gameHud";
      hud.innerHTML = `
        <span class="hudStat">🧠 Movimientos: <span id="mMoves">0</span></span>
        <span class="hudStat">✅ Parejas: <span id="mPairs">0</span> / ${icons.length}</span>
        <span class="hudStat">🏆 Mejor: <span id="mBest">—</span></span>
      `;

      if (user) {
        const best = Scores.getUser(user.id)?.memory?.bestMoves;
        if (typeof best === "number") $("#mBest", hud).textContent = String(best);
      }

      const panel = document.createElement("div");
      panel.className = "gamePanel";

      const grid = document.createElement("div");
      grid.className = "memoryGrid";

      const setHud = () => {
        $("#mMoves", hud).textContent = String(moves);
        $("#mPairs", hud).textContent = String(matched);
      };

      const makeCard = (icon, idx) => {
        const card = document.createElement("button");
        card.type = "button";
        card.className = "memCard";
        card.setAttribute("data-icon", icon);
        card.setAttribute("data-idx", String(idx));
        card.innerHTML = `
          <div class="memInner">
            <div class="memFace memFront">?</div>
            <div class="memFace memBack">${icon}</div>
          </div>
        `;
        return card;
      };

      deck.forEach((icon, idx) => grid.appendChild(makeCard(icon, idx)));

      const resetPick = () => {
        first = null;
        second = null;
        lock = false;
      };

      const checkWin = () => {
        if (matched !== icons.length) return;

        UI.toast({ title: "¡Completado!", message: `Terminaste en ${moves} movimientos.` });

        if (user) {
          const improved = Scores.updateBestLower(user.id, "memory", "bestMoves", moves);
          if (improved) {
            $("#mBest", hud).textContent = String(moves);
            UI.toast({ title: "Nuevo récord", message: `Mejor marca: ${moves} movimientos` });
            Home.updateBestStat();
          }
        }
      };

      grid.addEventListener("click", (ev) => {
        const card = ev.target.closest(".memCard");
        if (!card) return;

        if (lock) return;
        if (card.classList.contains("is-matched")) return;
        if (card === first) return;

        card.classList.add("is-flipped");

        if (!first) {
          first = card;
          return;
        }

        second = card;
        lock = true;
        moves++;
        setHud();

        const a = first.getAttribute("data-icon");
        const b = second.getAttribute("data-icon");

        if (a === b) {
          first.classList.add("is-matched");
          second.classList.add("is-matched");
          matched++;
          setHud();
          resetPick();
          checkWin();
          return;
        }

        // No coincide → vuelta atrás
        window.setTimeout(() => {
          first.classList.remove("is-flipped");
          second.classList.remove("is-flipped");
          resetPick();
        }, 520);
      });

      const row = document.createElement("div");
      row.className = "btnRow";
      row.innerHTML = `
        <button class="btn btn--ghost" type="button" id="mReset">Reiniciar</button>
      `;

      $("#mReset", row).addEventListener("click", () => {
        // Reinicio simple: reabrimos el juego desde cero
        Games.open("memory");
      });

      panel.appendChild(grid);
      panel.appendChild(document.createElement("div")).className = "spacer";
      panel.appendChild(row);

      root.appendChild(hud);
      root.appendChild(panel);
      setHud();

      if (!user) {
        const tip = document.createElement("div");
        tip.className = "help";
        tip.textContent = "Inicia sesión para guardar tu mejor número de movimientos.";
        root.appendChild(tip);
      }

      return root;
    },

    // ----------------------------------------------------------
    // 10.5) Whack (golpea al “pixel”)
    // ----------------------------------------------------------
    whack(game, user) {
      const root = document.createElement("div");
      root.className = "gameWrap";

      let score = 0;
      let bestScore = 0;
      let timeLeft = CONFIG.games.whackSeconds;

      let running = false;
      let timerId = 0;
      let activeIndex = -1;

      const hud = document.createElement("div");
      hud.className = "gameHud";
      hud.innerHTML = `
        <span class="hudStat">👾 Puntos: <span id="wScore">0</span></span>
        <span class="hudStat">⏱️ Tiempo: <span id="wTime">${CONFIG.games.whackSeconds}</span>s</span>
        <span class="hudStat">🏆 Mejor: <span id="wBest">—</span></span>
      `;

      if (user) {
        const best = Scores.getUser(user.id)?.whack?.bestScore;
        if (typeof best === "number") {
          bestScore = best;
          $("#wBest", hud).textContent = String(best);
        }
      }

      const panel = document.createElement("div");
      panel.className = "gamePanel";
      panel.innerHTML = `
        <p class="muted" style="margin:0 0 12px;">
          Haz click en el “pixel” brillante tantas veces como puedas antes de que acabe el tiempo.
        </p>

        <div class="whackGrid" id="wGrid"></div>

        <div class="spacer"></div>

        <div class="btnRow">
          <button class="btn btn--primary" id="wStart" type="button">Empezar</button>
          <button class="btn btn--ghost" id="wStop" type="button">Parar</button>
        </div>
      `;

      const grid = $("#wGrid", panel);

      // Crear 9 celdas
      for (let i = 0; i < 9; i++) {
        const cell = document.createElement("button");
        cell.type = "button";
        cell.className = "whackCell";
        cell.setAttribute("data-idx", String(i));
        cell.innerHTML = `<span class="whackDot"></span>`;
        grid.appendChild(cell);
      }

      const setHud = () => {
        $("#wScore", hud).textContent = String(score);
        $("#wTime", hud).textContent = String(timeLeft);
        $("#wBest", hud).textContent = user ? String(bestScore) : "—";
      };

      const clearActive = () => {
        if (activeIndex < 0) return;
        const active = grid.querySelector(`.whackCell[data-idx="${activeIndex}"]`);
        active?.classList.remove("is-active");
        activeIndex = -1;
      };

      const pickNew = () => {
        clearActive();
        activeIndex = Math.floor(Math.random() * 9);
        const next = grid.querySelector(`.whackCell[data-idx="${activeIndex}"]`);
        next?.classList.add("is-active");
      };

      const stop = () => {
        running = false;
        clearInterval(timerId);
        timerId = 0;
        clearActive();
      };

      const finish = () => {
        stop();
        UI.toast({ title: "Fin", message: `Puntuación: ${score}` });

        if (user) {
          const improved = Scores.updateBestHigher(user.id, "whack", "bestScore", score);
          if (improved) {
            bestScore = Math.max(bestScore, score);
            UI.toast({ title: "Nuevo récord", message: `Mejor puntuación: ${bestScore}` });
            Home.updateBestStat();
          }
        }
      };

      const start = () => {
        score = 0;
        timeLeft = CONFIG.games.whackSeconds;
        running = true;
        setHud();
        pickNew();

        clearInterval(timerId);
        timerId = window.setInterval(() => {
          timeLeft--;
          setHud();

          if (timeLeft <= 0) finish();
          else pickNew();
        }, 1000);
      };

      grid.addEventListener("click", (ev) => {
        const cell = ev.target.closest(".whackCell");
        if (!cell) return;
        if (!running) return;

        const idx = Number(cell.getAttribute("data-idx"));
        if (idx !== activeIndex) return;

        score++;
        setHud();
        pickNew();
      });

      $("#wStart", panel).addEventListener("click", start);
      $("#wStop", panel).addEventListener("click", () => {
        stop();
        UI.toast({ title: "Pausado", message: "Pulsa “Empezar” para reiniciar." });
      });

      root.appendChild(hud);
      root.appendChild(panel);
      setHud();

      if (!user) {
        const tip = document.createElement("div");
        tip.className = "help";
        tip.textContent = "Inicia sesión para guardar tu mejor puntuación.";
        root.appendChild(tip);
      }

      return root;
    }
  };

  /* ==========================================================================
     11) JUEGOS (CATÁLOGO + APERTURA DEL MODAL)
  ========================================================================== */
  const Games = {
    data: [
      {
        id: "reaction",
        title: "Reflejos",
        subtitle: "¿Qué tan rápido reaccionas?",
        desc: "Espera la señal y haz click en el momento exacto. Cuanto más bajo, mejor.",
        icon: "⚡",
        tag: "SPEED",
        meta: ["1 jugador", "Rápido", "ms"],
        g1: "#22c1c3",
        g2: "#8a5cff"
      },
      {
        id: "guess",
        title: "Adivina el número",
        subtitle: "Del 1 al 100",
        desc: "Encuentra el número secreto con las pistas “más alto / más bajo”.",
        icon: "🎯",
        tag: "PUZZLE",
        meta: ["1 jugador", "Lógica", "intent."],
        g1: "#8a5cff",
        g2: "#ff4d6d"
      },
      {
        id: "memory",
        title: "Memory",
        subtitle: "Encuentra las parejas",
        desc: "Voltea cartas y empareja símbolos. Menos movimientos = mejor marca.",
        icon: "🧠",
        tag: "MEMORY",
        meta: ["1 jugador", "Parejas", "moves"],
        g1: "#ff4d6d",
        g2: "#22c1c3"
      },
      {
        id: "whack",
        title: "Whack",
        subtitle: "Golpea al pixel",
        desc: "Haz click en el objetivo brillante tantas veces como puedas antes de que acabe el tiempo.",
        icon: "👾",
        tag: "ARCADE",
        meta: ["1 jugador", "20s", "score"],
        g1: "#22c1c3",
        g2: "#2dd4bf"
      },
      {
        id: "rps",
        title: "Piedra, papel, tijera",
        subtitle: "Clásico de toda la vida",
        desc: "Gana rondas y construye una racha. ¿Cuánto aguantas sin fallar?",
        icon: "🪨",
        tag: "CLÁSICO",
        meta: ["1 jugador", "Racha", "wins"],
        g1: "#8a5cff",
        g2: "#22c1c3"
      }
    ],

    get(gameId) {
      return Games.data.find((g) => g.id === gameId) || null;
    },

    open(gameId) {
      const game = Games.get(gameId);
      if (!game) {
        UI.toast({ title: "Error", message: "Juego no encontrado." });
        return;
      }

      const user = Auth.currentUser();

      // Elegimos la función de MiniGames en base al id
      const builder = MiniGames[game.id];
      if (typeof builder !== "function") {
        UI.toast({ title: "Error", message: "Este juego aún no está disponible." });
        return;
      }

      const contentEl = builder(game, user);

      UI.openGameModal({
        title: game.title,
        subtitle: game.subtitle,
        contentEl
      });
    }
  };

  /* ==========================================================================
     12) HOME (index.html)
  ========================================================================== */
  const Home = {
    renderStats() {
      const statUsers = $("#statUsers");
      const statComments = $("#statComments");
      const statBest = $("#statBest");

      const users = Auth.listUsers();
      const publicComments = Comments.listPublic();
      const current = Auth.currentUser();

      if (statUsers) statUsers.textContent = String(users.length);
      if (statComments) statComments.textContent = String(publicComments.length);

      if (statBest) {
        statBest.textContent = current ? Scores.bestLabelForUser(current.id) : "—";
      }
    },

    updateBestStat() {
      const current = Auth.currentUser();
      const statBest = $("#statBest");
      if (!statBest) return;
      statBest.textContent = current ? Scores.bestLabelForUser(current.id) : "—";
    },

    renderGames() {
      const grid = $("#gamesGrid");
      if (!grid) return;

      grid.innerHTML = "";

      Games.data.forEach((g) => {
        const card = document.createElement("article");
        card.className = "gameCard reveal";
        card.style.setProperty("--g1", g.g1);
        card.style.setProperty("--g2", g.g2);

        card.innerHTML = `
          <div class="gameCard__art">
            <div class="gameCard__icon">${g.icon}</div>
            <div class="gameCard__tag">${escapeHtml(g.tag)}</div>
          </div>

          <div class="gameCard__body">
            <h3 class="gameCard__title">${escapeHtml(g.title)}</h3>
            <p class="gameCard__desc">${escapeHtml(g.desc)}</p>

            <div class="gameCard__meta">
              ${g.meta.map((m) => `<span class="pillMeta">${escapeHtml(m)}</span>`).join("")}
            </div>

            <div class="gameCard__actions">
              <button class="btn btn--primary" data-action="openGame" data-game="${escapeHtml(g.id)}" type="button">
                Jugar
              </button>
              <button class="btn btn--ghost" data-action="openGame" data-game="${escapeHtml(g.id)}" type="button">
                Ver
              </button>
            </div>
          </div>
        `;

        grid.appendChild(card);
      });

      UI.initReveal();
    },

    renderComments() {
      const list = $("#commentsList");
      if (!list) return;

      const comments = Comments.listPublic();

      if (comments.length === 0) {
        list.innerHTML = `<div class="card card--pad muted">Aún no hay comentarios. ¡Sé el primero!</div>`;
        return;
      }

      list.innerHTML = "";

      comments.forEach((c) => {
        const item = document.createElement("div");
        item.className = "card comment reveal";

        item.innerHTML = `
          <div class="comment__top">
            <span class="comment__author">${escapeHtml(c.authorName)}</span>
            <span class="comment__date">${formatDate(c.createdAt)}</span>
          </div>
          <p class="comment__text">${escapeHtml(c.text)}</p>
        `;

        list.appendChild(item);
      });

      UI.initReveal();
    },

    bindCommentForm() {
      const form = $("#commentForm");
      if (!form) return;

      const help = $("#commentHelp");
      const loginBtn = $("#commentLoginBtn");
      const textarea = $("#commentText");

      const user = Auth.currentUser();

      // Sin sesión → bloquear textarea.
      if (!user) {
        if (textarea) textarea.disabled = true;
        if (help) help.textContent = "Para comentar necesitas iniciar sesión.";
        if (loginBtn) loginBtn.classList.remove("is-hidden");
        return;
      }

      // Con sesión → permitir comentar.
      if (textarea) textarea.disabled = false;
      if (loginBtn) loginBtn.classList.add("is-hidden");

      // Texto informativo.
      if (help) {
        help.textContent = user.role === "admin"
          ? "Tu comentario se publica al instante."
          : "Tu comentario se publicará tras revisión.";
      }

      form.addEventListener("submit", (ev) => {
        ev.preventDefault();

        const text = textarea?.value || "";
        if (text.trim().length < 2) {
          UI.toast({ title: "Error", message: "Escribe un comentario más largo." });
          return;
        }

        const c = Comments.add({ author: user, text });

        if (textarea) textarea.value = "";

        UI.toast({
          title: "Comentario enviado",
          message: c.status === "approved" ? "Publicado." : "Queda pendiente de revisión."
        });

        Home.renderComments();
        Home.renderStats();
      });
    },

    bindContactForm() {
      const form = $("#contactForm");
      if (!form) return;

      form.addEventListener("submit", (ev) => {
        ev.preventDefault();

        const name = $("#cName")?.value || "";
        const email = $("#cEmail")?.value || "";
        const subject = $("#cSubject")?.value || "";
        const body = $("#cMessage")?.value || "";

        if (!name.trim() || !subject.trim() || !body.trim()) {
          UI.toast({ title: "Error", message: "Completa todos los campos." });
          return;
        }
        if (!isValidEmail(normalizeEmail(email))) {
          UI.toast({ title: "Error", message: "El email no parece válido." });
          return;
        }

        Messages.add({ name, email, subject, body });
        form.reset();

        UI.toast({ title: "Mensaje enviado", message: "Gracias. Te responderemos lo antes posible." });
      });
    }
  };

  /* ==========================================================================
     13) ADMIN (admin.html)
  ========================================================================== */
  const Admin = {
    bindTabs() {
      $$("[data-tab]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const tab = btn.getAttribute("data-tab");

          $("#tabUsers")?.classList.add("is-hidden");
          $("#tabComments")?.classList.add("is-hidden");
          $("#tabMessages")?.classList.add("is-hidden");

          if (tab === "users") $("#tabUsers")?.classList.remove("is-hidden");
          if (tab === "comments") $("#tabComments")?.classList.remove("is-hidden");
          if (tab === "messages") $("#tabMessages")?.classList.remove("is-hidden");
        });
      });
    },

    renderAll() {
      Admin.renderUsers();
      Admin.renderComments();
      Admin.renderMessages();
    },

    renderUsers() {
      const tbody = $("#usersTbody");
      if (!tbody) return;

      const users = Auth.listUsers();
      const current = Auth.currentUser();

      tbody.innerHTML = "";

      users.forEach((u) => {
        const tr = document.createElement("tr");

        const canDelete = current && u.id !== current.id;
        const canChangeRole = current && u.id !== current.id;

        tr.innerHTML = `
          <td>${escapeHtml(u.name)}</td>
          <td>${escapeHtml(u.email)}</td>
          <td><b>${escapeHtml(u.role)}</b></td>
          <td style="display:flex; gap:8px; flex-wrap:wrap;">
            ${
              canChangeRole
                ? `<button class="btn btn--ghost" data-admin="toggleRole" data-user-id="${u.id}" type="button">
                     ${u.role === "admin" ? "Hacer usuario" : "Hacer admin"}
                   </button>`
                : `<span class="muted">—</span>`
            }
            ${
              canDelete
                ? `<button class="btn btn--ghost" data-admin="deleteUser" data-user-id="${u.id}" type="button">Borrar</button>`
                : ""
            }
          </td>
        `;

        tbody.appendChild(tr);
      });
    },

    renderComments() {
      const tbody = $("#commentsTbody");
      if (!tbody) return;

      const all = Comments.listAll().sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
      tbody.innerHTML = "";

      if (all.length === 0) {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td colspan="5" class="muted">No hay comentarios.</td>`;
        tbody.appendChild(tr);
        return;
      }

      all.forEach((c) => {
        const tr = document.createElement("tr");
        const status = c.status === "approved" ? "Aprobado" : "Pendiente";

        tr.innerHTML = `
          <td>${escapeHtml(c.authorName)}</td>
          <td><small>${escapeHtml(formatDate(c.createdAt))}</small></td>
          <td><b>${escapeHtml(status)}</b></td>
          <td>${escapeHtml(c.text).slice(0, 120)}${c.text.length > 120 ? "…" : ""}</td>
          <td style="display:flex; gap:8px; flex-wrap:wrap;">
            ${
              c.status !== "approved"
                ? `<button class="btn btn--primary" data-admin="approveComment" data-comment-id="${c.id}" type="button">Aprobar</button>`
                : ""
            }
            <button class="btn btn--ghost" data-admin="deleteComment" data-comment-id="${c.id}" type="button">Borrar</button>
          </td>
        `;

        tbody.appendChild(tr);
      });
    },

    renderMessages() {
      const tbody = $("#messagesTbody");
      if (!tbody) return;

      const all = Messages.list();
      tbody.innerHTML = "";

      if (all.length === 0) {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td colspan="5" class="muted">No hay mensajes.</td>`;
        tbody.appendChild(tr);
        return;
      }

      all.forEach((m) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${escapeHtml(m.name)}</td>
          <td>${escapeHtml(m.email)}</td>
          <td>${escapeHtml(m.subject)}</td>
          <td>${escapeHtml(m.body).slice(0, 140)}${m.body.length > 140 ? "…" : ""}</td>
          <td><small>${escapeHtml(formatDate(m.createdAt))}</small></td>
        `;
        tbody.appendChild(tr);
      });
    },

    bindActions() {
      document.addEventListener("click", async (ev) => {
        const btn = ev.target.closest("[data-admin]");
        if (!btn) return;

        const action = btn.getAttribute("data-admin");

        // ---------------- Cambiar rol ----------------
        if (action === "toggleRole") {
          const userId = btn.getAttribute("data-user-id");
          if (!userId) return;

          const u = Auth.findById(userId);
          if (!u) return;

          const ok = await UI.confirm({
            title: "Cambiar rol",
            message: `¿Cambiar rol de "${u.name}" a ${u.role === "admin" ? "user" : "admin"}?`
          });
          if (!ok) return;

          const users = Auth.listUsers().map((x) =>
            x.id === userId ? { ...x, role: x.role === "admin" ? "user" : "admin" } : x
          );
          Auth.saveUsers(users);

          UI.toast({ title: "Listo", message: "Rol actualizado." });
          Admin.renderUsers();
          UI.updateNav();
        }

        // ---------------- Borrar usuario ----------------
        if (action === "deleteUser") {
          const userId = btn.getAttribute("data-user-id");
          if (!userId) return;

          const u = Auth.findById(userId);
          if (!u) return;

          const ok = await UI.confirm({
            title: "Borrar usuario",
            message: `¿Seguro que quieres borrar a "${u.name}"?`
          });
          if (!ok) return;

          const users = Auth.listUsers().filter((x) => x.id !== userId);
          Auth.saveUsers(users);

          UI.toast({ title: "Eliminado", message: "Usuario borrado." });
          Admin.renderUsers();
        }

        // ---------------- Aprobar comentario ----------------
        if (action === "approveComment") {
          const commentId = btn.getAttribute("data-comment-id");
          if (!commentId) return;

          Comments.approve(commentId);
          UI.toast({ title: "Aprobado", message: "El comentario ya es público." });
          Admin.renderComments();
        }

        // ---------------- Borrar comentario ----------------
        if (action === "deleteComment") {
          const commentId = btn.getAttribute("data-comment-id");
          if (!commentId) return;

          const ok = await UI.confirm({
            title: "Borrar comentario",
            message: "¿Seguro que quieres borrar este comentario?"
          });
          if (!ok) return;

          Comments.remove(commentId);
          UI.toast({ title: "Borrado", message: "Comentario eliminado." });
          Admin.renderComments();
        }
      });
    }
  };

  /* ==========================================================================
     14) HELPERS EXTRA (escape + fecha)
  ========================================================================== */

  // Escape para evitar que el texto del usuario se interprete como HTML.
  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Formato de fecha bonito.
  function formatDate(iso) {
    try {
      const d = new Date(iso);
      return d.toLocaleString("es-ES", { dateStyle: "medium", timeStyle: "short" });
    } catch {
      return iso;
    }
  }

  // Etiquetas humanas para RPS.
  function labelPick(p) {
    if (p === "rock") return "piedra 🪨";
    if (p === "paper") return "papel 📄";
    return "tijera ✂️";
  }

  /* ==========================================================================
     15) PÁGINAS (CONTROLADORES)
     - Cada <body data-page="..."> activa una función aquí.
  ========================================================================== */
  const Pages = {
    home() {
      Home.renderStats();
      Home.renderGames();
      Home.renderComments();
      Home.bindCommentForm();
      Home.bindContactForm();
    },

    login() {
      const form = $("#loginForm");
      if (!form) return;

      form.addEventListener("submit", async (ev) => {
        ev.preventDefault();

        const email = $("#loginEmail")?.value || "";
        const password = $("#loginPassword")?.value || "";

        try {
          await Auth.login(email, password);
          UI.updateNav();
          UI.toast({ title: "Bienvenido", message: "Has iniciado sesión." });
          window.location.href = "index.html";
        } catch (err) {
          UI.toast({ title: "Error", message: err.message });
        }
      });
    },

    register() {
      const form = $("#registerForm");
      if (!form) return;

      form.addEventListener("submit", async (ev) => {
        ev.preventDefault();

        const name = $("#regName")?.value || "";
        const email = $("#regEmail")?.value || "";
        const pass1 = $("#regPassword")?.value || "";
        const pass2 = $("#regPassword2")?.value || "";
        const recovery = $("#regRecovery")?.value || "";

        if (pass1 !== pass2) {
          UI.toast({ title: "Error", message: "Las contraseñas no coinciden." });
          return;
        }

        try {
          await Auth.register({ name, email, password: pass1, recovery });
          UI.toast({ title: "Cuenta creada", message: "Ahora puedes iniciar sesión." });
          window.location.href = "login.html";
        } catch (err) {
          UI.toast({ title: "Error", message: err.message });
        }
      });
    },

    reset() {
      const form = $("#resetForm");
      if (!form) return;

      form.addEventListener("submit", async (ev) => {
        ev.preventDefault();

        const email = $("#resetEmail")?.value || "";
        const recovery = $("#resetRecovery")?.value || "";
        const pass1 = $("#resetPassword")?.value || "";
        const pass2 = $("#resetPassword2")?.value || "";

        if (pass1 !== pass2) {
          UI.toast({ title: "Error", message: "Las contraseñas no coinciden." });
          return;
        }

        try {
          await Auth.resetPassword({ email, recovery, newPassword: pass1 });
          UI.toast({ title: "Contraseña cambiada", message: "Ya puedes iniciar sesión." });
          window.location.href = "login.html";
        } catch (err) {
          UI.toast({ title: "Error", message: err.message });
        }
      });
    },

    admin() {
      const user = Auth.currentUser();

      // Guardia: solo admins.
      if (!user || user.role !== "admin") {
        UI.toast({ title: "Acceso denegado", message: "No tienes permisos para entrar aquí." });
        window.location.href = "index.html";
        return;
      }

      Admin.bindTabs();
      Admin.renderAll();
      Admin.bindActions();
    }
  };

  /* ==========================================================================
     16) INIT
  ========================================================================== */
  document.addEventListener("DOMContentLoaded", async () => {
    await Auth.seedDefaultAdmin();
    UI.bindCommon();

    const page = document.body.dataset.page;
    if (page && Pages[page]) Pages[page]();
  });
})();
