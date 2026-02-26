/* ============================================================
   SISTEMA INDICADORES PARACEL — app.js v1.0.0
   Módulos: Config, API, Auth, Crypto, Router, Form, Admin, UI
   ============================================================ */

// ── CONFIG ────────────────────────────────────────────────────
const CONFIG = {
  // ⚠ Reemplazar esta URL con la de tu Web App de Apps Script
  API_URL: 'https://script.google.com/macros/s/AKfycbxXJNHd12sCozM9-pfgwf3W8gYOJ2IcdeUxpYjawRCajJ8YKbkTI6h2_nm2FzmfToy9tA/exec',
  TOKEN_KEY: 'paracel_token',
  SESSION_KEY: 'paracel_session',
  MODULOS_LABELS: {
    TH: 'Talento Humano',
    SSL: 'Seguridad y Salud Laboral',
    REDES: 'Redes Sociales',
    QCYS: 'Quejas, Consultas y Sugerencias',
    PROGRAMAS: 'Programas Sociales'
  }
};

// (SHA-256 se realiza en el servidor para evitar doble-hash)

// ── API CLIENT ────────────────────────────────────────────────
const API = (() => {
  function getToken() {
    return sessionStorage.getItem(CONFIG.TOKEN_KEY);
  }

  async function request(action, method = 'GET', body = null) {
    const token = getToken();
    const url = new URL(CONFIG.API_URL);
    url.searchParams.set('action', action);
    if (token) url.searchParams.set('t', token);

    // IMPORTANTE: Usar text/plain evita preflight CORS (OPTIONS)
    // que Apps Script no soporta.
    const opts = { method, redirect: 'follow' };
    if (method === 'POST' && body) {
      if (token) body.__token = token;
      opts.headers = { 'Content-Type': 'text/plain;charset=UTF-8' };
      opts.body = JSON.stringify(body);
    }

    const resp = await fetch(url.toString(), opts);
    const data = await resp.json();

    const status = data.__status || 200;
    if (status >= 400) {
      const err = new Error(data.error || 'Error desconocido');
      err.status = status;
      throw err;
    }
    return data;
  }

  async function get(action, params = {}) {
    const token = getToken();
    const url = new URL(CONFIG.API_URL);
    url.searchParams.set('action', action);
    if (token) url.searchParams.set('t', token);
    Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
    const resp = await fetch(url.toString(), { redirect: 'follow' });
    const data = await resp.json();
    const status = data.__status || 200;
    if (status >= 400) {
      const err = new Error(data.error || 'Error desconocido');
      err.status = status;
      throw err;
    }
    return data;
  }

  return {
    login: (usuario, password) => request('login', 'POST', { usuario, password }),
    me: () => get('me'),
    getPeriodos: () => get('periodos'),
    getPeriodoActivo: () => get('periodoActivo'),
    getIndicadores: (modulo) => get('indicadores', { modulo }),
    getCapturas: (periodo, modulo) => get('capturas', { periodo, modulo }),
    upsertCaptura: (data) => request('upsertCaptura', 'POST', data),
    setPeriodoEstado: (data) => request('setPeriodoEstado', 'POST', data),
    controlCarga: (periodo) => get('controlCarga', periodo ? { periodo } : {}),
    exportCSV: (periodo) => get('exportCSV', { periodo }),
  };
})();

// ── STATE: sesión y estado de la app ─────────────────────────
const State = (() => {
  let session = null; // { usuario, nombre, rol, modulos_permitidos, exp }
  let periodoActivo = null;
  let activeModulo = null;
  let indicadoresCache = {}; // modulo → array
  let capturasCache = {}; // `${periodo}|${modulo}` → array

  function saveSession(sess, token) {
    session = sess;
    sessionStorage.setItem(CONFIG.TOKEN_KEY, token);
    sessionStorage.setItem(CONFIG.SESSION_KEY, JSON.stringify(sess));
  }

  function clearSession() {
    session = null;
    sessionStorage.removeItem(CONFIG.TOKEN_KEY);
    sessionStorage.removeItem(CONFIG.SESSION_KEY);
    indicadoresCache = {};
    capturasCache = {};
  }

  function getSession() {
    if (session) return session;
    try {
      const stored = sessionStorage.getItem(CONFIG.SESSION_KEY);
      if (stored) { session = JSON.parse(stored); return session; }
    } catch (_) { }
    return null;
  }

  function isExpired() {
    const sess = getSession();
    if (!sess || !sess.exp) return true;
    return Date.now() > sess.exp;
  }

  return {
    saveSession, clearSession, getSession, isExpired,
    get periodoActivo() { return periodoActivo; },
    set periodoActivo(v) { periodoActivo = v; },
    get activeModulo() { return activeModulo; },
    set activeModulo(v) { activeModulo = v; },
    indicadoresCache, capturasCache
  };
})();

// ── UI HELPERS ────────────────────────────────────────────────
const UI = (() => {
  function show(id) { const el = document.getElementById(id); if (el) el.classList.remove('hidden'); }
  function hide(id) { const el = document.getElementById(id); if (el) el.classList.add('hidden'); }
  function toggle(id, cond) { cond ? show(id) : hide(id); }

  function setHtml(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  }

  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function showLoading() { show('loading-overlay'); }
  function hideLoading() { hide('loading-overlay'); }

  // Toast notifications
  let toastTimer;
  function toast(msg, type = 'default', duration = 4000) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const t = document.createElement('div');
    const icons = { success: '✓', error: '⚠', warning: '⚠', default: 'ℹ' };
    t.className = `toast ${type}`;
    t.innerHTML = `<span aria-hidden="true">${icons[type] || 'ℹ'}</span> ${escapeHtml(msg)}`;
    t.setAttribute('role', 'status');
    container.appendChild(t);
    // Aria-live announce
    const live = document.getElementById('a11y-live');
    if (live) live.textContent = msg;
    setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, duration);
  }

  function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Modal info indicador
  function showInfoModal(title, body) {
    setText('modal-title', title);
    setHtml('modal-body', body);
    show('modal-overlay');
    document.getElementById('btn-modal-close').focus();
  }

  function hideInfoModal() { hide('modal-overlay'); }

  // Modal confirmación
  function showConfirmModal() { show('modal-confirm'); document.getElementById('btn-confirm-ok').focus(); }
  function hideConfirmModal() { hide('modal-confirm'); }

  // Modal período
  function showPeriodoModal() {
    document.getElementById('input-nuevo-periodo').value = '';
    document.getElementById('select-periodo-estado').value = 'ABIERTO';
    show('modal-periodo');
    document.getElementById('input-nuevo-periodo').focus();
  }
  function hidePeriodoModal() { hide('modal-periodo'); }

  function formatPeriodo(p) {
    if (!p) return '—';
    const [y, m] = String(p).split('-');
    const meses = ['', 'Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun', 'Jul', 'Ago', 'Sep', 'Oct', 'Nov', 'Dic'];
    return `${meses[parseInt(m)] || m} ${y}`;
  }

  function estadoBadge(estado) {
    const map = { ABIERTO: 'badge-ok', REVISION: 'badge-warning', CERRADO: 'badge-neutral', BORRADOR: 'badge-warning', ENVIADO: 'badge-ok' };
    const cls = map[estado] || 'badge-neutral';
    return `<span class="badge ${cls}">${estado}</span>`;
  }

  function moduloLabel(mod) {
    return CONFIG.MODULOS_LABELS[String(mod).toUpperCase()] || mod;
  }

  return {
    show, hide, toggle, setHtml, setText,
    showLoading, hideLoading,
    toast, escapeHtml,
    showInfoModal, hideInfoModal,
    showConfirmModal, hideConfirmModal,
    showPeriodoModal, hidePeriodoModal,
    formatPeriodo, estadoBadge, moduloLabel
  };
})();

// ── VALIDATOR ─────────────────────────────────────────────────
const Validator = (() => {
  function validate(value, indicador) {
    const { tipo_dato, requerido, regla_validacion } = indicador;
    const esReq = String(requerido).toUpperCase() === 'TRUE';
    const v = String(value !== null && value !== undefined ? value : '').trim();

    if (v === '') {
      if (esReq) return 'Campo requerido';
      return null;
    }

    switch (String(tipo_dato).toUpperCase()) {
      case 'NUMERO':
      case 'DECIMAL':
        if (isNaN(Number(v))) return 'Debe ser un número';
        break;
      case 'ENTERO':
        if (!/^-?\d+$/.test(v)) return 'Debe ser un número entero';
        break;
      case 'PORCENTAJE':
        const pct = Number(v);
        if (isNaN(pct) || pct < 0 || pct > 100) return 'Debe ser entre 0 y 100';
        break;
      case 'TEXTO':
        if (v.length > 2000) return 'Máximo 2000 caracteres';
        break;
      case 'BOOLEAN':
        if (!['true', 'false', '1', '0', 'si', 'no', 'sí'].includes(v.toLowerCase())) return 'Debe ser SI o NO';
        break;
      case 'FECHA':
        if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return 'Formato: AAAA-MM-DD';
        break;
    }

    // Reglas personalizadas
    if (regla_validacion) {
      const num = Number(v);
      const reglas = String(regla_validacion).split(',');
      for (const r of reglas) {
        const [k, val] = r.split(':');
        switch (k.trim().toUpperCase()) {
          case 'MIN': if (!isNaN(num) && num < Number(val)) return `Mínimo: ${val}`; break;
          case 'MAX': if (!isNaN(num) && num > Number(val)) return `Máximo: ${val}`; break;
        }
      }
    }

    return null;
  }

  return { validate };
})();

// ── FORM RENDERER ─────────────────────────────────────────────
const FormModule = (() => {
  let currentValues = {}; // id_indicador → value
  let currentComents = {};
  let isDirty = false;
  let savedEstado = 'BORRADOR';
  let isLocked = false; // true si ENVIADO y período no en REVISION

  async function load(modulo) {
    State.activeModulo = modulo;
    UI.showLoading();
    try {
      // Indicadores del módulo
      let indicadores = State.indicadoresCache[modulo];
      if (!indicadores) {
        const r = await API.getIndicadores(modulo);
        indicadores = r.indicadores || [];
        State.indicadoresCache[modulo] = indicadores;
      }

      // Período activo
      if (!State.periodoActivo) {
        const rp = await API.getPeriodoActivo();
        State.periodoActivo = rp.periodo;
      }
      const periodoObj = State.periodoActivo;
      const periodo = periodoObj ? periodoObj.periodo : '—';
      const estadoPer = periodoObj ? periodoObj.estado : 'CERRADO';

      // Capturas existentes
      let capturas = [];
      if (periodoObj) {
        const cKey = `${periodo}|${modulo}`;
        if (!State.capturasCache[cKey]) {
          const rc = await API.getCapturas(periodo, modulo);
          State.capturasCache[cKey] = rc.capturas || [];
        }
        capturas = State.capturasCache[cKey];
      }

      // Reconstruir valores existentes
      currentValues = {};
      currentComents = {};
      savedEstado = 'BORRADOR';
      capturas.forEach(c => {
        currentValues[c.id_indicador] = c.valor;
        currentComents[c.id_indicador] = c.comentario;
        if (c.estado_registro === 'ENVIADO') savedEstado = 'ENVIADO';
      });

      const sess = State.getSession();
      isLocked = savedEstado === 'ENVIADO' && estadoPer === 'ABIERTO' && sess.rol !== 'ADMIN';

      // Actualizar encabezado
      UI.setText('mh-modulo', UI.moduloLabel(modulo));
      UI.setText('mh-periodo', UI.formatPeriodo(periodo));
      UI.setHtml('mh-estado', UI.estadoBadge(estadoPer));
      UI.setText('mh-usuario', sess ? sess.nombre : '—');

      // Header global
      UI.setText('header-module-name', UI.moduloLabel(modulo) + ' — PARACEL');
      UI.setHtml('header-estado-badge', `<span class="badge periodo-badge-${estadoPer}">${estadoPer}</span>`);
      UI.setText('header-periodo', UI.formatPeriodo(periodo));

      // Renderizar secciones
      renderSections(indicadores, estadoPer);

      // Estado botones
      const btnDraft = document.getElementById('btn-draft');
      const btnSubmit = document.getElementById('btn-submit');
      const cerrado = estadoPer === 'CERRADO';

      if (btnDraft) btnDraft.disabled = cerrado || isLocked;
      if (btnSubmit) btnSubmit.disabled = cerrado || isLocked || savedEstado === 'ENVIADO';

      updateSaveStatus(savedEstado === 'ENVIADO' ? 'enviado' : 'clean');

      UI.hide('view-admin');
      UI.hide('view-loading');
      UI.show('view-form');
    } catch (err) {
      handleError(err, 'cargar el formulario');
    } finally {
      UI.hideLoading();
    }
  }

  function renderSections(indicadores, estadoPer) {
    // Agrupar por sección (campo: no existe en el diccionario, usamos el prefijo del id_indicador)
    // Los indicadores ya vienen ordenados por campo "orden"
    const container = document.getElementById('form-sections');
    if (!container) return;
    container.innerHTML = '';

    // Agrupar indicadores por sub-sección basada en el sufijo después de " — "
    // Ejemplo: "Mujeres — Industrial" → sección "Industrial"
    //          "Quejas recibidas"      → sección "General"
    const sections = {};
    indicadores.forEach(ind => {
      const nombre = String(ind.indicador || '');
      const dashPos = nombre.indexOf(' — ');
      let sec;
      if (dashPos > -1) {
        sec = nombre.substring(dashPos + 3).trim(); // "Industrial", "Forestal", "Instagram", etc.
      } else {
        sec = 'General';
      }
      if (!sections[sec]) sections[sec] = [];
      sections[sec].push(ind);
    });

    let sectionIndex = 0;
    Object.entries(sections).forEach(([secName, inds]) => {
      sectionIndex++;
      const totalReq = inds.filter(i => String(i.requerido).toUpperCase() === 'TRUE').length;
      const completed = inds.filter(i => {
        const v = currentValues[i.id_indicador];
        return v !== undefined && v !== null && String(v).trim() !== '';
      }).length;
      const isComplete = completed === inds.length;

      const secEl = document.createElement('div');
      secEl.className = 'card';
      secEl.innerHTML = `
        <div class="section-header">
          <h3 class="section-title">${UI.escapeHtml(secName)}</h3>
          <span class="section-progress ${isComplete ? 'complete' : ''}" 
                aria-label="${completed} de ${inds.length} indicadores completados">
            ${completed}/${inds.length}
          </span>
        </div>
        <div class="indicators-list" id="section-${sectionIndex}-list"></div>
      `;
      container.appendChild(secEl);
      const list = secEl.querySelector(`#section-${sectionIndex}-list`);
      inds.forEach(ind => list.appendChild(renderIndicator(ind, estadoPer)));
    });
  }

  function renderIndicator(ind, estadoPer) {
    const { id_indicador, indicador, unidad, tipo_dato, requerido, descripcion, ayuda } = ind;
    const esReq = String(requerido).toUpperCase() === 'TRUE';
    const val = currentValues[id_indicador] ?? '';
    const comentario = currentComents[id_indicador] ?? '';
    const cerrado = estadoPer === 'CERRADO';
    const locked = isLocked || cerrado;

    const row = document.createElement('div');
    row.className = 'indicator-row';
    row.id = `row-${id_indicador}`;

    // Tipo input
    let inputHtml;
    const inputId = `inp-${id_indicador}`;
    const tipUp = String(tipo_dato).toUpperCase();

    if (tipUp === 'TEXTO') {
      inputHtml = `<textarea
        id="${inputId}"
        name="${id_indicador}"
        aria-label="${UI.escapeHtml(indicador)}"
        aria-describedby="help-${id_indicador}"
        ${esReq ? 'required aria-required="true"' : ''}
        ${locked ? 'disabled' : ''}
        placeholder="Ingresa el valor..."
      >${UI.escapeHtml(String(val))}</textarea>`;
    } else if (tipUp === 'BOOLEAN') {
      const isYes = ['true', '1', 'si', 'sí'].includes(String(val).toLowerCase());
      const isNo = ['false', '0', 'no'].includes(String(val).toLowerCase());
      inputHtml = `
        <select id="${inputId}" name="${id_indicador}"
          aria-label="${UI.escapeHtml(indicador)}"
          ${esReq ? 'required aria-required="true"' : ''}
          ${locked ? 'disabled' : ''}>
          <option value="">Seleccionar...</option>
          <option value="SI"  ${isYes ? 'selected' : ''}>Sí</option>
          <option value="NO"  ${isNo ? 'selected' : ''}>No</option>
        </select>`;
    } else {
      const inputType = (tipUp === 'FECHA') ? 'date' : 'number';
      const step = (tipUp === 'DECIMAL' || tipUp === 'PORCENTAJE') ? '0.01' : '1';
      inputHtml = `<input
        type="${inputType}"
        id="${inputId}"
        name="${id_indicador}"
        value="${UI.escapeHtml(String(val))}"
        aria-label="${UI.escapeHtml(indicador)}"
        aria-describedby="help-${id_indicador}"
        ${esReq ? 'required aria-required="true"' : ''}
        ${(tipUp === 'NUMERO' || tipUp === 'DECIMAL' || tipUp === 'ENTERO' || tipUp === 'PORCENTAJE') ? `step="${step}" min="0"` : ''}
        ${locked ? 'disabled' : ''}
        placeholder="—"
        autocomplete="off"
      />`;
    }

    row.innerHTML = `
      <div class="indicator-label">
        ${esReq ? '<span class="required-star" aria-hidden="true">★</span>' : ''}
        <label for="${inputId}">${UI.escapeHtml(indicador)}</label>
      </div>
      <div class="indicator-input-group">
        ${inputHtml}
        ${unidad ? `<span class="indicator-unit" aria-label="Unidad: ${UI.escapeHtml(unidad)}">${UI.escapeHtml(unidad)}</span>` : ''}
        ${descripcion ? `
          <button type="button" class="btn-info" 
                  aria-label="Más información sobre ${UI.escapeHtml(indicador)}"
                  data-title="${UI.escapeHtml(indicador)}"
                  data-desc="${UI.escapeHtml(descripcion)}"
                  data-ayuda="${UI.escapeHtml(ayuda || '')}">
            ℹ
          </button>` : ''}
      </div>
      ${ayuda ? `<span class="indicator-help" id="help-${id_indicador}">${UI.escapeHtml(ayuda)}</span>` : ''}
      <span class="indicator-error hidden" id="err-${id_indicador}" role="alert"></span>
    `;

    // Eventos
    const input = row.querySelector(`#${inputId}`);
    if (input && !locked) {
      input.addEventListener('change', () => handleValueChange(id_indicador, input, ind));
      input.addEventListener('input', () => clearFieldError(id_indicador));
    }

    const btnInfo = row.querySelector('.btn-info');
    if (btnInfo) {
      btnInfo.addEventListener('click', () => {
        const bodyHtml = `
          <p><strong>Descripción:</strong> ${UI.escapeHtml(btnInfo.dataset.desc || '')}</p>
          ${btnInfo.dataset.ayuda ? `<p class="mt-4"><strong>Ayuda:</strong> ${UI.escapeHtml(btnInfo.dataset.ayuda)}</p>` : ''}
          <p class="mt-4 text-sm text-muted">Unidad: <strong>${UI.escapeHtml(unidad || '—')}</strong> | Tipo: <strong>${tipo_dato}</strong></p>
        `;
        UI.showInfoModal(btnInfo.dataset.title, bodyHtml);
      });
    }

    return row;
  }

  function handleValueChange(idInd, input, ind) {
    const val = input.value;
    const err = Validator.validate(val, ind);
    if (err) {
      showFieldError(idInd, err);
      input.classList.add('is-error');
      input.classList.remove('is-warning');
    } else {
      clearFieldError(idInd);
    }
    currentValues[idInd] = val;
    isDirty = true;
    updateSaveStatus('dirty');
  }

  function showFieldError(idInd, msg) {
    const errEl = document.getElementById(`err-${idInd}`);
    const input = document.getElementById(`inp-${idInd}`);
    if (errEl) { errEl.textContent = `⚠ ${msg}`; errEl.classList.remove('hidden'); }
    if (input) { input.classList.add('is-error'); input.setAttribute('aria-invalid', 'true'); }
  }

  function clearFieldError(idInd) {
    const errEl = document.getElementById(`err-${idInd}`);
    const input = document.getElementById(`inp-${idInd}`);
    if (errEl) { errEl.textContent = ''; errEl.classList.add('hidden'); }
    if (input) { input.classList.remove('is-error'); input.removeAttribute('aria-invalid'); }
  }

  function collectCurrentValues() {
    // Leer todos los inputs del formulario
    const inputs = document.querySelectorAll('#form-sections input, #form-sections select, #form-sections textarea');
    inputs.forEach(inp => {
      const id = inp.name;
      if (id) currentValues[id] = inp.value;
    });
  }

  function validateAll(indicadores) {
    const errors = [];
    indicadores.forEach(ind => {
      const val = currentValues[ind.id_indicador];
      const err = Validator.validate(val, ind);
      if (err) errors.push({ id: ind.id_indicador, nombre: ind.indicador, error: err });
    });
    return errors;
  }

  async function save(estadoRegistro) {
    collectCurrentValues();

    const modulo = State.activeModulo;
    const indicadores = State.indicadoresCache[modulo] || [];
    const periodoObj = State.periodoActivo;
    const periodo = periodoObj ? periodoObj.periodo : null;

    if (!periodo) { UI.toast('No hay período activo', 'error'); return; }

    // Validación cliente si es ENVIADO
    if (estadoRegistro === 'ENVIADO') {
      const errors = validateAll(indicadores);
      if (errors.length > 0) {
        showErrorSummary(errors);
        // Resaltar primeros errores encontrados
        errors.forEach(e => showFieldError(e.id, e.error));
        errors[0] && document.getElementById(`inp-${errors[0].id}`)?.focus();
        return;
      }
    }

    UI.hide('error-summary');
    updateSaveStatus('saving');
    UI.showLoading();

    let savedCount = 0;
    let errorCount = 0;

    // Enviar solo indicadores con valor o todos los requeridos
    const toSend = indicadores.filter(ind => {
      const v = currentValues[ind.id_indicador];
      return v !== undefined && v !== null && String(v).trim() !== '';
    });

    for (const ind of toSend) {
      try {
        await API.upsertCaptura({
          periodo,
          modulo,
          id_indicador: ind.id_indicador,
          valor: currentValues[ind.id_indicador],
          comentario: currentComents[ind.id_indicador] || '',
          estado_registro: estadoRegistro
        });
        savedCount++;
      } catch (err) {
        console.error('Error guardando', ind.id_indicador, err);
        errorCount++;
      }
    }

    // Invalidar cache
    delete State.capturasCache[`${periodo}|${modulo}`];

    UI.hideLoading();

    if (errorCount > 0) {
      UI.toast(`${savedCount} guardados, ${errorCount} con error`, 'warning');
      updateSaveStatus('error');
    } else {
      const ts = new Date().toLocaleTimeString('es-PY', { hour: '2-digit', minute: '2-digit' });
      updateSaveStatus(estadoRegistro === 'ENVIADO' ? 'enviado' : 'synced', ts);
      savedEstado = estadoRegistro;
      isDirty = false;

      if (estadoRegistro === 'ENVIADO') {
        isLocked = true;
        document.getElementById('btn-draft')?.setAttribute('disabled', '');
        document.getElementById('btn-submit')?.setAttribute('disabled', '');
        UI.toast('Formulario enviado correctamente ✓', 'success', 5000);
      } else {
        UI.toast(`Borrador guardado a las ${ts}`, 'success');
      }
    }
  }

  function showErrorSummary(errors) {
    const list = document.getElementById('error-summary-list');
    if (!list) return;
    list.innerHTML = errors.map(e =>
      `<li><a href="#inp-${e.id}">${UI.escapeHtml(e.nombre)}: ${UI.escapeHtml(e.error)}</a></li>`
    ).join('');
    UI.show('error-summary');
    document.getElementById('error-summary')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  function updateSaveStatus(state, ts) {
    const el = document.getElementById('save-status');
    if (!el) return;
    const msgs = {
      clean: 'Sin cambios pendientes',
      dirty: '● Hay cambios sin guardar',
      saving: '⏳ Guardando...',
      synced: `✓ Guardado a las ${ts}`,
      enviado: '✓ Enviado — sólo lectura',
      error: '⚠ Error al guardar algunos campos'
    };
    el.textContent = msgs[state] || '';
    el.className = ['save-status', state === 'synced' || state === 'enviado' ? 'synced' : state === 'saving' ? 'saving' : ''].join(' ').trim();
  }

  return { load, save };
})();

// ── ADMIN DASHBOARD ───────────────────────────────────────────
const AdminDashboard = (() => {
  async function load() {
    UI.showLoading();
    try {
      UI.hide('view-form');
      UI.hide('view-loading');
      UI.show('view-admin');

      // Cargar períodos para el filtro
      const rp = await API.getPeriodos();
      const periodos = (rp.periodos || []).sort((a, b) => b.periodo > a.periodo ? 1 : -1);
      populatePeriodosFilter(periodos);
      renderPeriodosTable(periodos);

      // Cargar control del período activo por defecto
      const rpa = await API.getPeriodoActivo();
      if (rpa.periodo) {
        const sel = document.getElementById('filter-periodo');
        if (sel) sel.value = rpa.periodo.periodo;
        await loadControl(rpa.periodo.periodo);
      }
    } catch (err) {
      handleError(err, 'cargar el tablero');
    } finally {
      UI.hideLoading();
    }
  }

  function populatePeriodosFilter(periodos) {
    const sel = document.getElementById('filter-periodo');
    if (!sel) return;
    sel.innerHTML = '<option value="">Seleccionar...</option>' +
      periodos.map(p => `<option value="${p.periodo}">${UI.formatPeriodo(p.periodo)} — ${p.estado}</option>`).join('');

    // Módulos filter
    const selMod = document.getElementById('filter-modulo');
    if (selMod) {
      selMod.innerHTML = '<option value="">Todos</option>' +
        Object.entries(CONFIG.MODULOS_LABELS).map(([k, v]) =>
          `<option value="${k}">${v}</option>`).join('');
    }
  }

  async function loadControl(periodo) {
    if (!periodo) return;
    UI.showLoading();
    try {
      const r = await API.controlCarga(periodo);
      renderControlGrid(r.control || {});
    } catch (err) {
      handleError(err, 'cargar el control');
    } finally {
      UI.hideLoading();
    }
  }

  function renderControlGrid(control) {
    const grid = document.getElementById('control-grid');
    if (!grid) return;

    const modulos = Object.keys(control);
    if (modulos.length === 0) {
      grid.innerHTML = `<div class="empty-state"><div class="icon">📊</div><p>Sin datos para este período</p></div>`;
      return;
    }

    grid.innerHTML = modulos.map(mod => {
      const d = control[mod];
      const pct = d.completitud_pct || 0;
      const barClass = pct === 100 ? 'complete' : pct >= 50 ? '' : 'mid';
      const ts = d.ultimo_cambio ? new Date(d.ultimo_cambio).toLocaleString('es-PY') : '—';
      return `
        <div class="control-card">
          <div class="control-card-title">
            ${UI.moduloLabel(mod)}
            ${d.enviados > 0 ? '<span class="badge badge-ok" style="margin-left:auto">ENVIADO</span>' : ''}
          </div>
          <div class="progress-bar-container" aria-label="${pct}% completado" title="${pct}%">
            <div class="progress-bar ${barClass}" style="width:${pct}%" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"></div>
          </div>
          <div style="font-size:.75rem;color:var(--text-subtle);margin-bottom:.75rem">${pct}% completado</div>
          <div class="control-stat"><span>Indicadores</span><span class="val">${d.total_indicadores}</span></div>
          <div class="control-stat"><span>Requeridos</span><span class="val">${d.total_requeridos}</span></div>
          <div class="control-stat"><span>Borradores</span><span class="val">${d.borradores}</span></div>
          <div class="control-stat"><span>Enviados</span><span class="val">${d.enviados}</span></div>
          ${d.faltantes_requeridos?.length > 0 ? `
          <div class="control-stat" style="flex-direction:column;align-items:flex-start;gap:.25rem">
            <span style="color:var(--error);font-weight:600">⚠ Faltantes requeridos (${d.faltantes_requeridos.length}):</span>
            <span class="val" style="font-size:.75rem">${d.faltantes_requeridos.join(', ')}</span>
          </div>` : ''}
          <div class="control-stat"><span>Último cambio</span><span class="val" style="font-size:.75rem">${ts}</span></div>
        </div>`;
    }).join('');
  }

  function renderPeriodosTable(periodos) {
    const tbody = document.getElementById('tbody-periodos');
    if (!tbody) return;
    if (!periodos.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-muted">Sin períodos registrados</td></tr>';
      return;
    }
    tbody.innerHTML = periodos.map(p => `
      <tr>
        <td><strong>${p.periodo}</strong></td>
        <td>${UI.estadoBadge(p.estado)}</td>
        <td>${p.fecha_apertura ? new Date(p.fecha_apertura).toLocaleDateString('es-PY') : '—'}</td>
        <td>${p.fecha_cierre ? new Date(p.fecha_cierre).toLocaleDateString('es-PY') : '—'}</td>
        <td>
          <div class="btn-group">
            ${p.estado !== 'ABIERTO' ? `<button class="btn btn-sm btn-secondary" onclick="App.adminSetEstado('${p.periodo}','ABIERTO')">Abrir</button>` : ''}
            ${p.estado !== 'REVISION' ? `<button class="btn btn-sm btn-ghost" onclick="App.adminSetEstado('${p.periodo}','REVISION')">Revisión</button>` : ''}
            ${p.estado !== 'CERRADO' ? `<button class="btn btn-sm btn-danger" onclick="App.adminSetEstado('${p.periodo}','CERRADO')">Cerrar</button>` : ''}
          </div>
        </td>
      </tr>`).join('');
  }

  async function exportCSV(periodo) {
    if (!periodo) { UI.toast('Selecciona un período', 'warning'); return; }
    UI.showLoading();
    try {
      const r = await API.exportCSV(periodo);
      if (!r.csv) { UI.toast('Sin datos para exportar', 'warning'); return; }
      const blob = new Blob(['\uFEFF' + r.csv], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `indicadores_${periodo}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      UI.toast(`CSV exportado (${r.total_filas} filas)`, 'success');
    } catch (err) {
      handleError(err, 'exportar CSV');
    } finally {
      UI.hideLoading();
    }
  }

  return { load, loadControl, exportCSV, renderPeriodosTable };
})();

// ── ROUTER ────────────────────────────────────────────────────
const Router = (() => {
  let periodos = [];

  function buildTabs(session) {
    const nav = document.getElementById('tabs-nav');
    if (!nav) return;

    const { rol, modulos_permitidos } = session;
    const esAdmin = rol === 'ADMIN';
    const modulos = esAdmin ? Object.keys(CONFIG.MODULOS_LABELS) : (modulos_permitidos || []);
    const showTabs = esAdmin || modulos.length > 1;

    if (!showTabs) { UI.hide('tabs-nav'); return; }

    UI.show('tabs-nav');
    nav.innerHTML = '';

    // Tab Admin Dashboard (solo ADMIN)
    if (esAdmin) {
      const btn = createTabBtn('admin', '⊞ Tablero', true);
      nav.appendChild(btn);
    }

    modulos.forEach((mod, i) => {
      const isFirst = !esAdmin && i === 0;
      const btn = createTabBtn(mod, UI.moduloLabel(mod), isFirst);
      nav.appendChild(btn);
    });
  }

  function createTabBtn(id, label, isActive) {
    const btn = document.createElement('button');
    btn.className = `tab-btn ${isActive ? 'active' : ''}`;
    btn.textContent = label;
    btn.id = `tab-${id}`;
    btn.setAttribute('role', 'tab');
    btn.setAttribute('aria-selected', String(isActive));
    btn.setAttribute('aria-controls', 'panel-main');
    btn.dataset.tabId = id;
    btn.addEventListener('click', () => activateTab(id));
    return btn;
  }

  async function activateTab(id) {
    // Marcar tab activo
    document.querySelectorAll('.tab-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.tabId === id);
      b.setAttribute('aria-selected', String(b.dataset.tabId === id));
    });

    UI.show('view-loading');
    UI.hide('view-form');
    UI.hide('view-admin');

    if (id === 'admin') {
      await AdminDashboard.load();
    } else {
      await FormModule.load(id);
    }
  }

  async function init(session) {
    buildTabs(session);

    const { rol, modulos_permitidos } = session;
    const esAdmin = rol === 'ADMIN';

    if (esAdmin) {
      await AdminDashboard.load();
    } else {
      const firstMod = (modulos_permitidos || [])[0];
      if (firstMod) {
        await FormModule.load(firstMod);
        // Prefetch: cargar el resto de módulos en background para cambio instantáneo
        prefetchModulos(modulos_permitidos, firstMod);
      } else {
        UI.setHtml('view-loading',
          `<div class="empty-state"><div class="icon">🚫</div><p>Sin módulos asignados</p><span>Contactá al administrador</span></div>`);
        UI.show('view-loading');
      }
    }
  }

  /**
   * Precarga indicadores y período activo de todos los módulos en background.
   * Esto hace que el cambio de pestaña sea instantáneo.
   */
  function prefetchModulos(modulos, excludeMod) {
    const toLoad = (modulos || Object.keys(CONFIG.MODULOS_LABELS)).filter(m => m !== excludeMod);
    toLoad.forEach(mod => {
      if (!State.indicadoresCache[mod]) {
        API.getIndicadores(mod).then(r => {
          State.indicadoresCache[mod] = r.indicadores || [];
        }).catch(() => { }); // silencioso si falla
      }
    });
    // También precargar período activo si no lo tenemos
    if (!State.periodoActivo) {
      API.getPeriodoActivo().then(r => {
        if (r.periodo) State.periodoActivo = r.periodo;
      }).catch(() => { });
    }
  }

  return { init, activateTab };
})();

// ── AUTH ──────────────────────────────────────────────────────
const Auth = (() => {
  async function login(usuario, password) {
    // El servidor se encarga del hash SHA-256 (la conexión ya es HTTPS)
    const data = await API.login(usuario, password);
    State.saveSession({
      usuario: data.usuario,
      nombre: data.nombre,
      rol: data.rol,
      modulos_permitidos: data.modulos_permitidos,
      exp: data.exp
    }, data.token);
    return data;
  }

  function logout() {
    State.clearSession();
    UI.hide('screen-app');
    UI.show('screen-login');
    document.getElementById('input-usuario').value = '';
    document.getElementById('input-password').value = '';
    document.getElementById('input-usuario').focus();
    UI.toast('Sesión cerrada');
  }

  function checkSession() {
    const sess = State.getSession();
    if (!sess || State.isExpired()) {
      State.clearSession();
      return null;
    }
    return sess;
  }

  return { login, logout, checkSession };
})();

// ── ERROR HANDLER ─────────────────────────────────────────────
function handleError(err, context) {
  console.error(`[Error en ${context}]:`, err);
  const status = err.status || 0;
  if (status === 401) {
    UI.toast('Sesión expirada. Volvé a iniciar sesión.', 'error', 6000);
    Auth.logout();
    return;
  }
  if (status === 403) {
    UI.toast(`Sin permisos: ${err.message}`, 'error', 6000);
    return;
  }
  UI.toast(`Error: ${err.message || 'Error desconocido'}`, 'error');
}

// ── APP INIT ──────────────────────────────────────────────────
const App = (() => {

  async function init() {
    // Verificar si hay sesión activa
    const sess = Auth.checkSession();
    if (sess) {
      showApp(sess);
      return;
    }
    showLogin();
  }

  function showLogin() {
    UI.hide('screen-app');
    UI.show('screen-login');
    document.getElementById('input-usuario')?.focus();
  }

  function showApp(session) {
    UI.hide('screen-login');
    UI.show('screen-app');
    UI.setText('header-module-name', 'PARACEL');
    Router.init(session);
  }

  // Manejo del formulario de login
  function setupLogin() {
    const form = document.getElementById('form-login');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const usuario = document.getElementById('input-usuario').value.trim();
      const password = document.getElementById('input-password').value;

      // Validaciones básicas de cliente
      let valid = true;
      if (!usuario) {
        document.getElementById('usuario-error')?.classList.remove('hidden');
        valid = false;
      } else {
        document.getElementById('usuario-error')?.classList.add('hidden');
      }
      if (!password) {
        document.getElementById('password-error')?.classList.remove('hidden');
        valid = false;
      } else {
        document.getElementById('password-error')?.classList.add('hidden');
      }
      if (!valid) return;

      // Loading state en botón
      document.getElementById('btn-login-text').textContent = 'Ingresando...';
      document.getElementById('btn-login-spinner').classList.remove('hidden');
      document.getElementById('btn-login').disabled = true;
      UI.hide('login-error');

      try {
        const data = await Auth.login(usuario, password);
        showApp(data);
      } catch (err) {
        const msg = err.message || 'Error al iniciar sesión';
        document.getElementById('login-error-msg').textContent = msg;
        document.getElementById('login-error').classList.remove('hidden');
        document.getElementById('input-password').value = '';
        document.getElementById('input-password').focus();
      } finally {
        document.getElementById('btn-login-text').textContent = 'Ingresar';
        document.getElementById('btn-login-spinner').classList.add('hidden');
        document.getElementById('btn-login').disabled = false;
      }
    });
  }

  function setupGlobalListeners() {
    // Logout
    document.getElementById('btn-logout')?.addEventListener('click', Auth.logout);

    // Guardar borrador
    document.getElementById('btn-draft')?.addEventListener('click', () => {
      FormModule.save('BORRADOR');
    });

    // Enviar (con confirmación)
    document.getElementById('btn-submit')?.addEventListener('click', () => {
      UI.showConfirmModal();
    });

    // Modal confirmación - OK
    document.getElementById('btn-confirm-ok')?.addEventListener('click', () => {
      UI.hideConfirmModal();
      FormModule.save('ENVIADO');
    });
    document.getElementById('btn-confirm-cancel')?.addEventListener('click', UI.hideConfirmModal);

    // Modal info - Cerrar
    document.getElementById('btn-modal-close')?.addEventListener('click', UI.hideInfoModal);
    document.getElementById('modal-overlay')?.addEventListener('click', e => {
      if (e.target.id === 'modal-overlay') UI.hideInfoModal();
    });

    // Modal período
    document.getElementById('modal-confirm')?.addEventListener('click', e => {
      if (e.target.id === 'modal-confirm') UI.hideConfirmModal();
    });

    // Admin: refresh control
    document.getElementById('btn-refresh-control')?.addEventListener('click', () => {
      const per = document.getElementById('filter-periodo')?.value;
      AdminDashboard.loadControl(per);
    });

    // Admin: exportar CSV
    document.getElementById('btn-export-csv')?.addEventListener('click', () => {
      const per = document.getElementById('filter-periodo')?.value;
      AdminDashboard.exportCSV(per);
    });

    // Admin: nuevo período
    document.getElementById('btn-nuevo-periodo')?.addEventListener('click', UI.showPeriodoModal);
    document.getElementById('btn-periodo-cancel')?.addEventListener('click', UI.hidePeriodoModal);
    document.getElementById('modal-periodo')?.addEventListener('click', e => {
      if (e.target.id === 'modal-periodo') UI.hidePeriodoModal();
    });

    document.getElementById('btn-periodo-save')?.addEventListener('click', async () => {
      const periodo = document.getElementById('input-nuevo-periodo')?.value.trim();
      const estado = document.getElementById('select-periodo-estado')?.value;
      if (!periodo || !/^\d{4}-\d{2}$/.test(periodo)) {
        UI.toast('Período inválido (formato: AAAA-MM)', 'error');
        return;
      }
      try {
        await API.setPeriodoEstado({ periodo, estado });
        UI.hidePeriodoModal();
        UI.toast(`Período ${periodo} → ${estado}`, 'success');
        AdminDashboard.load();
      } catch (err) {
        handleError(err, 'guardar período');
      }
    });

    // Teclado: Escape cierra modales
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        UI.hideInfoModal();
        UI.hideConfirmModal();
        UI.hidePeriodoModal();
      }
    });
  }

  // Expuesto globalmente para los botones de la tabla de períodos
  async function adminSetEstado(periodo, estado) {
    if (!confirm(`¿Cambiar período ${periodo} a "${estado}"?`)) return;
    try {
      UI.showLoading();
      await API.setPeriodoEstado({ periodo, estado });
      UI.toast(`Período ${periodo} → ${estado}`, 'success');
      AdminDashboard.load();
    } catch (err) {
      handleError(err, 'cambiar estado período');
    } finally {
      UI.hideLoading();
    }
  }

  return { init: () => { setupLogin(); setupGlobalListeners(); init(); }, adminSetEstado };
})();

// ── ARRANQUE ──────────────────────────────────────────────────
window.App = App;
document.addEventListener('DOMContentLoaded', App.init);
