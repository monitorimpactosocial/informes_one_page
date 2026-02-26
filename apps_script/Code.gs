// ============================================================
//  MONITOREO INDICADORES PARACEL — Google Apps Script Backend
//  Versión: 1.0.0 | 2026-02
//  Publicar como: Web App → "Anyone" (con token de seguridad)
// ============================================================

// ── CONSTANTES ──────────────────────────────────────────────
const SPREADSHEET_ID         = '1TFwLLp3B3LtYcq1lGVjn22RgGDg5SL6hGpx5YI-OlNM';
const SHEET_USUARIOS         = 'usuarios';
const SHEET_USUARIOS_MODULOS = 'usuarios_modulos';
const SHEET_PERIODOS         = 'periodos';
const SHEET_INDICADORES      = 'indicadores';
const SHEET_CAPTURAS         = 'capturas';
const SHEET_AUDITORIA        = 'auditoria';

const ROLES           = { ADMIN: 'ADMIN', COORDINADOR: 'COORDINADOR', USER: 'USER' };
const TOKEN_TTL_MS    = 8 * 60 * 60 * 1000; // 8 horas en ms
const CORS_HEADERS    = {
  'Access-Control-Allow-Origin'  : '*',
  'Access-Control-Allow-Methods' : 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers' : 'Authorization, Content-Type'
};

// ── ROUTER PRINCIPAL ────────────────────────────────────────

function doGet(e) {
  return handleRequest('GET', e);
}

function doPost(e) {
  return handleRequest('POST', e);
}

function handleRequest(method, e) {
  try {
    const action = (e.parameter && e.parameter.action) || '';

    // OPTIONS preflight (CORS)
    if (method === 'OPTIONS') {
      return buildResponse({ ok: true }, 200);
    }

    // Rutas públicas (no requieren token)
    if (method === 'POST') {
      const body = parseBody(e);
      if (action === 'login') return handleLogin(body);
    }

    // Rutas protegidas — validar token primero
    const token  = extractToken(e);
    const session = validateToken(token);
    if (!session) return buildResponse({ error: 'Token inválido o expirado' }, 401);

    // Dispatcher GET
    if (method === 'GET') {
      switch (action) {
        case 'me':            return handleMe(session);
        case 'periodos':      return handleGetPeriodos(session);
        case 'periodoActivo': return handleGetPeriodoActivo(session);
        case 'indicadores':   return handleGetIndicadores(session, e.parameter);
        case 'capturas':      return handleGetCapturas(session, e.parameter);
        case 'controlCarga':  return handleControlCarga(session, e.parameter);
        case 'exportCSV':     return handleExportCSV(session, e.parameter);
        default: return buildResponse({ error: 'Acción GET desconocida: ' + action }, 400);
      }
    }

    // Dispatcher POST
    if (method === 'POST') {
      const body = parseBody(e);
      switch (action) {
        case 'upsertCaptura':    return handleUpsertCaptura(session, body);
        case 'setPeriodoEstado': return handleSetPeriodoEstado(session, body);
        default: return buildResponse({ error: 'Acción POST desconocida: ' + action }, 400);
      }
    }

    return buildResponse({ error: 'Método no soportado' }, 405);

  } catch (err) {
    console.error('handleRequest error:', err);
    return buildResponse({ error: 'Error interno del servidor: ' + err.message }, 500);
  }
}

// ── HELPER: parseo de body ───────────────────────────────────

function parseBody(e) {
  try {
    if (e.postData && e.postData.contents) {
      return JSON.parse(e.postData.contents);
    }
  } catch (_) {}
  return e.parameter || {};
}

// ── HELPER: respuesta JSON ───────────────────────────────────

function buildResponse(data, statusCode) {
  const payload = JSON.stringify(data);
  const output  = ContentService.createTextOutput(payload)
    .setMimeType(ContentService.MimeType.JSON);
  // Apps Script no permite setear status code directamente;
  // encapsulamos el status en el payload para que el cliente lo maneje.
  if (statusCode && statusCode !== 200) {
    const wrapped = { __status: statusCode, ...data };
    return ContentService.createTextOutput(JSON.stringify(wrapped))
      .setMimeType(ContentService.MimeType.JSON);
  }
  return output;
}

function buildOk(data) {
  return buildResponse({ ok: true, ...data }, 200);
}

function buildError(msg, code) {
  return buildResponse({ ok: false, error: msg, __status: code || 400 }, code || 400);
}

// ── HELPER: extrae token del header ─────────────────────────

function extractToken(e) {
  // Apps Script no expone headers en Web App "anyone" — usamos parámetro 't'
  if (e.parameter && e.parameter.t) return e.parameter.t;
  // Para POST también leemos del body como fallback
  try {
    if (e.postData && e.postData.contents) {
      const b = JSON.parse(e.postData.contents);
      if (b.__token) return b.__token;
    }
  } catch (_) {}
  return null;
}

// ── SEGURIDAD: SHA-256 y HMAC ────────────────────────────────

/**
 * SHA-256 hex de un string UTF-8 usando Utilities nativos de Apps Script.
 */
function sha256Hex(text) {
  const bytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    text,
    Utilities.Charset.UTF_8
  );
  return bytes.map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}

/**
 * HMAC-SHA256 usando Utilities.computeHmacSha256Signature
 * Devuelve string base64url-safe.
 */
function hmacSHA256(message, secret) {
  const sig = Utilities.computeHmacSha256Signature(message, secret, Utilities.Charset.UTF_8);
  return Utilities.base64EncodeWebSafe(sig).replace(/=+$/, '');
}

function base64urlEncode(obj) {
  const json  = JSON.stringify(obj);
  const bytes = Utilities.newBlob(json, 'application/json').getBytes();
  return Utilities.base64EncodeWebSafe(bytes).replace(/=+$/, '');
}

function base64urlDecode(str) {
  // Restaurar padding
  const padded = str + '==='.slice((str.length + 3) % 4);
  const bytes  = Utilities.base64DecodeWebSafe(padded);
  return JSON.parse(Utilities.newBlob(bytes).getDataAsString());
}

function getSecret() {
  const secret = PropertiesService.getScriptProperties().getProperty('JWT_SECRET');
  if (!secret) throw new Error('JWT_SECRET no configurado en Script Properties');
  return secret;
}

// ── TOKEN: crear y validar ───────────────────────────────────

function createToken(payload) {
  const full = { ...payload, exp: Date.now() + TOKEN_TTL_MS };
  const encoded = base64urlEncode(full);
  const sig     = hmacSHA256(encoded, getSecret());
  return encoded + '.' + sig;
}

/**
 * Valida token. Retorna payload si válido, null si inválido/expirado.
 */
function validateToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [encoded, sig] = parts;
  const expectedSig = hmacSHA256(encoded, getSecret());

  // Comparación segura (evitar timing attacks en JS — suficiente para GAS)
  if (sig !== expectedSig) return null;

  let payload;
  try { payload = base64urlDecode(encoded); } catch (_) { return null; }

  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload; // { usuario, rol, modulos_permitidos, exp }
}

// ── AUTORIZACIÓN ─────────────────────────────────────────────

/**
 * Verifica que el session tenga acceso al módulo.
 * ADMIN tiene acceso a todo.
 */
function canAccessModulo(session, modulo) {
  if (session.rol === ROLES.ADMIN) return true;
  return Array.isArray(session.modulos_permitidos) &&
    session.modulos_permitidos.includes(modulo);
}

// ── ACCESO A SHEET ───────────────────────────────────────────

function getSheet(name) {
  const ss = SpreadsheetApp.openById(SPREADSHEET_ID);
  const sh = ss.getSheetByName(name);
  if (!sh) throw new Error('Hoja no encontrada: ' + name);
  return sh;
}

/**
 * Devuelve array de objetos con las filas de una hoja.
 * Primera fila = encabezados.
 */
function sheetToObjects(sheetName) {
  const sh   = getSheet(sheetName);
  const data = sh.getDataRange().getValues();
  if (data.length < 2) return [];
  const headers = data[0].map(h => String(h).toLowerCase().trim());
  return data.slice(1).map(row => {
    const obj = {};
    headers.forEach((h, i) => { obj[h] = row[i]; });
    return obj;
  });
}

/**
 * Append una fila al final de una hoja.
 * fields = array de valores en el mismo orden que los encabezados.
 */
function appendRow(sheetName, fields) {
  const sh = getSheet(sheetName);
  sh.appendRow(fields);
}

/**
 * Actualiza una fila específica (1-indexed, incluye header).
 */
function updateRow(sheetName, rowIndex1, colValues) {
  const sh = getSheet(sheetName);
  colValues.forEach(({ col, value }) => {
    sh.getRange(rowIndex1, col).setValue(value);
  });
}

// ── ENDPOINT: POST /login ────────────────────────────────────

function handleLogin(body) {
  const { usuario, password } = body;
  if (!usuario || !password) return buildError('Credenciales faltantes', 400);

  const usuarios = sheetToObjects(SHEET_USUARIOS);
  const user = usuarios.find(u =>
    String(u.usuario).toLowerCase() === String(usuario).toLowerCase()
  );

  if (!user) return buildError('Credenciales inválidas', 401);
  if (String(user.activo).toUpperCase() !== 'TRUE') return buildError('Usuario inactivo', 403);

  const hashInput = sha256Hex(String(password));
  const stored    = String(user.hash_password || '').toLowerCase().trim();
  if (hashInput !== stored) return buildError('Credenciales inválidas', 401);

  // Obtener módulos activos
  const asignaciones = sheetToObjects(SHEET_USUARIOS_MODULOS);
  const modulos_permitidos = asignaciones
    .filter(a =>
      String(a.usuario).toLowerCase() === String(usuario).toLowerCase() &&
      String(a.activo).toUpperCase() === 'TRUE'
    )
    .map(a => String(a.modulo).toUpperCase());

  const payload = {
    usuario     : String(user.usuario),
    nombre      : String(user.nombre),
    rol         : String(user.rol).toUpperCase(),
    modulos_permitidos
  };

  const token = createToken(payload);

  // Auditoría de login
  logAuditoria({
    usuario : payload.usuario,
    accion  : 'LOGIN',
    periodo : '',
    modulo  : '',
    id_indicador   : '',
    valor_anterior : '',
    valor_nuevo    : ''
  });

  return buildOk({
    token,
    usuario  : payload.usuario,
    nombre   : payload.nombre,
    rol      : payload.rol,
    modulos_permitidos,
    exp      : Date.now() + TOKEN_TTL_MS
  });
}

// ── ENDPOINT: GET /me ────────────────────────────────────────

function handleMe(session) {
  return buildOk({
    usuario           : session.usuario,
    nombre            : session.nombre,
    rol               : session.rol,
    modulos_permitidos: session.modulos_permitidos,
    exp               : session.exp
  });
}

// ── ENDPOINT: GET /periodos ───────────────────────────────────

function handleGetPeriodos(session) {
  const periodos = sheetToObjects(SHEET_PERIODOS);
  return buildOk({ periodos });
}

// ── ENDPOINT: GET /periodoActivo ─────────────────────────────

function handleGetPeriodoActivo(session) {
  const periodos = sheetToObjects(SHEET_PERIODOS);
  const activo   = periodos.find(p => String(p.estado).toUpperCase() === 'ABIERTO');
  return buildOk({ periodo: activo || null });
}

// ── ENDPOINT: GET /indicadores?modulo=X ─────────────────────

function handleGetIndicadores(session, params) {
  const modulo = String(params.modulo || '').toUpperCase();
  if (!modulo) return buildError('Parámetro "modulo" requerido', 400);
  if (!canAccessModulo(session, modulo)) return buildError('Sin acceso al módulo', 403);

  const todos = sheetToObjects(SHEET_INDICADORES);
  const filtrados = todos.filter(ind =>
    String(ind.modulo).toUpperCase() === modulo &&
    String(ind.activo).toUpperCase() === 'TRUE'
  );
  // Asegurar orden
  filtrados.sort((a, b) => Number(a.orden) - Number(b.orden));
  return buildOk({ indicadores: filtrados });
}

// ── ENDPOINT: GET /capturas ──────────────────────────────────

function handleGetCapturas(session, params) {
  const periodo = String(params.periodo || '').trim();
  const modulo  = String(params.modulo  || '').toUpperCase();

  if (!periodo) return buildError('Parámetro "periodo" requerido', 400);
  if (!modulo)  return buildError('Parámetro "modulo" requerido', 400);
  if (!canAccessModulo(session, modulo)) return buildError('Sin acceso al módulo', 403);

  const capturas = sheetToObjects(SHEET_CAPTURAS);
  const filtradas = capturas.filter(c =>
    String(c.periodo) === periodo &&
    String(c.modulo).toUpperCase() === modulo
  );
  return buildOk({ capturas: filtradas });
}

// ── ENDPOINT: POST /upsertCaptura ────────────────────────────

function handleUpsertCaptura(session, body) {
  const { periodo, modulo, id_indicador, valor, comentario, estado_registro } = body;

  // Validaciones básicas
  if (!periodo)      return buildError('"periodo" requerido', 400);
  if (!modulo)       return buildError('"modulo" requerido', 400);
  if (!id_indicador) return buildError('"id_indicador" requerido', 400);

  const moduloU = String(modulo).toUpperCase();
  if (!canAccessModulo(session, moduloU)) return buildError('Sin acceso al módulo', 403);

  // Verificar período abierto
  const periodos = sheetToObjects(SHEET_PERIODOS);
  const per = periodos.find(p => String(p.periodo) === String(periodo));
  if (!per) return buildError('Período no encontrado', 404);
  if (String(per.estado).toUpperCase() === 'CERRADO') {
    return buildError('El período está CERRADO, no se pueden guardar datos', 403);
  }

  // Verificar indicador existe y pertenece al módulo
  const indicadores = sheetToObjects(SHEET_INDICADORES);
  const ind = indicadores.find(i =>
    String(i.id_indicador) === String(id_indicador) &&
    String(i.modulo).toUpperCase() === moduloU
  );
  if (!ind) return buildError('Indicador no encontrado en el módulo', 404);

  // Validación de tipo_dato del valor
  const validError = validateTipoDato(valor, ind.tipo_dato, ind.regla_validacion, ind.requerido);
  if (validError) return buildError(validError, 422);

  // Buscar captura existente
  const sh    = getSheet(SHEET_CAPTURAS);
  const data  = sh.getDataRange().getValues();
  const headers = data[0].map(h => String(h).toLowerCase().trim());
  const iP  = headers.indexOf('periodo');
  const iM  = headers.indexOf('modulo');
  const iId = headers.indexOf('id_indicador');
  const iV  = headers.indexOf('valor');
  const iC  = headers.indexOf('comentario');
  const iER = headers.indexOf('estado_registro');
  const iVer= headers.indexOf('version');
  const iTs = headers.indexOf('ts');
  const iUs = headers.indexOf('usuario');

  let existingRowIndex = -1;
  let valorAnterior    = '';
  let existingEstado   = '';

  for (let r = 1; r < data.length; r++) {
    if (
      String(data[r][iP]) === String(periodo) &&
      String(data[r][iM]).toUpperCase() === moduloU &&
      String(data[r][iId]) === String(id_indicador)
    ) {
      existingRowIndex = r + 1; // 1-indexed GAS
      valorAnterior    = data[r][iV];
      existingEstado   = String(data[r][iER]).toUpperCase();
      break;
    }
  }

  // Si ya estaba ENVIADO y período no está en REVISION, bloquear (opcional: COORDINADOR puede reabrir)
  if (existingEstado === 'ENVIADO' && String(per.estado).toUpperCase() !== 'REVISION') {
    if (session.rol !== ROLES.ADMIN) {
      return buildError('El registro ya fue ENVIADO y no puede modificarse', 403);
    }
  }

  const ts      = new Date().toISOString();
  const estadoFinal = String(estado_registro || 'BORRADOR').toUpperCase();

  if (existingRowIndex === -1) {
    // INSERT
    const version = 1;
    appendRow(SHEET_CAPTURAS, [
      ts, periodo, session.usuario, moduloU,
      id_indicador, valor, comentario || '', estadoFinal, version
    ]);
    logAuditoria({
      usuario: session.usuario, accion: 'INSERT',
      periodo, modulo: moduloU, id_indicador,
      valor_anterior: '', valor_nuevo: valor
    });
  } else {
    // UPDATE
    const nuevaVersion = (Number(data[existingRowIndex - 1][iVer]) || 0) + 1;
    sh.getRange(existingRowIndex, iTs  + 1).setValue(ts);
    sh.getRange(existingRowIndex, iUs  + 1).setValue(session.usuario);
    sh.getRange(existingRowIndex, iV   + 1).setValue(valor);
    sh.getRange(existingRowIndex, iC   + 1).setValue(comentario || '');
    sh.getRange(existingRowIndex, iER  + 1).setValue(estadoFinal);
    sh.getRange(existingRowIndex, iVer + 1).setValue(nuevaVersion);

    logAuditoria({
      usuario: session.usuario, accion: 'UPDATE',
      periodo, modulo: moduloU, id_indicador,
      valor_anterior: valorAnterior, valor_nuevo: valor
    });
  }

  return buildOk({
    ts,
    periodo,
    modulo     : moduloU,
    id_indicador,
    valor,
    estado_registro: estadoFinal
  });
}

// ── ENDPOINT: POST /setPeriodoEstado ─────────────────────────

function handleSetPeriodoEstado(session, body) {
  if (session.rol !== ROLES.ADMIN) return buildError('Solo ADMIN puede cambiar estado de períodos', 403);

  const { periodo, estado } = body;
  if (!periodo) return buildError('"periodo" requerido', 400);
  if (!estado)  return buildError('"estado" requerido (ABIERTO/REVISION/CERRADO)', 400);

  const estadoU = String(estado).toUpperCase();
  if (!['ABIERTO','REVISION','CERRADO'].includes(estadoU)) {
    return buildError('Estado debe ser ABIERTO, REVISION o CERRADO', 400);
  }

  const sh    = getSheet(SHEET_PERIODOS);
  const data  = sh.getDataRange().getValues();
  const headers = data[0].map(h => String(h).toLowerCase().trim());
  const iP  = headers.indexOf('periodo');
  const iE  = headers.indexOf('estado');
  const iFC = headers.indexOf('fecha_cierre');

  let found = false;
  for (let r = 1; r < data.length; r++) {
    if (String(data[r][iP]) === String(periodo)) {
      sh.getRange(r + 1, iE + 1).setValue(estadoU);
      if (estadoU === 'CERRADO') {
        sh.getRange(r + 1, iFC + 1).setValue(new Date().toISOString());
      }
      found = true;
      break;
    }
  }

  if (!found) {
    // Crear período si no existe
    appendRow(SHEET_PERIODOS, [
      periodo, estadoU, new Date().toISOString(), estadoU === 'CERRADO' ? new Date().toISOString() : ''
    ]);
  }

  logAuditoria({
    usuario: session.usuario, accion: 'UPDATE',
    periodo, modulo: 'SISTEMA', id_indicador: '',
    valor_anterior: '', valor_nuevo: 'ESTADO=' + estadoU
  });

  return buildOk({ periodo, estado: estadoU });
}

// ── ENDPOINT: GET /controlCarga ──────────────────────────────

function handleControlCarga(session, params) {
  if (session.rol !== ROLES.ADMIN && session.rol !== ROLES.COORDINADOR) {
    return buildError('Acceso denegado', 403);
  }

  const periodo = String(params.periodo || '').trim();

  const indicadores = sheetToObjects(SHEET_INDICADORES).filter(i =>
    String(i.activo).toUpperCase() === 'TRUE'
  );
  const capturas = sheetToObjects(SHEET_CAPTURAS).filter(c =>
    (!periodo || String(c.periodo) === periodo)
  );

  // Agrupar por módulo
  const moduloSet = new Set(indicadores.map(i => String(i.modulo).toUpperCase()));
  const result = {};

  moduloSet.forEach(mod => {
    // COORDINADOR solo ve sus módulos
    if (session.rol !== ROLES.ADMIN && !canAccessModulo(session, mod)) return;

    const inds = indicadores.filter(i => String(i.modulo).toUpperCase() === mod);
    const reqs = inds.filter(i => String(i.requerido).toUpperCase() === 'TRUE');
    const caps = capturas.filter(c => String(c.modulo).toUpperCase() === mod);

    const recibidos    = caps.filter(c => String(c.estado_registro).toUpperCase() === 'ENVIADO').length;
    const borradores   = caps.filter(c => String(c.estado_registro).toUpperCase() === 'BORRADOR').length;
    const faltantesReq = reqs.filter(r =>
      !caps.find(c => String(c.id_indicador) === String(r.id_indicador))
    );

    result[mod] = {
      total_indicadores  : inds.length,
      total_requeridos   : reqs.length,
      enviados           : recibidos,
      borradores,
      faltantes_requeridos: faltantesReq.map(f => f.id_indicador),
      completitud_pct    : inds.length > 0 ? Math.round((caps.length / inds.length) * 100) : 0,
      ultimo_cambio      : caps.length > 0
        ? caps.reduce((max, c) => c.ts > max ? c.ts : max, '')
        : ''
    };
  });

  return buildOk({ periodo, control: result });
}

// ── ENDPOINT: GET /exportCSV ──────────────────────────────────

function handleExportCSV(session, params) {
  if (session.rol !== ROLES.ADMIN) return buildError('Solo ADMIN puede exportar', 403);

  const periodo = String(params.periodo || '').trim();
  if (!periodo) return buildError('"periodo" requerido', 400);

  const indicadores = sheetToObjects(SHEET_INDICADORES);
  const capturas    = sheetToObjects(SHEET_CAPTURAS).filter(c =>
    String(c.periodo) === periodo
  );

  // Enriquecer capturas con descripción del indicador
  const enriched = capturas.map(c => {
    const ind = indicadores.find(i => String(i.id_indicador) === String(c.id_indicador));
    return {
      ...c,
      indicador_nombre: ind ? ind.indicador   : '',
      unidad          : ind ? ind.unidad       : '',
      descripcion     : ind ? ind.descripcion  : ''
    };
  });

  // Construir CSV
  const cols = ['ts','periodo','usuario','modulo','id_indicador','indicador_nombre',
                 'unidad','valor','comentario','estado_registro','version','descripcion'];
  const header = cols.join(',');
  const rows   = enriched.map(r =>
    cols.map(c => '"' + String(r[c] || '').replace(/"/g, '""') + '"').join(',')
  );

  const csv = [header, ...rows].join('\n');
  return buildOk({ csv, periodo, total_filas: rows.length });
}

// ── AUDITORÍA ────────────────────────────────────────────────

function logAuditoria({ usuario, accion, periodo, modulo, id_indicador, valor_anterior, valor_nuevo }) {
  try {
    appendRow(SHEET_AUDITORIA, [
      new Date().toISOString(),
      usuario,
      accion,
      periodo,
      modulo,
      id_indicador,
      valor_anterior,
      valor_nuevo
    ]);
  } catch (e) {
    console.error('Error logAuditoria:', e);
  }
}

// ── VALIDACIÓN DE TIPO_DATO ───────────────────────────────────

/**
 * Valida valor según tipo_dato e regla_validacion opcional.
 * Retorna null si ok, o string con el error.
 */
function validateTipoDato(valor, tipo_dato, regla_validacion, requerido) {
  const esRequerido = String(requerido).toUpperCase() === 'TRUE';

  if (valor === null || valor === undefined || String(valor).trim() === '') {
    if (esRequerido) return 'Este indicador es requerido';
    return null; // vacío permitido si no es requerido
  }

  const v = String(valor).trim();

  switch (String(tipo_dato).toUpperCase()) {
    case 'NUMERO':
    case 'DECIMAL':
      if (isNaN(Number(v))) return 'El valor debe ser numérico';
      break;
    case 'ENTERO':
      if (!/^-?\d+$/.test(v)) return 'El valor debe ser un número entero';
      break;
    case 'PORCENTAJE':
      const pct = Number(v);
      if (isNaN(pct) || pct < 0 || pct > 100) return 'El valor debe ser un porcentaje entre 0 y 100';
      break;
    case 'TEXTO':
      if (v.length > 2000) return 'El texto no puede superar 2000 caracteres';
      break;
    case 'BOOLEAN':
      if (!['TRUE','FALSE','1','0','SI','NO','SÍ'].includes(v.toUpperCase())) {
        return 'El valor debe ser SI o NO';
      }
      break;
    case 'FECHA':
      if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return 'El valor debe ser una fecha YYYY-MM-DD';
      break;
  }

  // Regla de validación personalizada (ej: "MIN:0,MAX:1000")
  if (regla_validacion) {
    const reglas = String(regla_validacion).split(',');
    const num    = Number(v);
    for (const regla of reglas) {
      const [key, val] = regla.split(':');
      switch (key.toUpperCase().trim()) {
        case 'MIN':
          if (!isNaN(num) && num < Number(val)) return 'El valor mínimo permitido es ' + val;
          break;
        case 'MAX':
          if (!isNaN(num) && num > Number(val)) return 'El valor máximo permitido es ' + val;
          break;
        case 'REGEX':
          try {
            if (!new RegExp(val).test(v)) return 'El valor no cumple el formato requerido';
          } catch (_) {}
          break;
      }
    }
  }

  return null;
}

// ── SETUP INICIAL (ejecutar una sola vez desde el editor) ─────

/**
 * Ejecutar manualmente desde el editor de Apps Script para crear
 * las hojas y cargar datos iniciales.
 */
function setupInitialData() {
  const ss = SpreadsheetApp.openById(SPREADSHEET_ID);

  function ensureSheet(name, headers) {
    let sh = ss.getSheetByName(name);
    if (!sh) {
      sh = ss.insertSheet(name);
    }
    // Solo escribe encabezados si la hoja está vacía
    if (sh.getLastRow() === 0) {
      sh.appendRow(headers);
    }
    return sh;
  }

  // 1. Usuarios
  ensureSheet(SHEET_USUARIOS, ['usuario','hash_password','nombre','rol','activo']);

  // 2. Asignación usuario-módulo
  ensureSheet(SHEET_USUARIOS_MODULOS, ['usuario','modulo','activo']);

  // 3. Períodos
  const shPer = ensureSheet(SHEET_PERIODOS, ['periodo','estado','fecha_apertura','fecha_cierre']);
  if (shPer.getLastRow() <= 1) {
    shPer.appendRow(['2026-02', 'ABIERTO', new Date().toISOString(), '']);
  }

  // 4. Indicadores
  ensureSheet(SHEET_INDICADORES,
    ['id_indicador','modulo','indicador','unidad','tipo_dato','requerido',
     'regla_validacion','orden','activo','descripcion','ayuda']);

  // 5. Capturas
  ensureSheet(SHEET_CAPTURAS,
    ['ts','periodo','usuario','modulo','id_indicador','valor',
     'comentario','estado_registro','version']);

  // 6. Auditoría
  ensureSheet(SHEET_AUDITORIA,
    ['ts','usuario','accion','periodo','modulo','id_indicador','valor_anterior','valor_nuevo']);

  // 7. Usuario admin inicial
  // Contraseña: Admin123! → SHA-256
  const adminHash = sha256Hex('Admin123!');
  const shU = ss.getSheetByName(SHEET_USUARIOS);
  if (shU.getLastRow() <= 1) {
    shU.appendRow(['admin', adminHash, 'Administrador', 'ADMIN', 'TRUE']);
    shU.appendRow(['coordinador1', sha256Hex('Coord123!'), 'Coordinador Área', 'COORDINADOR', 'TRUE']);
    shU.appendRow(['social1', sha256Hex('Social123!'), 'Responsable Social', 'USER', 'TRUE']);
    shU.appendRow(['th1', sha256Hex('TH123!'), 'Responsable TH', 'USER', 'TRUE']);
  }

  // 8. Asignaciones ejemplo
  const shUM = ss.getSheetByName(SHEET_USUARIOS_MODULOS);
  if (shUM.getLastRow() <= 1) {
    // admin no necesita asignaciones (acceso total por rol)
    // coordinador con múltiples módulos
    shUM.appendRow(['coordinador1', 'SOCIAL',    'TRUE']);
    shUM.appendRow(['coordinador1', 'TH',        'TRUE']);
    shUM.appendRow(['coordinador1', 'LOGISTICA', 'TRUE']);
    shUM.appendRow(['social1',      'SOCIAL',    'TRUE']);
    shUM.appendRow(['th1',          'TH',        'TRUE']);
  }

  // 9. Indicadores ejemplo (SSL_INDUSTRIAL, TH, SOCIAL)
  const shInd = ss.getSheetByName(SHEET_INDICADORES);
  if (shInd.getLastRow() <= 1) {
    const inds = [
      ['TH_001','TH','Total de empleados directos','personas','ENTERO','TRUE','MIN:0','1','TRUE','Número total de empleados con contrato directo a fin de mes','Incluir solo contratos vigentes al último día del mes'],
      ['TH_002','TH','Total de empleados contratistas','personas','ENTERO','TRUE','MIN:0','2','TRUE','Número de empleados de empresas contratistas operando en planta','Promedio del mes o al último día'],
      ['TH_003','TH','Nuevas contrataciones en el mes','personas','ENTERO','FALSE','MIN:0','3','TRUE','Ingresos en el período',''],
      ['TH_004','TH','Desvinculaciones en el mes','personas','ENTERO','FALSE','MIN:0','4','TRUE','Bajas en el período','Incluir renuncias, despidos y jubilaciones'],
      ['TH_005','TH','Tasa de rotación mensual','%','PORCENTAJE','TRUE','MIN:0,MAX:100','5','TRUE','(Desvinculaciones / Total empleados) x 100','Calcular al cierre del mes'],
      ['TH_006','TH','Horas de capacitación total','horas','NUMERO','FALSE','MIN:0','6','TRUE','Suma total de horas de formación impartidas en el mes','Presencial + virtual'],
      ['TH_007','TH','Porcentaje de empleadas mujeres','%','PORCENTAJE','TRUE','MIN:0,MAX:100','7','TRUE','(Empleadas mujeres / Total empleados) x 100',''],
      ['SOC_001','SOCIAL','Comunidades visitadas en el mes','cantidad','ENTERO','TRUE','MIN:0','1','TRUE','Número de comunidades con visita presencial de relacionamiento',''],
      ['SOC_002','SOCIAL','Reuniones con líderes comunitarios','cantidad','ENTERO','TRUE','MIN:0','2','TRUE','Reuniones formales e informales con líderes',''],
      ['SOC_003','SOCIAL','Beneficiarios de programas sociales','personas','ENTERO','TRUE','MIN:0','3','TRUE','Cantidad de personas beneficiadas por programas sociales del mes',''],
      ['SOC_004','SOCIAL','Compromisos sociales vencidos','cantidad','ENTERO','TRUE','MIN:0','4','TRUE','Compromisos con comunidades que vencieron en el mes sin cumplir','Deben ser accionados en el mes siguiente'],
      ['SOC_005','SOCIAL','Compromisos sociales cumplidos','cantidad','ENTERO','TRUE','MIN:0','5','TRUE','Compromisos cumplidos en el mes',''],
      ['SOC_006','SOCIAL','Índice de percepción positiva (%)','%','PORCENTAJE','FALSE','MIN:0,MAX:100','6','TRUE','Porcentaje de percepciones positivas sobre PARACEL en la comunidad','Basado en encuesta o reporte de Asuntos Comunitarios'],
      ['SSL_001','SSL_INDUSTRIAL','Accidentes con tiempo perdido','cantidad','ENTERO','TRUE','MIN:0','1','TRUE','Accidentes que generaron ausencia del trabajador',''],
      ['SSL_002','SSL_INDUSTRIAL','Índice de frecuencia de accidentes','IF','DECIMAL','TRUE','MIN:0','2','TRUE','(Accidentes x 1.000.000) / Horas trabajadas','Calculado por SSOMA'],
      ['SSL_003','SSL_INDUSTRIAL','Horas trabajadas en el mes','horas','NUMERO','TRUE','MIN:0','3','TRUE','Total de horas-hombre trabajadas en el período','Incluir contratistas'],
      ['FOR_001','FORESTAL','Hectáreas plantadas en el mes','ha','DECIMAL','TRUE','MIN:0','1','TRUE','Superficie plantada en el período',''],
      ['FOR_002','FORESTAL','Hectáreas cosechadas en el mes','ha','DECIMAL','FALSE','MIN:0','2','TRUE','Superficie con cosecha finalizada en el período',''],
      ['LOG_001','LOGISTICA','Viajes de transporte realizados','viajes','ENTERO','TRUE','MIN:0','1','TRUE','Total de viajes de transporte de producto en el mes',''],
      ['LOG_002','LOGISTICA','Toneladas transportadas','ton','DECIMAL','TRUE','MIN:0','2','TRUE','Toneladas de materia prima o producto transportadas',''],
      ['AMB_001','AMBIENTAL','Consumo de agua (m³)','m³','DECIMAL','TRUE','MIN:0','1','TRUE','Volumen total de agua captada y utilizada en planta',''],
      ['AMB_002','AMBIENTAL','Residuos peligrosos generados (kg)','kg','DECIMAL','TRUE','MIN:0','2','TRUE','Peso de residuos peligrosos generados en el mes',''],
      ['COM_001','COMPRAS','Órdenes de compra emitidas','cantidad','ENTERO','TRUE','MIN:0','1','TRUE','Número de órdenes de compra generadas en el mes',''],
      ['COM_002','COMPRAS','Monto total de compras (USD)','USD','DECIMAL','TRUE','MIN:0','2','TRUE','Valor total de compras del mes en dólares',''],
      ['FIN_001','FINANZAS','Ingresos del mes (USD)','USD','DECIMAL','TRUE','','1','TRUE','Ingresos operacionales del mes',''],
      ['FIN_002','FINANZAS','Gastos operativos del mes (USD)','USD','DECIMAL','TRUE','','2','TRUE','Gastos operativos totales del mes',''],
      ['IND_001','INDUSTRIAL','Producción total (ton)','ton','DECIMAL','TRUE','MIN:0','1','TRUE','Toneladas producidas en el mes',''],
      ['IND_002','INDUSTRIAL','Eficiencia de planta (%)','%','PORCENTAJE','TRUE','MIN:0,MAX:100','2','TRUE','(Producción real / Producción planificada) x 100','']
    ];
    inds.forEach(row => shInd.appendRow(row));
  }

  // Recordatorio de configurar el secreto
  SpreadsheetApp.getUi().alert(
    '✅ Setup completado.\n\n' +
    'IMPORTANTE: Ve a Proyecto > Propiedades del proyecto > Propiedades de script\n' +
    'y agrega la propiedad:\n' +
    '  Nombre: JWT_SECRET\n' +
    '  Valor: (una cadena secreta larga y aleatoria, mínimo 32 caracteres)\n\n' +
    'Usuarios iniciales creados:\n' +
    '  admin / Admin123!\n' +
    '  coordinador1 / Coord123!\n' +
    '  social1 / Social123!\n' +
    '  th1 / TH123!'
  );
}

/**
 * Utility: Genera el hash SHA-256 de un password para insertarlo manualmente.
 * Ejecutar desde el editor: hashPassword('MiClave123!')
 */
function hashPassword(pwd) {
  const h = sha256Hex(pwd);
  console.log('SHA-256 de "' + pwd + '": ' + h);
  return h;
}
