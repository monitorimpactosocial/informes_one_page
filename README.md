# Sistema de Indicadores Mensuales — PARACEL

App web mobile-first para carga mensual de indicadores por área.  
**Stack:** GitHub Pages (HTML/CSS/JS) + Google Apps Script (API REST) + Google Sheets (DB).

---

## Tabla de Contenidos

1. [Arquitectura](#arquitectura)
2. [Setup: Google Sheets](#1-configurar-google-sheets)
3. [Setup: Apps Script](#2-configurar-google-apps-script)
4. [Setup: Frontend](#3-configurar-el-frontend)
5. [Deploy a GitHub Pages](#4-deploy-a-github-pages)
6. [Usuarios y permisos](#5-gestión-de-usuarios-y-permisos)
7. [Pruebas de seguridad](#6-pruebas-de-seguridad)
8. [Guía UI/UX y WCAG](#7-guía-uiux-y-checklist-wcag-aa)

---

## Arquitectura

```
GitHub Pages  ←→  Apps Script Web App  ←→  Google Sheets
  index.html       Code.gs (REST API)       6 hojas normalizadas
  styles.css       Token HMAC-SHA256
  app.js           Control de permisos
```

**Hojas de cálculo:**

| Hoja | Propósito |
|------|-----------|
| `usuarios` | Credenciales (hash SHA-256), roles |
| `usuarios_modulos` | Asignación usuario↔módulo |
| `periodos` | Períodos YYYY-MM y estado |
| `indicadores` | Catálogo de indicadores por módulo |
| `capturas` | Valores cargados (formato largo) |
| `auditoria` | Log completo de acciones |

---

## 1. Configurar Google Sheets

### 1.1 Crear la planilla

1. Ir a [sheets.google.com](https://sheets.google.com) → **Crear nueva hoja de cálculo**
2. Nombrarla: `PARACEL — Indicadores Mensuales`

### 1.2 Ejecutar el setup automático

> El script `setupInitialData()` crea todas las hojas y carga datos iniciales.  
> Lo harás en el Paso 2. No hace falta crear hojas manualmente.

### 1.3 Estructura de hojas (referencia)

**`usuarios`**
| usuario | hash_password | nombre | rol | activo |
|---------|--------------|--------|-----|--------|
| admin | `sha256("Admin123!")` | Administrador | ADMIN | TRUE |

**`usuarios_modulos`**
| usuario | modulo | activo |
|---------|--------|--------|
| social1 | SOCIAL | TRUE |
| coordinador1 | SOCIAL | TRUE |
| coordinador1 | TH | TRUE |

**`periodos`**
| periodo | estado | fecha_apertura | fecha_cierre |
|---------|--------|---------------|-------------|
| 2026-02 | ABIERTO | 2026-02-01T00:00:00Z | |

**`indicadores`**
| id_indicador | modulo | indicador | unidad | tipo_dato | requerido | regla_validacion | orden | activo | descripcion | ayuda |
|---|---|---|---|---|---|---|---|---|---|---|
| TH_001 | TH | Total empleados directos | personas | ENTERO | TRUE | MIN:0 | 1 | TRUE | … | … |

**`capturas`** (formato largo — una fila por indicador por período)
| ts | periodo | usuario | modulo | id_indicador | valor | comentario | estado_registro | version |
|---|---|---|---|---|---|---|---|---|

**`auditoria`**
| ts | usuario | accion | periodo | modulo | id_indicador | valor_anterior | valor_nuevo |
|---|---|---|---|---|---|---|---|

---

## 2. Configurar Google Apps Script

### 2.1 Crear el proyecto

1. En la planilla, ir a **Extensiones → Apps Script**
2. Borrar el código `function myFunction()` existente
3. Copiar todo el contenido de `apps_script/Code.gs` y pegarlo
4. Guardar (Ctrl+S)

### 2.2 Configurar el secreto JWT

1. En el editor de Apps Script: **Proyecto → Propiedades del proyecto → Propiedades de script**
2. Agregar:
   - **Nombre:** `JWT_SECRET`
   - **Valor:** una cadena aleatoria de al menos 32 caracteres (ej: `pArAcEl!2026$ind1c@dores#sEcr3t`)
3. Guardar

> ⚠️ **NUNCA** pongas el secreto en el código, solo en Script Properties.

### 2.3 Ejecutar el setup inicial

1. En el editor, seleccionar la función `setupInitialData` en el dropdown
2. Hacer clic en **Ejecutar**
3. Autorizar los permisos cuando se solicite
4. Aparecerá un alert con los usuarios iniciales creados

**Usuarios iniciales creados:**

| Usuario | Contraseña | Rol | Módulos |
|---------|-----------|-----|---------|
| `admin` | `Admin123!` | ADMIN | Todos |
| `coordinador1` | `Coord123!` | COORDINADOR | SOCIAL, TH, LOGISTICA |
| `social1` | `Social123!` | USER | SOCIAL |
| `th1` | `TH123!` | USER | TH |

> ⚠️ Cambiar las contraseñas inmediatamente después del primer login.

### 2.4 Publicar como Web App

1. **Implementar → Nueva implementación**
2. Tipo: **App web**
3. Configuración:
   - **Descripción:** `PARACEL Indicadores v1`
   - **Ejecutar como:** `Yo (tu cuenta)`
   - **Quién tiene acceso:** `Cualquier usuario`
4. Hacer clic en **Implementar**
5. Copiar la **URL de la app web** (la necesitarás en el paso siguiente)

> La URL tiene la forma:  
> `https://script.google.com/macros/s/AKfycby.../exec`

---

## 3. Configurar el Frontend

Abrir `web/app.js` y reemplazar la URL de la API:

```js
// Línea ~8 de app.js
const CONFIG = {
  API_URL: 'https://script.google.com/macros/s/TU_SCRIPT_ID_AQUI/exec',
  // ...
};
```

---

## 4. Deploy a GitHub Pages

### 4.1 Crear repositorio

```bash
# En la carpeta ONEPAGE/
git init
git add .
git commit -m "feat: sistema de indicadores mensuales v1"

# Crear repo en GitHub (sin README) y conectar:
git remote add origin https://github.com/TU_ORG/paracel-indicadores.git
git branch -M main
git push -u origin main
```

### 4.2 Activar GitHub Pages

1. Ir al repositorio en GitHub → **Settings → Pages**
2. Source: `Deploy from a branch`
3. Branch: `main` | Folder: `/web`
4. Guardar

La app estará en: `https://TU_ORG.github.io/paracel-indicadores/`

### 4.3 Actualizar CORS en Apps Script (si es necesario)

Si el dominio de GitHub Pages es nuevo, verificar que la Web App responde correctamente haciendo un request de prueba desde la consola del navegador.

---

## 5. Gestión de Usuarios y Permisos

### Agregar un nuevo usuario

1. Abrir la hoja `usuarios` en Google Sheets
2. Agregar una fila:
   ```
   | nuevo_usuario | <hash_sha256> | Nombre Apellido | USER | TRUE |
   ```
3. Para obtener el hash: en el editor de Apps Script, ejecutar:
   ```js
   hashPassword('LaContraseña123!')
   // → copia el hash del log de ejecución
   ```

### Asignar módulos al usuario

En la hoja `usuarios_modulos`, agregar una fila por módulo:
```
| nuevo_usuario | SOCIAL    | TRUE |
| nuevo_usuario | LOGISTICA | TRUE |
```

- **USER** con 1 módulo → ve solo ese módulo sin tabs
- **USER** con N módulos → se recomienda cambiar rol a **COORDINADOR**
- **ADMIN** → no necesita filas en `usuarios_modulos`, tiene acceso total

### Revocar acceso a un módulo

Cambiar `activo` a `FALSE` en la fila correspondiente de `usuarios_modulos`.  
El próximo login del usuario ya no incluirá ese módulo en su token.

### Desactivar un usuario

Cambiar `activo` a `FALSE` en la hoja `usuarios`. El sistema devuelve 403 inmediatamente.

### Módulos disponibles

| Código | Nombre display |
|--------|----------------|
| `SSL_INDUSTRIAL` | SSL Industrial |
| `FORESTAL` | Forestal |
| `TH` | Talento Humano |
| `LOGISTICA` | Logística |
| `AMBIENTAL` | Ambiental |
| `COMPRAS` | Compras |
| `SOCIAL` | Social |
| `FINANZAS` | Finanzas |
| `INDUSTRIAL` | Industrial |

### Agregar un nuevo módulo

1. Agregar indicadores en la hoja `indicadores` con el código del nuevo módulo
2. Asignar el módulo a usuarios en `usuarios_modulos`
3. Agregar la etiqueta en `MODULOS_LABELS` en `app.js`:
   ```js
   NUEVO_MODULO: 'Mi Nuevo Módulo',
   ```

---

## 6. Pruebas de Seguridad

Ejecutar estas pruebas desde la consola del navegador (F12) o con `curl`:

### Prueba 1 — Login exitoso
```js
// En consola del navegador, en la página de la app:
const url = 'https://script.google.com/macros/s/TU_ID/exec?action=login';
const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('Admin123!'));
const hex = [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2,'0')).join('');
const r = await fetch(url, {method:'POST',body:JSON.stringify({usuario:'admin',password:hex}),headers:{'Content-Type':'application/json'}});
const d = await r.json();
console.log(d); // ✅ Esperado: { ok: true, token: "...", rol: "ADMIN", modulos_permitidos: [] }
```

### Prueba 2 — Login fallido (contraseña incorrecta)
```js
const r = await fetch('URL?action=login', {method:'POST',body:JSON.stringify({usuario:'admin',password:'hash_incorrecto'}),headers:{'Content-Type':'application/json'}});
const d = await r.json();
console.log(d.__status, d.error); // ✅ Esperado: 401 "Credenciales inválidas"
```

### Prueba 3 — Acción sin token
```js
const r = await fetch('URL?action=indicadores&modulo=TH');
const d = await r.json();
console.log(d.__status); // ✅ Esperado: 401
```

### Prueba 4 — Acceso a módulo no asignado ★ (prueba de seguridad crítica)
```js
// Primero, loguear como social1 (solo tiene módulo SOCIAL)
// Luego intentar leer indicadores de FINANZAS con ese token:
const r = await fetch('URL?action=indicadores&modulo=FINANZAS&t=TOKEN_DE_SOCIAL1');
const d = await r.json();
console.log(d.__status, d.error); // ✅ Esperado: 403 "Sin acceso al módulo"
```

### Prueba 5 — upsertCaptura en módulo no asignado
```js
const r = await fetch('URL?action=upsertCaptura', {
  method: 'POST',
  headers: {'Content-Type':'application/json'},
  body: JSON.stringify({
    periodo:'2026-02', modulo:'FINANZAS',
    id_indicador:'FIN_001', valor:'99999',
    __token: 'TOKEN_DE_SOCIAL1'
  })
});
const d = await r.json();
console.log(d.__status, d.error); // ✅ Esperado: 403 "Sin acceso al módulo"
```

### Prueba 6 — Período cerrado
```js
// Primero cerrar el período 2026-02 con ADMIN.
// Luego intentar escribir:
// Esperado: 403 "El período está CERRADO, no se pueden guardar datos"
```

### Prueba 7 — Token expirado/manipulado
```js
// Tomar un token válido y modificar el payload manualmente:
const r = await fetch('URL?action=me&t=payload_falso.firma_falsificada');
const d = await r.json();
console.log(d.__status); // ✅ Esperado: 401
```

### Prueba 8 — Usuario inactivo
```js
// Cambiar activo=FALSE para social1 en la hoja usuarios
// Intentar login: Esperado: 403 "Usuario inactivo"
```

---

## 7. Guía UI/UX y Checklist WCAG AA

### Contraste de colores (verificado)

| Token | Valor | Ratio text/bg | ¿Cumple AA? |
|-------|-------|---------------|-------------|
| `--text` `#111827` sobre `--bg` `#f8fafc` | texto principal | ~15:1 | ✅ AAA |
| `--text-muted` `#374151` sobre `--bg` | textos secundarios | ~8:1 | ✅ AAA |
| `--text-subtle` `#4b5563` sobre `--bg` | ayudas | ~6:1 | ✅ AA |
| `--primary` `#1d4ed8` sobre `#fff` | botón primario (texto blanco) | ~7.5:1 | ✅ AA |
| `--success` `#166534` sobre `#dcfce7` | badge OK | ~7.1:1 | ✅ AA |
| `--error` `#991b1b` sobre `#fee2e2` | badge error | ~8.3:1 | ✅ AA |
| `--warning` `#92400e` sobre `#fef3c7` | badge warning | ~7.2:1 | ✅ AA |

### Checklist WCAG AA

**Percepción**
- [x] Contraste texto ≥ 4.5:1 (textos normales) — cumplido con margen
- [x] Contraste ≥ 3:1 para componentes UI (bordes de inputs, botones)
- [x] No se usa solo el color para transmitir información (íconos + etiquetas)
- [x] Placeholders con contraste suficiente

**Operación**
- [x] Toda funcionalidad accesible con teclado (`Tab`, `Enter`, `Escape`)
- [x] Focus visible en todos los elementos interactivos (`:focus-visible`)
- [x] Skip navigation link al inicio
- [x] Sin trampas de foco (modales tienen botón de cierre)
- [x] Inputs táctiles ≥ 44px de altura

**Comprensión**
- [x] Labels asociados a inputs con `for`/`id`
- [x] Mensajes de error bajo el campo (no solo alerta general)
- [x] Resumen de errores con links a campos
- [x] Feedbacks con timestamp ("Guardado a las HH:MM")
- [x] Confirmación antes de acción irreversible (modal "Enviar")

**Robustez**
- [x] HTML semántico (`main`, `header`, `nav`, `h1/h2/h3`)
- [x] `aria-live` para mensajes dinámicos
- [x] `role` en tabs, dialogs, tabpanels
- [x] `aria-required`, `aria-invalid` en inputs
- [x] `aria-label` en botones icon-only

### Wireframes de vistas

**Vista USER (1 módulo)**
```
┌──────────────────────────────────────────┐
│ [Logo] Talento Humano — PARACEL   ⏻ Salir│  ← header fijo
├──────────────────────────────────────────┤
│ MÓDULO    PERÍODO     ESTADO   RESPONSAB.│  ← module-header
│ Tal.Hum.  Feb 2026   ABIERTO   María G.  │
├──────────────────────────────────────────┤
│ ─── Indicadores ─────────────── (3/7) ─  │
│  ★ Total empleados directos               │
│  [    150      ] personas  [ℹ]            │
│  ─────────────────────────────────────── │
│  ★ Total contratistas                     │
│  [    30       ] personas  [ℹ]            │
│  ─────────────────────────────────────── │
│  ★ Tasa de rotación                       │
│  [    2.5      ] %         [ℹ]            │
│  ⚠ Debe ser entre 0 y 100                 │
└─────────────────────────── ─────────────┘
 Sin cambios guardados    [Borrador] [Enviar]  ← sticky
```

**Vista COORDINADOR (N módulos)**
```
┌──────────────────────────────────────────┐
│ [Logo] PARACEL                    ⏻ Salir│
├──────────────────────────────────────────┤
│ [Social] [Tal.Humano] [Logística]        │  ← tabs
├──────────────────────────────────────────┤
│ (contenido del tab activo)               │
└──────────────────────────────────────────┘
```

**Vista ADMIN — Tablero**
```
┌──────────────────────────────────────────┐
│ [Logo] PARACEL            [ADMIN] ⏻ Salir│
├──────────────────────────────────────────┤
│ [⊞ Tablero][SOCIAL][TH][FOR][...][Config]│
├──────────────────────────────────────────┤
│ Filtros: [Período ▾] [Módulo ▾] [↻] [CSV]│
│                                          │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│ │ SOCIAL   │ │ TH       │ │ FORESTAL │  │
│ │ ████▓░ 75%│ │ ████░░ 60%│ │ ██░░░░ 40%│  │
│ │ 6/8 ind. │ │ 4/7 ind  │ │ 2/5 ind  │  │
│ │ ENVIADO  │ │ BORRADOR │ │ Sin datos│  │
│ └──────────┘ └──────────┘ └──────────┘  │
└──────────────────────────────────────────┘
```

---

## Estructura del Repositorio

```
/
├── web/
│   ├── index.html      ← App shell + pantalla login
│   ├── app.js          ← Auth, Router, Forms, Admin
│   └── styles.css      ← Design system mobile-first
├── apps_script/
│   └── Code.gs         ← Backend completo
└── README.md
```

---

## Notas de Seguridad

- Las contraseñas nunca viajan en texto plano. El cliente hashea con `crypto.subtle.digest` (SHA-256) antes de enviar.
- El backend valida NUEVAMENTE el hash contra la base de datos.
- El token HMAC-SHA256 tiene TTL de 8 horas y no puede ser falsificado sin conocer `JWT_SECRET`.
- **Toda verificación de permisos es en el backend.** El frontend es solo UI; manipularlo no bypasea la seguridad.
- El token se guarda en `sessionStorage` (no `localStorage`), se elimina al cerrar la pestaña.
- Toda escritura queda registrada en la hoja `auditoria`.
