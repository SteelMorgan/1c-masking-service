'use strict';
/*++agent TASK-224 [24.09.2026] — единый JS нового UI (старт/активация/admin/viewer).
   CSRF только в памяти вкладки (Б11); reveal-данные не кэшируются и не
   сохраняются в web storage; тема — единственное значение в localStorage. */

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

const state = { session: null };

//**agent TASK-225 [26.09.2026 02:10:00] фаза 3: ошибки setup API несут details
// (errors[] разбора файла, missing/unknown id подтверждений, автор конфликта черновика).
// class ApiErr extends Error {
//   constructor(status, code, message, correlationId) {
//     super(message || 'Операция не выполнена');
//     this.status = status;
//     this.code = code || '';
//     this.correlationId = correlationId || '';
//   }
// }
class ApiErr extends Error {
  constructor(status, code, message, correlationId, details) {
    super(message || 'Операция не выполнена');
    this.status = status;
    this.code = code || '';
    this.correlationId = correlationId || '';
    this.details = details || null;
  }
}
//**agent TASK-225

async function api(path, options = {}, retried = false) {
  const headers = new Headers(options.headers || {});
  if (options.body !== undefined) headers.set('Content-Type', 'application/json');
  if (options.method && options.method !== 'GET' && state.session) {
    headers.set('X-CSRF-Token', state.session.csrf_token);
  }
  if (options.csrf) headers.set('X-CSRF-Token', options.csrf);
  const response = await fetch(path, {
    method: options.method || 'GET',
    headers,
    body: options.body,
    credentials: 'same-origin',
    cache: 'no-store',
  });
  if (response.status === 401 && state.session) {
    location.assign('/?expired=1');
    throw new ApiErr(401, 'AUTHENTICATION_FAILED', 'Сеанс завершён');
  }
  if (response.status === 403 && state.session && !retried && options.method && options.method !== 'GET') {
    // CSRF мог устареть — восстанавливаем из GET /session (Б11) и повторяем раз.
    try {
      const fresh = await fetch('/api/v1/session', { credentials: 'same-origin', cache: 'no-store' });
      if (fresh.ok) state.session = await fresh.json();
      return await api(path, options, true);
    } catch (_) { /* fallthrough to error below */ }
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const err = body && body.error ? body.error : {};
    //**agent TASK-225 [26.09.2026 02:10:00]
    // throw new ApiErr(response.status, err.code, err.message, err.correlation_id);
    throw new ApiErr(response.status, err.code, err.message, err.correlation_id, err.details);
    //**agent TASK-225
  }
  if (response.status === 204 || response.status === 202) return null;
  return response.json();
}
//++agent TASK-225 [26.09.2026 02:40:00] скачивание attachment (экспорт настройки):
// fetch+blob, чтобы ошибки API показывались в UI, а имя брать из Content-Disposition.
async function downloadFile(path, fallbackName) {
  const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store' });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const err = body && body.error ? body.error : {};
    throw new ApiErr(response.status, err.code, err.message || `HTTP ${response.status}`, err.correlation_id, err.details);
  }
  const cd = response.headers.get('Content-Disposition') || '';
  const m = cd.match(/filename\*=UTF-8''([^;]+)/i) || cd.match(/filename="?([^";]+)"?/i);
  let name = fallbackName;
  if (m) { try { name = decodeURIComponent(m[1]); } catch (_) { name = m[1]; } }
  const url = URL.createObjectURL(await response.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  return name;
}
//++agent TASK-225

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showError(node, error) {
  if (!node) return;
  const suffix = error && error.correlationId ? ` Код обращения: ${error.correlationId}` : '';
  node.textContent = (error && error.message ? error.message : 'Операция не выполнена') + suffix;
  node.hidden = false;
}

/*++agent TASK-224 [24.09.2026] итерация 2 — короткий GUID для fallback-имён баз. */
const shortId = value => (value.length > 12 ? `${value.slice(0, 6)}…${value.slice(-4)}` : value);

/* Кнопка «скопировать» с визуальным подтверждением; без clipboard API — noop. */
const copyButton = (value, label) => {
  const btn = el('button', 'copy-link', label || 'скопировать ID');
  btn.type = 'button';
  btn.addEventListener('click', async event => {
    event.stopPropagation();
    try {
      await navigator.clipboard.writeText(value);
      btn.textContent = 'скопировано';
      setTimeout(() => { btn.textContent = label || 'скопировать ID'; }, 1500);
    } catch (_) {
      btn.textContent = 'не удалось';
    }
  });
  return btn;
};

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function fmtAgo(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const diff = Date.now() - d.getTime();
  if (diff < 60_000) return 'только что';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} мин назад`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} ч назад`;
  return d.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' });
}

function fmtCountdown(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

function closeOverlays() {
  $$('.overlay').forEach(o => o.classList.remove('on'));
  $$('.menu').forEach(m => m.classList.remove('on'));
}

function openOverlay(id) {
  closeOverlays();
  const node = $('#' + id);
  if (node) node.classList.add('on');
}

function copyText(text, button) {
  const done = () => {
    const original = button.textContent;
    button.textContent = 'Скопировано';
    setTimeout(() => { button.textContent = original; }, 1200);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done, done);
  } else {
    const area = el('textarea');
    area.value = text;
    document.body.append(area);
    area.select();
    try { document.execCommand('copy'); } catch (_) { /* копирование недоступно */ }
    area.remove();
    done();
  }
}

// Тема: по системе + ручной переключатель; localStorage — единственное
// несекретное удобство, разрешённое дизайном.
function applyStoredTheme() {
  try {
    const stored = localStorage.getItem('masking-theme');
    if (stored === 'dark' || stored === 'light') document.documentElement.dataset.theme = stored;
  } catch (_) { /* storage может быть недоступен */ }
}

function toggleTheme() {
  const root = document.documentElement;
  const dark = root.dataset.theme
    ? root.dataset.theme === 'dark'
    : matchMedia('(prefers-color-scheme: dark)').matches;
  const next = dark ? 'light' : 'dark';
  root.dataset.theme = next;
  try { localStorage.setItem('masking-theme', next); } catch (_) { /* не критично */ }
}

function wireProfile(session) {
  $('#profileName').textContent = session.login || '';
  $('#profileBtn').addEventListener('click', () => $('#profileMenu').classList.toggle('on'));
  $('#menuTheme').addEventListener('click', () => { toggleTheme(); closeOverlays(); });
  $('#menuLogout').addEventListener('click', async () => {
    try { await api('/auth/logout', { method: 'POST' }); } catch (_) { /* выходим локально */ }
    state.session = null;
    location.assign('/');
  });
  $('#menuPassword').addEventListener('click', () => {
    $('#passErr').hidden = true;
    $('#passOk').hidden = true;
    $('#passForm').reset();
    openOverlay('dlgPass');
  });
  $('#passCancel').addEventListener('click', closeOverlays);
  $('#passForm').addEventListener('submit', async event => {
    event.preventDefault();
    $('#passErr').hidden = true;
    $('#passOk').hidden = true;
    const current = $('#pwCurrent').value;
    const next = $('#pwNew').value;
    if (next !== $('#pwRepeat').value) {
      showError($('#passErr'), { message: 'Новые пароли не совпадают' });
      return;
    }
    try {
      const fresh = await api('/api/v1/session/password', {
        method: 'POST',
        body: JSON.stringify({ current_password: current, new_password: next }),
      });
      state.session = fresh; // новый CSRF из ответа
      $('#passForm').reset();
      $('#passOk').hidden = false;
    } catch (error) {
      showError($('#passErr'), error.status === 401
        ? { message: 'Текущий пароль неверен или новый совпадает со старым' }
        : error);
    }
  });
}

// ---------- Стартовый экран ----------

async function startPage() {
  const showScreen = id => $$('.screen').forEach(s => s.classList.toggle('on', s.id === id));
  const setTab = tab => {
    $('#tabBtnLogin').classList.toggle('on', tab === 'login');
    $('#tabBtnInvite').classList.toggle('on', tab === 'invite');
    $('#paneLogin').hidden = tab !== 'login';
    $('#paneInvite').hidden = tab !== 'invite';
  };
  $('#tabBtnLogin').addEventListener('click', () => setTab('login'));
  $('#tabBtnInvite').addEventListener('click', () => setTab('invite'));

  if (new URLSearchParams(location.search).get('expired') === '1') {
    $('#noticeExpired').hidden = false;
    history.replaceState(null, '', '/');
  }

  // Б9: сервис без первого администратора → экран «ещё не настроен».
  const checkStatus = async () => {
    try {
      const status = await api('/api/v1/status');
      if (status.bootstrap_required) {
        showScreen('s-notinit');
        return true;
      }
      if (status.version) {
        $('#versionLine').textContent = `Версия сервиса: ${status.version}`;
        $('#versionLine').hidden = false;
      }
    } catch (_) { /* статус недоступен — показываем обычный вход */ }
    return false;
  };
  $('#recheckStatus').addEventListener('click', async () => {
    if (!(await checkStatus())) showScreen('s-start');
  });
  $('#copyCmd').addEventListener('click', e => copyText($('#bootstrapCmd').textContent, e.currentTarget));
  $('#firstRunLink').addEventListener('click', () => showScreen('s-notinit'));
  if (await checkStatus()) return;

  // Живая сессия → сразу в раздел (сервер тоже редиректит, это страховка).
  try {
    const session = await api('/api/v1/session');
    location.assign(session.role === 'Admin' ? '/admin' : '/viewer');
    return;
  } catch (_) { /* сессии нет — форма входа */ }

  let loginLockUntil = 0;
  let lockTimer = null;
  const lockLogin = () => {
    loginLockUntil = Date.now() + 60_000;
    $('#loginLimited').hidden = false;
    $('#loginSubmit').disabled = true;
    clearInterval(lockTimer);
    lockTimer = setInterval(() => {
      const left = Math.ceil((loginLockUntil - Date.now()) / 1000);
      if (left <= 0) {
        clearInterval(lockTimer);
        $('#loginLimited').hidden = true;
        $('#loginSubmit').disabled = false;
        return;
      }
      $('#loginTimer').textContent = String(left);
    }, 500);
  };

  $('#paneLogin').addEventListener('submit', async event => {
    event.preventDefault();
    if (Date.now() < loginLockUntil) return;
    $('#loginErr').hidden = true;
    try {
      const session = await api('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ login: $('#loginName').value, password: $('#loginPassword').value }),
      });
      state.session = session;
      location.assign(session.role === 'Admin' ? '/admin' : '/viewer');
    } catch (error) {
      if (error.status === 429) {
        lockLogin();
        return;
      }
      $('#loginPassword').value = '';
      $('#loginPassword').focus();
      showError($('#loginErr'), {
        message: error.status === 503
          ? `Сервис временно недоступен.${error.correlationId ? ` Код обращения: ${error.correlationId}` : ''}`
          : 'Неверный логин или пароль, либо вход для учётной записи недоступен.',
      });
    }
  });

  $('#inviteForm').addEventListener('submit', event => {
    event.preventDefault();
    $('#inviteErr').hidden = true;
    const raw = $('#inviteInput').value.trim();
    // Принимаем целую ссылку или код: последний сегмент пути, без пробелов.
    const token = raw.split('/').filter(Boolean).pop()?.replace(/\s+/g, '') || '';
    if (!token || token.length > 128) {
      showError($('#inviteErr'), { message: 'Вставьте код приглашения или ссылку целиком.' });
      return;
    }
    location.assign(`/activate/${encodeURIComponent(token)}`);
  });
}

// ---------- Активация ----------

async function activatePage() {
  const showScreen = id => $$('.screen').forEach(s => s.classList.toggle('on', s.id === id));
  const token = decodeURIComponent(location.pathname.replace(/^\/activate\/?/, ''));
  // Код убираем из адресной строки сразу (история/скриншоты без токена).
  history.replaceState(null, '', '/');
  if (!token || token.length > 128) {
    showScreen('s-invalid');
    return;
  }

  let login = '';
  try {
    const info = await api(`/auth/activate/${encodeURIComponent(token)}`);
    login = info.login;
  } catch (error) {
    if (error.status === 429) {
      $('#actLimited').hidden = false;
      showScreen('s-form');
    } else {
      showScreen('s-invalid');
    }
    return;
  }
  $('#actLogin').textContent = login;
  showScreen('s-form');

  const check = () => {
    const a = $('#actP1').value;
    const ok1 = a.length >= 12 && a.length <= 1024;
    const ok2 = ok1 && a === $('#actP2').value;
    $('#actC1').classList.toggle('ok', ok1);
    $('#actC2').classList.toggle('ok', ok2);
    $('#actSubmit').disabled = !ok2;
  };
  $('#actP1').addEventListener('input', check);
  $('#actP2').addEventListener('input', check);

  $('#activateForm').addEventListener('submit', async event => {
    event.preventDefault();
    $('#actErr').hidden = true;
    $('#actLimited').hidden = true;
    $('#actSubmit').disabled = true;
    try {
      // CSRF для активации — сам код приглашения (double-submit).
      const session = await api(`/auth/activate/${encodeURIComponent(token)}`, {
        method: 'POST',
        csrf: token,
        body: JSON.stringify({ password: $('#actP1').value }),
      });
      state.session = session;
      showScreen('s-done');
      location.assign(session.role === 'Admin' ? '/admin' : '/viewer');
    } catch (error) {
      $('#actSubmit').disabled = false;
      if (error.status === 429) {
        $('#actLimited').hidden = false;
      } else if (error.code === 'PASSWORD_POLICY') {
        showError($('#actErr'), { message: 'Пароль не подходит: нужно от 12 до 1024 символов.' });
      } else if (error.status === 403) {
        showError($('#actErr'), { message: 'Откройте ссылку в обычном окне браузера по адресу сервиса.' });
      } else {
        showScreen('s-invalid');
      }
    }
  });
}

// ---------- Отчёт (общий рендер для viewer) ----------
//++agent TASK-224 [24.09.2026] итерация 3
// Табличные блоки — через изолированный MaskingGrid (web/grid.js): вход
// {columns, rows}, без знаний о backend. Reveal-дифф и маск-токены приходят
// снаружи через renderCell; CSV-экспорт отдаёт то, что на экране
// (exportRows); реальные — после подтверждения (TASK-225, realCopy).
//--agent TASK-224

//++agent TASK-224 [25.09.2026 12:25:00] итерация 5: иконки — inline SVG через
// createElementNS (emoji в окружении не рендерятся; CSP запрещает внешние
// ресурсы). Набор минимальный — только то, что использует UI.
const SVG_ICONS = {
  lock: ['M7 11V8a5 5 0 0 1 10 0v3', 'M5 11h14v10H5z'],
  eye: ['M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z', 'M12 9a3 3 0 1 0 0 6a3 3 0 0 0 0-6z'],
  copy: ['M9 9h11v11H9z', 'M5 15V4h11'],
};
function svgIcon(name, size) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', size ? `ico ${size}` : 'ico');
  svg.setAttribute('aria-hidden', 'true');
  for (const d of SVG_ICONS[name] || []) {
    const path = document.createElementNS(NS, 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  return svg;
}
//++agent TASK-224

//++agent TASK-224 [25.09.2026 12:40:00] итерация 5
function ruPlural(n, one, few, many) {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
}
//++agent TASK-224

const MASK_TOKEN = /\[MASK:v1:[^\]]+\]|‹[^›]+›/g;

function appendMaskedText(target, text) {
  // Подсветка маск-токенов внутри скалярного значения.
  let rest = String(text);
  let match;
  MASK_TOKEN.lastIndex = 0;
  while ((match = MASK_TOKEN.exec(rest)) !== null) {
    if (match.index > 0) target.append(document.createTextNode(rest.slice(0, match.index)));
    target.append(el('span', 'm', match[0]));
    rest = rest.slice(match.index + match[0].length);
    MASK_TOKEN.lastIndex = 0;
  }
  if (rest) target.append(document.createTextNode(rest));
}

//**agent TASK-225 [26.09.2026 03:00:00] decorate(node, blockIndex, rowIndex, column) —
// подсветка ячеек причины «Почему скрыто» (B9) без знания о причинах внутри рендера.
// function renderReport(target, report, maskedReport, grids, exportPrefix) {
//**agent TASK-225 [27.09.2026 09:16:39] realCopy = {confirm(proceed), notify()}
// function renderReport(target, report, maskedReport, grids, exportPrefix, decorate) {
function renderReport(target, report, maskedReport, grids, exportPrefix, decorate, realCopy) {
//**agent TASK-225
//**agent TASK-225
  target.replaceChildren();
  // Старые grid-инстансы уничтожаем — снимаются их document-слушатели.
  if (grids) {
    grids.forEach(grid => grid.destroy());
    grids.length = 0;
  }
  if (!report || report.version !== 1 || !Array.isArray(report.blocks)) {
    target.append(el('p', 'muted', 'Отчёт недоступен.'));
    return;
  }
  report.blocks.forEach((block, index) => {
    const maskedBlock = maskedReport && maskedReport.blocks ? maskedReport.blocks[index] : null;
    if (block.kind === 'text' && typeof block.text === 'string') {
      const pre = el('pre', 'report');
      const changed = maskedBlock && maskedBlock.kind === 'text' && maskedBlock.text !== block.text;
      if (changed) {
        // Раскрытый текст целиком помечаем как «реальные значения».
        pre.classList.add('r');
        pre.textContent = block.text;
      } else {
        appendMaskedText(pre, block.text);
      }
      if (decorate) decorate(pre, index, null, null); // TASK-225
      target.append(pre);
    } else if (block.kind === 'table' && Array.isArray(block.columns) && Array.isArray(block.rows)) {
      const host = el('div');
      target.append(host);
      if (!window.MaskingGrid) {
        host.append(el('p', 'muted', 'Табличный модуль не загружен.'));
        return;
      }
      const grid = window.MaskingGrid.create(host, {
        columns: block.columns,
        rows: block.rows,
        exportFileName: `${exportPrefix || 'report'}-${index + 1}.csv`,
        //**agent TASK-225 [27.09.2026 09:16:39] блокировка выгрузки раскрытых
        // значений ничего не защищала (текст выделяется и копируется хоткеем):
        // CSV/«Копировать» выгружают то, что на экране, а реальные — только
        // после подтверждения человека (realCopy от просмотрщика).
        // // CSV — всегда маскированная версия блока, независимо от того, что
        // // показано на экране.
        // exportRows: () => (maskedBlock
        //   ? { columns: maskedBlock.columns || block.columns, rows: maskedBlock.rows || block.rows }
        //   : { columns: block.columns, rows: block.rows }),
        exportRows: () => ({ columns: block.columns, rows: block.rows }),
        realValues: !!maskedReport,
        confirmReal: realCopy && realCopy.confirm,
        onRealCopied: realCopy && realCopy.notify,
        //**agent TASK-225
        renderCell: (td, value, rowIndex, colIndex, type) => {
          const maskedValue = maskedBlock && maskedBlock.rows && maskedBlock.rows[rowIndex]
            ? maskedBlock.rows[rowIndex][colIndex] : undefined;
          const changed = maskedBlock && JSON.stringify(maskedValue) !== JSON.stringify(value);
          //**agent TASK-224 [25.09.2026 12:25:00] итерация 5: ru-формат по типу
          // const display = value === null ? '—' : String(value);
          const display = window.MaskingGrid.formatValue
            ? window.MaskingGrid.formatValue(value, type)
            : (value === null ? '—' : String(value));
          //**agent TASK-224
          if (changed) {
            td.append(el('span', 'r', display));
          } else {
            appendMaskedText(td, display);
          }
          if (decorate) decorate(td, index, rowIndex, block.columns[colIndex]); // TASK-225
        },
      });
      //--agent TASK-225 [27.09.2026 09:16:39] выгрузка раскрытых значений разрешена
      // if (maskedReport) {
      //   grid.setExportEnabled(false,
      //     'Экспорт недоступен, пока показаны реальные значения — CSV выгружает только маскированные.');
      // }
      //--agent TASK-225
      if (grids) grids.push(grid);
    }
  });
}

// ---------- Viewer ----------

//++agent TASK-224 [08.10.2026] итерация 4: все машинные статусы —
// русские подписи (terminal_denial — «отклонено»), fallback остаётся
// для неизвестных будущих кодов.
const OUTCOME_LABELS = {
  tool_result: ['ok', 'выполнено'],
  transport_error: ['err', 'ошибка транспорта'],
  sanitized_error: ['err', 'ошибка обработки'],
  terminal_denial: ['err', 'отклонено'],
  denied: ['err', 'отклонено'],
};

//++agent TASK-225 [27.09.2026 12:00:00] штатные отказы защиты 1С и сервиса
// не должны выглядеть как сбой: код из результата вызова → вид + пояснение.
// Вид: protection — защита сработала штатно (информационный тег), config —
// поправить настройку, query — ошибка текста запроса, technical — сбой.
const CALL_ERROR_KIND = {
  protection: ['acc', 'Защита сработала'],
  config: ['warn', 'Нужна настройка'],
  query: ['warn', 'Ошибка запроса'],
  technical: ['err', 'Технический сбой'],
};
const LINEAGE_TECH = {
  kind: 'protection', title: 'Не удалось проверить происхождение колонок',
  hint: 'Проверка происхождения колонок технически не выполнилась, поэтому результат не выдан ради безопасности. Упростите запрос или повторите позже.',
};
const DICT_HINT = 'Откройте настройку словаря в админке и исправьте источник значений.';
const CALL_ERROR_CODES = {
  SOURCE_LINEAGE_UNVERIFIED: {
    kind: 'protection', title: 'Выражение над защищёнными полями запрещено',
    hint: 'Запрос вычисляет значение из полей (ПОДСТРОКА, склейка, агрегат, условие по полю), происхождение которого нельзя однозначно проверить. Так можно вытащить секрет или ПДн по частям, поэтому результат не выдан. Выбирайте поле напрямую, без преобразований.',
  },
  LINEAGE_INVALID_SCHEMA: LINEAGE_TECH,
  LINEAGE_NATIVE_UNAVAILABLE: LINEAGE_TECH,
  SECRET_SCAN_DEPTH_LIMIT: {
    kind: 'protection', title: 'Результат слишком глубоко вложен',
    hint: 'Проверить такой результат на секреты невозможно, поэтому он не выдан. Уменьшите вложенность выборки.',
  },
  DICTIONARY_SECRET_SOURCE_DENIED: { kind: 'config', title: 'Источник словаря — секретное поле', hint: `Секретное поле нельзя использовать источником словаря. ${DICT_HINT}` },
  DICTIONARY_SOURCE_NOT_ALLOWED: { kind: 'config', title: 'Источник словаря не разрешён', hint: `Источник не входит в допустимые. ${DICT_HINT}` },
  DICTIONARY_SOURCE_TYPE_UNSUPPORTED: { kind: 'config', title: 'Тип источника словаря не поддерживается', hint: `Источником словаря может быть только строковое поле. ${DICT_HINT}` },
  DICTIONARY_WILDCARD_ALLOWLIST_REQUIRED: { kind: 'config', title: 'Шаблону источника нужен список разрешённых', hint: `Источник задан шаблоном (*) — перечислите разрешённые объекты явно. ${DICT_HINT}` },
  DICTIONARY_SELECTOR_INVALID: { kind: 'config', title: 'Некорректный селектор словаря', hint: `Селектор источника не распознан. ${DICT_HINT}` },
  DICTIONARY_SOURCE_INVALID: { kind: 'config', title: 'Некорректный источник словаря', hint: `Источник словаря не найден или задан неверно. ${DICT_HINT}` },
  ACTION_REQUIRED: { kind: 'config', title: 'База требует настройки', hint: 'Маскирование для базы ещё не настроено: завершите настройку в админке, затем повторите вызов.' },
  QUERY_PARSE_ERROR: { kind: 'query', title: 'Ошибка в тексте запроса', hint: 'Запрос не разобран — это не защита. Исправьте синтаксис запроса.' },
  QUERY_EXECUTION_ERROR: { kind: 'query', title: 'Ошибка выполнения запроса в 1С', hint: 'Запрос разобран, но 1С не смогла его выполнить. Проверьте имена таблиц, полей и параметры.' },
  CURSOR_INVALID: { kind: 'technical', title: 'Курсор выборки недействителен', hint: 'Курсор устарел или повреждён — запросите данные заново с начала.' },
  METADATA_SELECTOR_INVALID: { kind: 'technical', title: 'Некорректный селектор метаданных', hint: 'Проверьте имя объекта метаданных в вызове.' },
  FILTER_AST_UNSUPPORTED: { kind: 'technical', title: 'Фильтр не поддерживается', hint: 'Упростите условие отбора.' },
  SOURCE_TOOL_FAILED: { kind: 'technical', title: 'Инструмент-источник завершился ошибкой', hint: 'Сбой на стороне 1С — подробности в журнале регистрации.' },
  FEED_: { kind: 'technical', title: 'Ошибка ленты данных', hint: 'Технический сбой выдачи данных — повторите позже.' },
  SERVICE_RESULT_UNAVAILABLE: { kind: 'technical', title: 'Результат недоступен', hint: 'Сервис не смог безопасно обработать результат. Найдите correlation_id в журнале сервиса.' },
  SERVICE_TEMP_UNAVAILABLE: { kind: 'technical', title: 'Операция временно недоступна', hint: 'Временный сбой сервиса или связи с 1С — повторите позже; correlation_id — для журнала.' },
};
// Тексты, которые сервис пишет в историю сам (safe_*_error в service.rs).
const CALL_ERROR_TEXTS = [
  [/^База требует настройки пользователем/, 'ACTION_REQUIRED'],
  [/^Результат недоступен/, 'SERVICE_RESULT_UNAVAILABLE'],
  [/^Операция временно недоступна/, 'SERVICE_TEMP_UNAVAILABLE'],
];
const callErrorInfo = code => CALL_ERROR_CODES[code]
  || (typeof code === 'string' && code.startsWith('FEED_') ? CALL_ERROR_CODES.FEED_ : null);
// Ищет известный код в тексте блока: JSON {"error":"КОД"} / {"error":{"code":…}}
// (возможно внутри content[].text), иначе — служебные фразы сервиса.
// Неизвестный код → null (запись рисуется как раньше).
function detectCallError(record) {
  const report = record && record.report;
  if (!report || !Array.isArray(report.blocks)) return null;
  const fromValue = (value, depth) => {
    if (!value || typeof value !== 'object' || depth > 4) return null;
    const err = value.error;
    const code = typeof err === 'string' ? err : (err && typeof err.code === 'string' ? err.code : null);
    if (code && callErrorInfo(code)) {
      return { code, message: typeof value.message === 'string' ? value.message : (err && err.message) || '' };
    }
    if (value.structured_content) { const hit = fromValue(value.structured_content, depth + 1); if (hit) return hit; }
    if (Array.isArray(value.content)) {
      for (const c of value.content) { const hit = c && typeof c.text === 'string' ? fromText(c.text, depth + 1) : null; if (hit) return hit; }
    }
    return null;
  };
  const fromText = (text, depth) => {
    const t = text.trim();
    if (t.startsWith('{')) {
      try { const hit = fromValue(JSON.parse(t), depth); if (hit) return hit; } catch (_) { /* не JSON */ }
    }
    for (const [re, code] of CALL_ERROR_TEXTS) if (re.test(t)) return { code, message: t };
    return null;
  };
  for (const block of report.blocks) {
    if (block && block.kind === 'text' && typeof block.text === 'string') {
      const hit = fromText(block.text, 0);
      if (hit) return { ...hit, ...callErrorInfo(hit.code) };
    }
  }
  return null;
}
// Статус записи для тега: распознанный отказ перекрывает outcome.
function callStatus(record) {
  const hit = detectCallError(record);
  if (hit) {
    const [cls, label] = CALL_ERROR_KIND[hit.kind];
    return { cls, label, hit };
  }
  const [cls, label] = OUTCOME_LABELS[record.outcome] || ['mut', record.outcome];
  return { cls, label, hit: null };
}
//++agent TASK-225

//++agent TASK-225 [27.09.2026 12:30:00] текст запроса — блок кода «как в
// конфигураторе»: подсветка ключевых слов языка запросов 1С, строк, чисел,
// комментариев и параметров. Только отображение: собирается из текстовых
// узлов (без innerHTML), копируется исходный текст.
const QUERY_KEYWORDS = new Set((
  'ВЫБРАТЬ ИЗ ГДЕ И ИЛИ НЕ КАК ПЕРВЫЕ РАЗЛИЧНЫЕ РАЗРЕШЕННЫЕ СОЕДИНЕНИЕ ЛЕВОЕ ПРАВОЕ ВНУТРЕННЕЕ ПОЛНОЕ ПО '
  + 'СГРУППИРОВАТЬ УПОРЯДОЧИТЬ УБЫВ ВОЗР ИМЕЮЩИЕ ОБЪЕДИНИТЬ ВСЕ ВЫБОР КОГДА ТОГДА ИНАЧЕ КОНЕЦ ЕСТЬ NULL '
  + 'ЗНАЧЕНИЕ ПОДОБНО МЕЖДУ В ИЕРАРХИИ ИСТИНА ЛОЖЬ НЕОПРЕДЕЛЕНО КОЛИЧЕСТВО СУММА МАКСИМУМ МИНИМУМ СРЕДНЕЕ '
  + 'ПОДСТРОКА ВЫРАЗИТЬ ДАТАВРЕМЯ ПОМЕСТИТЬ ИНДЕКСИРОВАТЬ ССЫЛКА ДЛЯ ИЗМЕНЕНИЯ ИТОГИ '
  + 'SELECT FROM WHERE AND OR NOT AS TOP DISTINCT ALLOWED JOIN LEFT RIGHT INNER FULL OUTER ON BY GROUP ORDER '
  + 'DESC ASC HAVING UNION ALL CASE WHEN THEN ELSE END IS VALUE LIKE BETWEEN IN HIERARCHY TRUE FALSE UNDEFINED '
  + 'COUNT SUM MAX MIN AVG SUBSTRING CAST DATETIME INTO INDEX REFS FOR UPDATE TOTALS'
).split(' '));
// Перед этими словами — перенос строки при переформатировании однострочного запроса.
const QUERY_BREAK_BEFORE = new Set('ИЗ ГДЕ СГРУППИРОВАТЬ УПОРЯДОЧИТЬ ИМЕЮЩИЕ ОБЪЕДИНИТЬ ЛЕВОЕ ПРАВОЕ ВНУТРЕННЕЕ ПОЛНОЕ СОЕДИНЕНИЕ FROM WHERE GROUP ORDER HAVING UNION LEFT RIGHT INNER FULL JOIN'.split(' '));
const QUERY_JOIN_QUAL = new Set('ЛЕВОЕ ПРАВОЕ ВНУТРЕННЕЕ ПОЛНОЕ LEFT RIGHT INNER FULL OUTER'.split(' '));
const QUERY_TOKEN_RE = /(\/\/[^\n]*)|("(?:[^"]|"")*"?)|(&[\wА-Яа-яЁё]+)|(\d+(?:\.\d+)?)|([A-Za-zА-Яа-яЁё_][\wА-Яа-яЁё]*)|(\s+)|([^\s])/gu;
function tokenizeQuery(text) {
  const out = [];
  QUERY_TOKEN_RE.lastIndex = 0;
  let m;
  while ((m = QUERY_TOKEN_RE.exec(text))) {
    const kind = m[1] ? 'cm' : m[2] ? 'str' : m[3] ? 'par' : m[4] ? 'num'
      : m[5] ? (QUERY_KEYWORDS.has(m[5].toUpperCase()) ? 'kw' : 'id') : m[6] ? 'ws' : 'p';
    out.push({ kind, text: m[0] });
  }
  return out;
}
// Однострочный длинный запрос → переносы перед ключевыми разделами.
function reflowQuery(tokens, source) {
  if (source.includes('\n') || source.length <= 80) return tokens;
  let prevWord = '';
  let seenWord = false;
  return tokens.map((tok, i) => {
    if (tok.kind === 'ws') {
      const next = tokens[i + 1];
      const up = next && next.kind === 'kw' ? next.text.toUpperCase() : '';
      const brk = seenWord && QUERY_BREAK_BEFORE.has(up)
        && !((up === 'СОЕДИНЕНИЕ' || up === 'JOIN' || up === 'OUTER') && QUERY_JOIN_QUAL.has(prevWord));
      return brk ? { kind: 'ws', text: '\n' } : tok;
    }
    if (tok.kind === 'kw' || tok.kind === 'id') { prevWord = tok.text.toUpperCase(); seenWord = true; }
    return tok;
  });
}
function renderQueryCode(node, text) {
  node.replaceChildren();
  reflowQuery(tokenizeQuery(text), text).forEach(tok => {
    if (tok.kind === 'ws' || tok.kind === 'id' || tok.kind === 'p') node.append(document.createTextNode(tok.text));
    else node.append(el('span', `q-${tok.kind}`, tok.text));
  });
}
//++agent TASK-225

async function viewerPage() {
  let session;
  try {
    session = await api('/api/v1/session');
  } catch (_) {
    location.assign('/?expired=1');
    return;
  }
  state.session = session;
  wireProfile(session);

  const viewer = {
    databases: [],
    database: null,
    chat: null,
    record: null,
    revealed: null, // только в памяти; сбрасывается при уходе с записи
    //++agent TASK-224 [24.09.2026] итерация 3
    showMasked: false, // переключатель «Показать маскированное»
    grids: [], // живые MaskingGrid-инстансы отчёта (для destroy/export)
    //--agent TASK-224
  };

  const crumbs = () => {
    const box = $('#crumbs');
    box.replaceChildren();
    const home = el('button', '', 'Базы');
    home.type = 'button';
    home.addEventListener('click', () => { viewer.database = null; selectDatabase(null); });
    box.append(home);
    if (viewer.database) {
      //++agent TASK-224 [08.10.2026] итерация 4: крошки не дублируют GUID —
      // либо заданное имя, либо короткий GUID с копированием полного.
      box.append(document.createTextNode(' › '));
      if (viewer.database.display_label) {
        box.append(document.createTextNode(viewer.database.display_label));
      } else {
        const short = el('span', 'mono small', shortId(viewer.database.id));
        short.title = viewer.database.id;
        box.append(short);
      }
      box.append(copyButton(viewer.database.id));
      //--agent TASK-224
    }
    if (viewer.chat) {
      //++agent TASK-224 [08.10.2026] имя чата обрезается с конца
      // (CSS ellipsis), полное — в title.
      const name = el('span', 'mono small clip', `чат ${viewer.chat.chat_id}`);
      name.title = viewer.chat.chat_id;
      box.append(document.createTextNode(' › '), name);
      //--agent TASK-224
    }
    if (viewer.record) box.append(document.createTextNode(` › ${fmtTime(viewer.record.created_at)}`));
  };

  const listInto = (target, items, render, emptyText) => {
    target.replaceChildren();
    if (!items.length) {
      target.append(el('p', 'empty', emptyText));
      return;
    }
    items.forEach(item => target.append(render(item)));
  };

  const selectDatabase = db => {
    viewer.database = db;
    viewer.chat = null;
    viewer.record = null;
    viewer.revealed = null;
    viewer.showMasked = false;
    $('#chatsHead').hidden = !db;
    $('#recordsHead').hidden = true;
    $('#reportCard').hidden = true;
    $('#chatList').replaceChildren();
    $('#recordList').replaceChildren();
    $$('#dbList > button').forEach(b => b.classList.toggle('on', b.dataset.id === (db && db.id)));
    //**agent TASK-225 [26.09.2026 04:30:00] кнопка в верхней панели: видна всегда, активна при выбранной базе
    // $('#vExportBtn').hidden = !db; // TASK-225
    $('#vExportBtn').disabled = !db;
    $('#vExportBtn').title = db ? `Экспорт действующей настройки базы ${db.display_label || shortId(db.id)}` : 'Сначала выберите базу';
    //**agent TASK-225
    crumbs();
    if (db) loadChats(db);
  };

  const selectChat = chat => {
    viewer.chat = chat;
    viewer.record = null;
    viewer.revealed = null;
    viewer.showMasked = false;
    $('#recordsHead').hidden = false;
    $('#reportCard').hidden = true;
    $$('#chatList > button').forEach(b => b.classList.toggle('on', b.dataset.id === chat.chat_id));
    crumbs();
    loadHistory(chat);
  };

  //++agent TASK-224 [24.09.2026] итерация 3
  // Перерисовка отчёта по текущему состоянию: раскрытое (если есть и не
  // выключено переключателем) с дифф-подсветкой .r, иначе маскированное.
  const applyReportView = () => {
    if (!viewer.record) return;
    const revealed = viewer.revealed && !viewer.showMasked;
    renderReport(
      $('#reportBody'),
      revealed ? viewer.revealed : viewer.record.report,
      revealed ? viewer.record.report : null,
      viewer.grids,
      viewer.record.id,
      whyDecorate, // TASK-225
      realCopy, // TASK-225: подтверждение выгрузки реальных значений
    );
    $('#revealNote').hidden = !revealed;
    $('#maskToggle').hidden = !viewer.revealed;
    //++agent TASK-224 [08.10.2026] итерация 4: переключатель «Оригинал» —
    // нажатое состояние = показаны реальные значения.
    //**agent TASK-224 [25.09.2026 12:25:00] итерация 5: сегменты вместо кнопки
    // $('#maskToggle').classList.toggle('on', !!revealed);
    $$('#maskToggle button').forEach(b => b.classList.toggle('on', (b.dataset.view === 'real') === !!revealed));
    //**agent TASK-224
    //--agent TASK-224
  };

  //++agent TASK-224 [08.10.2026] итерация 4
  // Шапка отчёта: заголовок — текст запроса (report.title) или имя
  // инструмента; справа — статус записи, инструмент, время, признак
  // маскированного хранения.
  const renderReportHead = record => {
    const report = record.report || {};
    const title = $('#reportTitle');
    const text = (typeof report.title === 'string' && report.title.trim())
      ? report.title
      : record.tool_name;
    //**agent TASK-225 [27.09.2026 12:30:00] запрос — подсвеченный блок кода + копирование
    // title.textContent = text;
    const isQuery = typeof report.title === 'string' && !!report.title.trim();
    title.classList.toggle('qcode', isQuery);
    if (isQuery) renderQueryCode(title, text); else title.textContent = text;
    title.title = text;
    $$('.rep-q .q-copy').forEach(n => n.remove());
    if (isQuery) {
      const copy = copyButton(text, 'копировать запрос');
      copy.classList.add('q-copy');
      title.after(copy);
    }
    //**agent TASK-225
    //++agent TASK-224 [25.09.2026 12:25:00] итерация 5: свёрнут до 2 строк;
    // «Развернуть» — только если текст реально обрезан.
    title.classList.add('clamp');
    const more = $('#reportMore');
    more.textContent = 'Развернуть';
    requestAnimationFrame(() => { more.hidden = title.scrollHeight <= title.clientHeight + 1; });
    //++agent TASK-224
    //**agent TASK-225 [27.09.2026 12:00:00] штатный отказ — вид + пояснение
    // const [cls, label] = OUTCOME_LABELS[record.outcome] || ['mut', record.outcome];
    const { cls, label, hit } = callStatus(record);
    const status = $('#reportStatus');
    status.className = `tag ${cls}`;
    status.textContent = label;
    status.title = hit ? `${hit.title}. ${hit.hint}` : '';
    const note = $('#callNote');
    note.hidden = !hit;
    if (hit) {
      note.className = `note ${hit.kind === 'protection' ? 'info' : hit.kind === 'technical' ? 'err' : 'warn'}`;
      const head = el('b', '', hit.title);
      const code = el('span', 'mono small muted', hit.code);
      code.title = hit.message || hit.code;
      note.replaceChildren(head, document.createTextNode(' '), code,
        el('div', 'hint', hit.hint));
    }
    //**agent TASK-225
    const meta = $('#reportMeta');
    //**agent TASK-224 [25.09.2026 12:25:00] итерация 5: meta — иконки, русская метка
    // meta.replaceChildren(
    //   el('span', 'mono', record.tool_name),
    //   document.createTextNode(` · ${shortId(record.id)} · ${fmtTime(record.created_at)} · `),
    //   el('span', 'tag mut', 'masked'),
    // );
    const idSpan = el('span', 'mono', shortId(record.id));
    idSpan.title = record.id;
    const stored = el('span', 'tag plain');
    stored.append(svgIcon('lock', 'sm'), document.createTextNode('хранится маскированным'));
    meta.replaceChildren(
      el('span', 'mono', record.tool_name), el('span', 'dot', '·'),
      idSpan, el('span', 'dot', '·'),
      el('span', '', fmtTime(record.created_at)), el('span', 'dot', '·'),
      stored,
    );
    //**agent TASK-224
  };
  //--agent TASK-224

  const selectRecord = record => {
    viewer.record = record;
    viewer.revealed = null;
    viewer.showMasked = false;
    $$('#recordList > button').forEach(b => b.classList.toggle('on', b.dataset.id === record.id));
    crumbs();
    $('#reportCard').hidden = false;
    renderReportHead(record);
    $('#revealNote').hidden = true;
    $('#revealWarn').hidden = true;
    $('#revealErr').hidden = true;
    $('#maskToggle').hidden = true;
    $$('#maskToggle button').forEach(b => b.classList.remove('on'));
    //**agent TASK-225 [26.09.2026 03:00:00] сброс панели «Почему скрыто»
    // renderReport($('#reportBody'), record.report, null, viewer.grids, record.id);
    resetWhy();
    renderReport($('#reportBody'), record.report, null, viewer.grids, record.id, whyDecorate);
    //**agent TASK-225
    // Раскрытие автоматическое при открытии записи — без диалога. Ответ
    // применяется, только если пользователь ещё на этой записи.
    api(`/api/v1/history/${encodeURIComponent(record.id)}/reveal`, { method: 'POST' })
      .then(report => {
        if (viewer.record !== record) return;
        viewer.revealed = report;
        applyReportView();
      })
      .catch(error => {
        if (viewer.record !== record || error.status === 401) return;
        //++agent TASK-225 [27.09.2026 12:30:00] соответствия для раскрытия
        // живут только в памяти сервиса (migrations/0009_call_contexts.sql) —
        // после перезапуска/истечения срока 404 штатен: нейтральная подсказка.
        const warn = $('#revealWarn');
        warn.className = 'note warn';
        if (error.code === 'MAPPING_UNAVAILABLE') warn.className = 'note info';
        if (error.status === 404 || error.code === 'NOT_FOUND') {
          warn.className = 'note info';
          showError(warn, { message: 'Раскрытие недоступно: данные для раскрытия хранятся только в памяти сервиса и были очищены (перезапуск сервиса или истёк срок хранения). Маскированный результат остаётся доступен.' });
          return;
        }
        //++agent TASK-225
        // Не стена ошибки: маскированный отчёт уже на экране, плашка — warn.
        showError($('#revealWarn'), error.code === 'MAPPING_UNAVAILABLE'
          ? { message: 'Реальные значения недоступны: срок хранения соответствий истёк или сервис перезапускался. Показаны маскированные данные.' }
          : { message: `Раскрытие не удалось — показаны маскированные данные. ${error.message}` });
      });
  };
  //--agent TASK-224

  const loadDatabases = async () => {
    try {
      viewer.databases = await api('/api/v1/databases');
    } catch (error) {
      if (error.status !== 401) showError($('#viewerErr'), error);
      return;
    }
    listInto($('#dbList'), viewer.databases, db => {
      const btn = el('button');
      btn.type = 'button';
      btn.dataset.id = db.id;
      //++agent TASK-224 [08.10.2026] безымянная база — «без названия» +
      // короткий GUID, а не полный id вместо имени.
      btn.append(el('b', '', db.display_label || 'без названия'), document.createElement('br'),
        el('span', 'mono small muted', shortId(db.id)), document.createTextNode(' '),
        el('span', `tag ${db.mode === 'enabled' ? 'ok' : 'mut'}`,
          db.mode === 'enabled' ? 'Маскирование включено' : 'выкл.'));
      //--agent TASK-224
      btn.addEventListener('click', () => selectDatabase(db));
      return btn;
    }, 'Нет доступных баз');
  };

  const loadChats = async db => {
    const target = $('#chatList');
    target.replaceChildren(el('p', 'empty', 'Загрузка…'));
    try {
      const chats = await api(`/api/v1/chats?database_id=${encodeURIComponent(db.id)}`);
      listInto(target, chats, chat => {
        const btn = el('button');
        btn.type = 'button';
        btn.dataset.id = chat.chat_id;
        //++agent TASK-224 [08.10.2026] имя чата целиком; обрезка с конца
        // через .clip (никаких middle-ellipsis от shortId), полное имя — title.
        const name = el('span', 'mono small clip', chat.chat_id);
        name.title = chat.chat_id;
        btn.append(name, document.createElement('br'),
          //--agent TASK-224
          //**agent TASK-224 [25.09.2026 12:40:00] итерация 5: склонение
          // el('span', 'small muted', `${chat.message_count} записей · ${fmtAgo(chat.last_message_at)}`));
          el('span', 'small muted', `${chat.message_count} ${ruPlural(chat.message_count, 'запись', 'записи', 'записей')} · ${fmtAgo(chat.last_message_at)}`));
          //**agent TASK-224
        btn.addEventListener('click', () => selectChat(chat));
        return btn;
      }, 'В базе нет чатов');
    } catch (error) {
      if (error.status !== 401) target.replaceChildren(el('p', 'empty', error.message));
    }
  };

  const loadHistory = async chat => {
    const target = $('#recordList');
    target.replaceChildren(el('p', 'empty', 'Загрузка…'));
    try {
      const items = await api(
        `/api/v1/history?database_id=${encodeURIComponent(viewer.database.id)}&chat_id=${encodeURIComponent(chat.chat_id)}&limit=50`);
      listInto(target, items, item => {
        const btn = el('button');
        btn.type = 'button';
        btn.dataset.id = item.id;
        //**agent TASK-225 [27.09.2026 12:00:00] отказ защиты — не «ошибка»
        // const [cls, label] = OUTCOME_LABELS[item.outcome] || ['mut', item.outcome];
        // btn.append(el('b', '', fmtTime(item.created_at)), document.createTextNode(' '),
        //   el('span', 'mono small', item.tool_name), document.createElement('br'),
        //   el('span', `tag ${cls}`, label));
        const { cls, label, hit } = callStatus(item);
        const tag = el('span', `tag ${cls}`, label);
        if (hit) tag.title = `${hit.title} (${hit.code})`;
        btn.append(el('b', '', fmtTime(item.created_at)), document.createTextNode(' '),
          el('span', 'mono small', item.tool_name), document.createElement('br'), tag);
        //**agent TASK-225
        btn.addEventListener('click', () => selectRecord(item));
        return btn;
      }, 'В чате нет записей');
    } catch (error) {
      if (error.status !== 401) target.replaceChildren(el('p', 'empty', error.message));
    }
  };

  //++agent TASK-224 [24.09.2026] итерация 3
  // Переключатель «Показать маскированное/реальные». Раскрытые данные
  // остаются только в памяти вкладки и сбрасываются при уходе с записи.
  //**agent TASK-224 [25.09.2026 12:25:00] итерация 5: два сегмента
  // $('#maskToggle').addEventListener('click', () => {
  //   if (!viewer.revealed) return;
  //   viewer.showMasked = !viewer.showMasked;
  //   applyReportView();
  // });
  $('#maskToggle').addEventListener('click', event => {
    const btn = event.target.closest('button[data-view]');
    if (!btn || !viewer.revealed) return;
    const masked = btn.dataset.view === 'masked';
    if (masked === viewer.showMasked) return;
    viewer.showMasked = masked;
    applyReportView();
  });
  $('#reportMore').addEventListener('click', () => {
    const title = $('#reportTitle');
    const collapsed = title.classList.toggle('clamp');
    $('#reportMore').textContent = collapsed ? 'Развернуть' : 'Свернуть';
  });
  $('#revealNote').prepend(svgIcon('eye'));

  //++agent TASK-225 [27.09.2026 09:16:39] выгрузка реальных значений:
  // первое «Копировать»/CSV в рамках раскрытия записи — модалка, дальше без
  // вопросов. Подтверждение привязано к объекту viewer.revealed: уход с
  // записи обнуляет его, и следующее раскрытие спросит снова.
  let realCopyPending = null;
  const realToast = message => {
    const node = el('div', 'toast', message);
    node.setAttribute('role', 'status');
    document.body.append(node);
    setTimeout(() => node.remove(), 1800);
  };
  const realCopy = {
    confirm(proceed) {
      if (viewer.revealed && viewer.realCopyAck === viewer.revealed) {
        proceed();
        realToast('Скопировано (реальные значения)');
        return;
      }
      realCopyPending = proceed;
      openOverlay('dlgRealCopy');
    },
    notify() { realToast('Скопировано (реальное значение)'); },
  };
  $('#realCopyCancel').addEventListener('click', () => { realCopyPending = null; closeOverlays(); });
  $('#realCopyGo').addEventListener('click', () => {
    const proceed = realCopyPending;
    realCopyPending = null;
    viewer.realCopyAck = viewer.revealed;
    closeOverlays();
    if (proceed) {
      proceed();
      realToast('Скопировано (реальные значения)');
    }
  });
  //++agent TASK-225

  //++agent TASK-225 [27.09.2026 13:00:00] «Скопировать для агента»: только
  // идентификаторы, исход и текст запроса из МАСКИРОВАННОЙ записи
  // (viewer.record, никогда viewer.revealed); результат не копируется —
  // лишь число строк. Полей, которых нет в записи, в блоке нет.
  const agentCallText = record => {
    const db = viewer.database;
    const report = record.report || {};
    const hit = detectCallError(record);
    const lines = ['Вызов MCP (сервис маскирования)'];
    if (db) lines.push(`- База: ${db.display_label || 'без названия'} (${db.id})`);
    else if (record.database_id) lines.push(`- База: ${record.database_id}`);
    lines.push(`- Инструмент: ${record.tool_name}`);
    if (record.created_at) lines.push(`- Время: ${record.created_at}`);
    if (record.chat_id) lines.push(`- Чат: ${record.chat_id}`);
    let ids = `- id записи истории: ${record.id}`;
    const corr = /correlation_id\W{1,3}([0-9a-f-]{36})/i.exec((report.blocks || []).filter(b => b && b.kind === 'text').map(b => b.text).join('\n'));
    if (corr) ids += `; correlation_id: ${corr[1]}`;
    lines.push(ids);
    lines.push(`- Исход: ${record.outcome}${hit ? ` [${hit.code} — ${hit.title}]` : ''}`);
    const rows = (report.blocks || []).filter(b => b && b.kind === 'table' && Array.isArray(b.rows))
      .reduce((n, b) => n + b.rows.length, 0);
    if (rows) lines.push(`- Строк в результате: ${rows}`);
    if (typeof report.title === 'string' && report.title.trim()) {
      lines.push('- Запрос:', '  ```', ...report.title.split('\n').map(l => `  ${l}`), '  ```');
    }
    return lines.join('\n');
  };
  $('#agentCopyBtn').addEventListener('click', event => {
    if (viewer.record) copyText(agentCallText(viewer.record), event.currentTarget);
  });
  //++agent TASK-225
  //**agent TASK-224
  //--agent TASK-224

  //++agent TASK-225 [26.09.2026 03:00:00] «Почему скрыто» (B9): причины
  // маскирования записи и подсветка их ячеек; ссылка ведёт в админку на
  // правило/источник той версии, которой запись обработана.
  function resetWhy() {
    viewer.why = null;
    viewer.whySel = null;
    $('#whyPanel').hidden = true;
    $('#whyBtn').classList.remove('on');
  }
  const whyCellMap = () => {
    const map = new Map();
    const why = viewer.why;
    if (!why || !why.detailed) return map;
    (why.cells || []).forEach(c => {
      map.set(`${c.block ?? 0}|${c.row ?? '*'}|${c.column ?? '*'}`, c.reasons || []);
    });
    return map;
  };
  const cellReasons = (b, r, col) => {
    const map = viewer.whyMap || new Map();
    const colId = col ? (col.id ?? col.label) : null;
    return map.get(`${b}|${r ?? '*'}|${colId ?? '*'}`) || map.get(`${b}|*|${colId ?? '*'}`) || (r === null ? map.get(`${b}|*|*`) : null) || null;
  };
  function whyDecorate(node, b, r, col) {
    if (!viewer.why || !viewer.why.detailed || $('#whyPanel').hidden) return;
    const reasons = cellReasons(b, r, col);
    if (!reasons) return;
    if (viewer.whySel !== null && reasons.includes(viewer.whySel)) node.classList.add('hl');
    node.classList.add('whyc');
    node.addEventListener('click', event => {
      event.stopPropagation();
      viewer.whySel = reasons[0];
      renderWhy(reasons);
      applyReportView();
    });
  }
  const WHY_KIND = {
    rule: 'Правило', dictionary: 'Словарь', builtin: 'Встроенное', secret: 'Секрет',
  };
  const renderWhy = only => {
    const why = viewer.why;
    const list = $('#whyList');
    list.replaceChildren();
    $('#whyNote').hidden = true;
    $('#whyHint').hidden = true;
    if (!why) return;
    if (why.expired) {
      $('#whyVersion').textContent = '';
      $('#whyNote').textContent = 'Запись удалена по сроку хранения — причины недоступны.';
      $('#whyNote').hidden = false;
      return;
    }
    if (why.error) {
      $('#whyVersion').textContent = '';
      $('#whyNote').textContent = `Причины не получены: ${why.error}`;
      $('#whyNote').hidden = false;
      return;
    }
    const ver = why.policy_version;
    $('#whyVersion').textContent = ver
      ? `Запись обработана версией настройки ${ver}${why.active_version && why.active_version !== ver ? ` (сейчас действует ${why.active_version})` : ''}.`
      : '';
    if (!why.detailed) {
      const legacy = (why.legacy_reasons || []).join(', ');
      $('#whyNote').textContent = `Детальные причины не сохранены для этой записи (создана до обновления сервиса).${legacy ? ` Общие причины: ${legacy}.` : ''}`;
      $('#whyNote').hidden = false;
      return;
    }
    const reasons = why.reasons || [];
    if (!reasons.length) {
      list.append(el('p', 'empty', 'В этой записи ничего не скрыто.'));
      return;
    }
    reasons.forEach(rs => {
      const card = el('div', `rs${viewer.whySel === rs.idx ? ' sel' : ''}`);
      if (only && !only.includes(rs.idx)) card.classList.add('dim');
      const top = el('div', 'row spread');
      const [cls, label] = rs.action === 'secret' || rs.kind === 'secret' ? ['err', 'Секрет'] : rs.action === 'keep' ? ['warn', 'Не маскировать'] : ['acc', 'Скрыть'];
      top.append(el('span', `tag ${cls}`, label), el('span', 'small muted', `${rs.cells} ${ruPlural(rs.cells, 'ячейка', 'ячейки', 'ячеек')}`));
      card.append(top, el('b', '', rs.label || `${WHY_KIND[rs.kind] || rs.kind}${rs.category ? `, категория ${rs.category}` : ''}`));
      const subj = rs.source_path || rs.selector || rs.pattern;
      if (subj) card.append(el('div', 'mono small brk', subj));
      if (rs.kind === 'builtin') card.append(el('div', 'small muted', 'Нельзя отключить'));
      if (rs.link && rs.link.admin_path) {
        const isAdmin = state.session && state.session.role === 'Admin';
        const a = el('button', 'btn link small', isAdmin ? (rs.rule_id ? 'Открыть правило' : 'Открыть источник') : 'Скопировать ссылку для администратора');
        a.type = 'button';
        a.addEventListener('click', event => {
          event.stopPropagation();
          const url = new URL(rs.link.admin_path, location.origin).href;
          if (isAdmin) window.open(url, '_blank', 'noopener');
          else copyText(url, a);
        });
        card.append(a);
      }
      card.addEventListener('click', () => {
        viewer.whySel = viewer.whySel === rs.idx ? null : rs.idx;
        renderWhy();
        applyReportView();
      });
      list.append(card);
    });
    if (why.truncated) list.append(el('p', 'small muted', 'Показаны не все ячейки — отчёт слишком большой.'));
    $('#whyHint').hidden = false;
  };
  $('#whyBtn').addEventListener('click', async () => {
    const record = viewer.record;
    if (!record) return;
    const panel = $('#whyPanel');
    if (!panel.hidden) {
      panel.hidden = true;
      $('#whyBtn').classList.remove('on');
      applyReportView();
      return;
    }
    panel.hidden = false;
    $('#whyBtn').classList.add('on');
    if (!viewer.why) {
      $('#whyList').replaceChildren(el('p', 'empty', 'Загрузка…'));
      try {
        viewer.why = await api(`/api/v1/history/${encodeURIComponent(record.id)}/reasons`);
      } catch (error) {
        if (error.status === 401) return;
        viewer.why = error.status === 410 || error.code === 'HISTORY_EXPIRED' ? { expired: true } : { error: error.message };
      }
      if (viewer.record !== record) return;
      viewer.whyMap = whyCellMap();
    }
    renderWhy();
    applyReportView();
  });

  // Экспорт: Viewer выгружает только действующую версию (B3v).
  $('#vExportBtn').addEventListener('click', () => {
    if (!viewer.database) return;
    $('#vExErr').hidden = true;
    $('#vExTools').checked = false;
    $('#vExText').textContent = `Будет выгружена действующая версия настройки маскирования базы ${viewer.database.display_label || shortId(viewer.database.id)}.`;
    openOverlay('dlgVExport');
  });
  $('#vExCancel').addEventListener('click', closeOverlays);
  $('#vExGo').addEventListener('click', async () => {
    const db = viewer.database;
    if (!db) return;
    const label = (db.display_label || db.id).replace(/[^\p{L}\p{N}_.-]+/gu, '_');
    try {
      await downloadFile(`/api/v1/databases/${encodeURIComponent(db.id)}/setup/export?include_tools=${$('#vExTools').checked ? 1 : 0}`,
        `masking-setup-${label}-${new Date().toISOString().slice(0, 10)}.json`);
      closeOverlays();
    } catch (error) {
      showError($('#vExErr'), error.code === 'NO_ACTIVE_VERSION' || error.status === 404
        ? { message: 'У базы нет действующей настройки — выгружать нечего.' }
        : error);
    }
  });
  //++agent TASK-225

  await loadDatabases();
  crumbs();
}

// ---------- Admin ----------

const TOOL_CLASSES = [
  ['data-mask', 'Маскировать'],
  //**agent TASK-225 [26.09.2026 05:00:00] единая подпись режима
  // ['no-mask', 'Только метаданные'],
  ['no-mask', 'Без маскирования'],
  //**agent TASK-225
  ['deny-pending-review', 'Запрещено до проверки'],
];
const POLICY_STATUS = { draft: ['warn', 'Черновик'], active: ['ok', 'Действующая'], retired: ['mut', 'Архив'] };

async function adminPage() {
  let session;
  try {
    session = await api('/api/v1/session');
  } catch (_) {
    location.assign('/?expired=1');
    return;
  }
  state.session = session;
  wireProfile(session);

  $('#navUsers').addEventListener('click', () => switchSection('users'));
  $('#navDbs').addEventListener('click', () => switchSection('dbs'));
  function switchSection(name) {
    $('#navUsers').classList.toggle('on', name === 'users');
    $('#navDbs').classList.toggle('on', name === 'dbs');
    $('#s-users').classList.toggle('on', name === 'users');
    $('#s-dbs').classList.toggle('on', name === 'dbs');
    if (name === 'dbs' && !dbs.loaded) loadDatabases();
  }

  // --- диалог подтверждения ---
  let confirmAction = null;
  const askConfirm = (title, text, action) => {
    $('#confirmTitle').textContent = title;
    $('#confirmText').textContent = text;
    confirmAction = action;
    openOverlay('dlgConfirm');
  };
  $('#confirmYes').addEventListener('click', async () => {
    closeOverlays();
    if (confirmAction) await confirmAction();
    confirmAction = null;
  });
  $('#confirmNo').addEventListener('click', () => { confirmAction = null; closeOverlays(); });

  // --- пользователи ---
  let users = [];
  let inviteContext = null; // {userId, timer}
  let inviteTimer = null;

  const userStatusTag = user => {
    if (user.status === 'disabled') return ['mut', 'Отключён'];
    if (!user.activated) {
      if (user.invitation_expires_at && new Date(user.invitation_expires_at) > new Date()) {
        const left = Math.ceil((new Date(user.invitation_expires_at) - Date.now()) / 60_000);
        return ['warn', `Ожидает · ${left} мин`];
      }
      return ['err', 'Приглашение истекло'];
    }
    return ['ok', 'Активен'];
  };

  const loadUsers = async () => {
    try {
      users = await api('/api/v1/admin/users');
    } catch (error) {
      if (error.status !== 401) showError($('#usersErr'), error);
      return;
    }
    const body = $('#usersBody');
    body.replaceChildren();
    if (!users.length) {
      body.insertRow().insertCell().outerHTML = '<td colspan="5" class="empty">Нет пользователей</td>';
      return;
    }
    for (const user of users) {
      const tr = body.insertRow();
      tr.className = 'click';
      tr.append(el('td', 'mono', user.login));
      tr.append(el('td', '', user.role === 'Admin' ? 'Администратор' : 'Просмотр'));
      const [cls, label] = userStatusTag(user);
      const statusCell = el('td');
      statusCell.append(el('span', `tag ${cls}`, label));
      if (cls === 'err') {
        statusCell.append(document.createTextNode(' '));
        const reissue = el('button', 'btn sm', 'Выпустить новое');
        reissue.type = 'button';
        reissue.addEventListener('click', event => {
          event.stopPropagation();
          reissueInvitation(user);
        });
        statusCell.append(reissue);
      }
      tr.append(statusCell);
      tr.append(el('td', 'hide-sm muted', fmtAgo(user.last_login_at)));
      tr.append(el('td', '', '›'));
      tr.addEventListener('click', () => openUserCard(user));
    }
  };

  const showInvite = (login, payload, userId) => {
    // Карточка приглашения: ссылка/код показываются один раз, таймер от
    // expires_in_seconds ответа.
    $('#invLogin').textContent = login;
    $('#invUrl').textContent = payload.activation_url;
    $('#invCode').textContent = (payload.activation_token.match(/.{1,4}/g) || []).join(' ');
    $('#invMsg').textContent = `Вам создан доступ к сервису маскирования. Логин: ${login}. ` +
      `Откройте ссылку в течение 15 минут и задайте пароль: ${payload.activation_url}`;
    inviteContext = { userId, login };
    let left = payload.expires_in_seconds || 900;
    $('#invLive').hidden = false;
    $('#invDead').hidden = true;
    clearInterval(inviteTimer);
    const tick = () => {
      if (left <= 0) {
        clearInterval(inviteTimer);
        $('#invLive').hidden = true;
        $('#invDead').hidden = false;
        return;
      }
      $('#invTimer').textContent = fmtCountdown(left);
      left -= 1;
    };
    tick();
    inviteTimer = setInterval(tick, 1000);
    openOverlay('dlgInvite');
  };

  const reissueInvitation = async user => {
    try {
      const payload = await api(`/api/v1/admin/users/${encodeURIComponent(user.user_id)}/invitation`, { method: 'POST' });
      showInvite(user.login, payload, user.user_id);
      loadUsers();
    } catch (error) {
      //++agent TASK-224 [08.10.2026] USER_DISABLED — отдельное объяснение.
      showError($('#usersErr'), error.code === 'USER_DISABLED'
        ? { message: 'Пользователь отключён — сначала включите его и сохраните.' }
        : error.status === 409
          ? { message: 'Перевыпуск доступен только для пользователя без активации.' }
          : error);
      //--agent TASK-224
    }
  };

  $$('#dlgInvite [data-copy]').forEach(btn => btn.addEventListener('click', () => {
    copyText($('#' + btn.dataset.copy).textContent, btn);
  }));
  $('#invDone').addEventListener('click', () => { clearInterval(inviteTimer); closeOverlays(); });
  $('#invReissue').addEventListener('click', async () => {
    if (!inviteContext) return;
    const known = users.find(u => u.user_id === inviteContext.userId);
    await reissueInvitation(known || { user_id: inviteContext.userId, login: inviteContext.login });
  });

  $('#newUserBtn').addEventListener('click', () => {
    $('#newErr').hidden = true;
    $('#newForm').reset();
    $('#newLoginHint').textContent = '';
    openOverlay('dlgNew');
  });
  $('#newCancel').addEventListener('click', closeOverlays);
  $('#newLogin').addEventListener('input', () => {
    const value = $('#newLogin').value.trim().toLowerCase();
    $('#newLoginHint').textContent = value ? `Будет сохранён как ${value}` : '';
  });
  $('#newForm').addEventListener('submit', async event => {
    event.preventDefault();
    $('#newErr').hidden = true;
    const role = ($('#newForm').querySelector('input[name="newRole"]:checked') || {}).value || 'Viewer';
    try {
      const payload = await api('/api/v1/admin/users', {
        method: 'POST',
        body: JSON.stringify({ login: $('#newLogin').value.trim(), role }),
      });
      closeOverlays();
      showInvite(payload.login, payload, payload.user_id);
      loadUsers();
    } catch (error) {
      showError($('#newErr'), error.status === 409
        ? { message: 'Не удалось создать: логин занят или недопустим.' }
        : error);
    }
  });

  // --- карточка пользователя ---
  let cardUser = null;
  let cardRole = 'Viewer';
  let cardStatus = 'active';

  const cardDirty = () => cardUser && (cardRole !== cardUser.role || cardStatus !== cardUser.status);
  //++agent TASK-224 [08.10.2026] итерация 4: приглашение/сброс не должны
  // уходить от устаревшего состояния карточки — при несохранённых
  // изменениях или отключённом статусе действия блокируются с причиной
  // (backend дополнительно отвечает 409 USER_DISABLED).
  const refreshCardButtons = () => {
    $('#userSave').disabled = !cardDirty();
    const blocked = !!cardUser && (cardDirty() || cardStatus !== 'active');
    $('#userReissue').disabled = blocked;
    $('#userReset').disabled = blocked;
    const hint = $('#userAccessHint');
    hint.hidden = !blocked;
    if (blocked) {
      hint.textContent = cardDirty()
        ? 'Есть несохранённые изменения — сначала нажмите «Сохранить», затем повторите действие.'
        : 'Пользователь отключён — приглашение и сброс пароля станут доступны после включения и сохранения.';
    }
  };
  //--agent TASK-224

  const openUserCard = user => {
    cardUser = user;
    cardRole = user.role;
    cardStatus = user.status;
    $('#userErr').hidden = true;
    $('#userLogin').textContent = user.login;
    $$('#userRoleSeg button').forEach(b => b.classList.toggle('on', b.dataset.role === cardRole));
    const [cls, label] = userStatusTag(user);
    const tag = $('#userStatusTag');
    tag.className = `tag ${cls}`;
    tag.textContent = label;
    $('#userToggle').textContent = user.status === 'active' ? 'Отключить' : 'Включить';
    // Б1: перевыпуск — только «ожидающим»; Б5: сброс — активированным;
    // Б6: удаление — только никогда не входившим.
    $('#userInviteRow').hidden = user.activated;
    $('#userResetRow').hidden = !user.activated;
    $('#userDeleteRow').hidden = user.activated;
    refreshCardButtons();
    openOverlay('dlgUser');
  };

  $$('#userRoleSeg button').forEach(btn => btn.addEventListener('click', () => {
    cardRole = btn.dataset.role;
    $$('#userRoleSeg button').forEach(b => b.classList.toggle('on', b === btn));
    refreshCardButtons();
  }));
  $('#userToggle').addEventListener('click', () => {
    cardStatus = cardStatus === 'active' ? 'disabled' : 'active';
    $('#userToggle').textContent = cardStatus === 'active' ? 'Отключить' : 'Включить';
    refreshCardButtons();
  });
  $('#userClose').addEventListener('click', () => { cardUser = null; closeOverlays(); });
  $('#userSave').addEventListener('click', async () => {
    if (!cardUser) return;
    const save = async () => {
      try {
        await api(`/api/v1/admin/users/${encodeURIComponent(cardUser.user_id)}`, {
          method: 'PATCH',
          body: JSON.stringify({ role: cardRole, status: cardStatus }),
        });
        cardUser = null;
        closeOverlays();
        loadUsers();
      } catch (error) {
        showError($('#userErr'), error.status === 409
          ? { message: 'Нельзя отключить или понизить последнего активного администратора.' }
          : error);
      }
    };
    if (cardStatus === 'disabled' && cardUser.status !== 'disabled') {
      askConfirm('Отключить пользователя?', 'Все сеансы пользователя будут завершены. Действие записывается в журнал.', save);
    } else {
      await save();
    }
  });
  $('#userReissue').addEventListener('click', () => { if (cardUser) reissueInvitation(cardUser); });
  $('#userReset').addEventListener('click', () => {
    if (!cardUser) return;
    const target = cardUser;
    askConfirm('Сбросить пароль?', 'Старый пароль перестанет работать, все сеансы пользователя будут завершены. Будет выдано новое приглашение.', async () => {
      try {
        const payload = await api(`/api/v1/admin/users/${encodeURIComponent(target.user_id)}/password-reset`, { method: 'POST' });
        cardUser = null;
        showInvite(target.login, payload, target.user_id);
        loadUsers();
      } catch (error) {
        openOverlay('dlgUser');
        //++agent TASK-224 [08.10.2026] USER_DISABLED — отдельное объяснение.
        showError($('#userErr'), error.code === 'USER_DISABLED'
          ? { message: 'Пользователь отключён — сначала включите его и сохраните.' }
          : error);
        //--agent TASK-224
      }
    });
  });
  $('#userDelete').addEventListener('click', () => {
    if (!cardUser) return;
    const target = cardUser;
    askConfirm('Удалить пользователя?', `Учётная запись ${target.login} будет удалена без возможности восстановления. Логин освобождается.`, async () => {
      try {
        await api(`/api/v1/admin/users/${encodeURIComponent(target.user_id)}`, { method: 'DELETE' });
        cardUser = null;
        loadUsers();
      } catch (error) {
        openOverlay('dlgUser');
        showError($('#userErr'), error.status === 409
          ? { message: 'Удалить можно только пользователя, который ни разу не входил.' }
          : error);
      }
    });
  });

  // --- базы ---
  const dbs = { loaded: false, list: [], current: null, refreshTimer: null };
  const TOOL_CLASS_LABEL = Object.fromEntries(TOOL_CLASSES);

  const dbStatusTag = db => db.mode === 'enabled'
    ? ['ok', 'Маскирование включено']
    : ['mut', 'Маскирование выключено'];

  const loadDatabases = async () => {
    try {
      dbs.list = await api('/api/v1/admin/databases');
      dbs.loaded = true;
    } catch (error) {
      if (error.status !== 401) showError($('#dbsErr'), error);
      return;
    }
    const list = $('#dbList');
    list.replaceChildren();
    if (!dbs.list.length) {
      list.append(el('p', 'empty', 'Нет настроенных баз'));
      return;
    }
    for (const db of dbs.list) {
      const btn = el('button');
      btn.type = 'button';
      btn.dataset.id = db.id;
      const [cls, label] = dbStatusTag(db);
      //++agent TASK-224 [08.10.2026] то же правило имён, что у viewer.
      btn.append(el('b', '', db.display_label || 'без названия'), document.createElement('br'),
        el('span', 'mono small muted', shortId(db.id)), document.createTextNode(' '),
        el('span', `tag ${cls}`, label));
      //++agent TASK-225 [26.09.2026 02:40:00] состояние настройки и сбой обновления
      if (db.setup_state === 'unconfigured') btn.append(document.createTextNode(' '), el('span', 'tag warn', 'Не настроено'));
      if (db.refresh && db.refresh.state === 'needs_attention') btn.append(document.createTextNode(' '), el('span', 'tag err', 'Нужна настройка'));
      if (db.new_tools_count) btn.append(document.createTextNode(' '), el('span', 'badge', String(db.new_tools_count)));
      //++agent TASK-225
      // Итерация 5 [25.09.2026]: перерисовка списка (опрос, переименование)
      // не теряет подсветку выбранной базы.
      btn.classList.toggle('on', !!(dbs.current && dbs.current.id === db.id));
      //--agent TASK-224
      btn.addEventListener('click', () => selectDb(db));
      list.append(btn);
    }
    if (dbs.current) {
      const fresh = dbs.list.find(d => d.id === dbs.current.id);
      if (fresh) {
        dbs.current = fresh;
        renderDbHead(fresh, true); // TASK-224: не закрывать открытую правку имени
        renderRefreshState(fresh);
        renderRefreshProblem(fresh); // TASK-225
      }
    }
  };

  //++agent TASK-224 [24.09.2026] шапка базы: display_label крупно; без имени —
  // короткий GUID + метка «без названия»; полный GUID мелко + копирование.
  //--agent TASK-224
  const renderDbHead = (db, keepEdit) => {
    const title = $('#dbTitle');
    title.replaceChildren(el('span', '', db.display_label || shortId(db.id)));
    if (!db.display_label) title.append(document.createTextNode(' '), el('span', 'tag mut', 'без названия'));
    $('#dbGuid').textContent = db.id;
    //**agent TASK-224 [25.09.2026 13:30:00] фоновый опрос статуса (каждые 3 с)
    // перерисовывает шапку той же базы; сбрасывать открытую правку имени нельзя,
    // иначе окно переименования закрывается через 1-2 с.
    // $('#dbNameInput').value = db.display_label || '';
    // $('#dbRenameRow').hidden = true;
    // $('#dbNameErr').hidden = true;
    if (keepEdit && !$('#dbRenameRow').hidden) return;
    $('#dbNameInput').value = db.display_label || '';
    $('#dbRenameRow').hidden = true;
    $('#dbNameErr').hidden = true;
    //**agent TASK-224
  };

  $('#dbGuidCopy').addEventListener('click', async () => {
    if (!dbs.current) return;
    const btn = $('#dbGuidCopy');
    try {
      await navigator.clipboard.writeText(dbs.current.id);
      btn.textContent = 'Скопировано';
    } catch (_) {
      btn.textContent = 'Не удалось — скопируйте вручную';
    }
    setTimeout(() => { btn.textContent = 'Копировать ID'; }, 1500);
  });
  $('#dbRename').addEventListener('click', () => {
    $('#dbRenameRow').hidden = false;
    $('#dbNameInput').focus();
  });
  $('#dbNameCancel').addEventListener('click', () => { $('#dbRenameRow').hidden = true; });
  $('#dbNameSave').addEventListener('click', async () => {
    if (!dbs.current) return;
    $('#dbNameErr').hidden = true;
    try {
      await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ display_label: $('#dbNameInput').value.trim() }),
      });
      $('#dbRenameRow').hidden = true; // TASK-224: сохранено — закрыть правку явно
      await loadDatabases();
    } catch (error) {
      showError($('#dbNameErr'), error);
    }
  });

  //++agent TASK-225 [27.09.2026 08:30:42] удаление базы (DELETE /admin/databases/{id}).
  // Необратимо и стирает всю настройку, поэтому подтверждение вводом имени, а не
  // одним кликом; кнопка только у Admin (защита на сервере, здесь - не соблазнять).
  $('#dbDelete').hidden = !(state.session && state.session.role === 'Admin');
  const dbDel = { target: null, expect: '' };
  const dbDelMatch = () => $('#dbDelInput').value.trim() === dbDel.expect;
  const dbDelNotify = text => {
    const note = $('#dbsOk');
    note.textContent = text;
    note.hidden = false;
    setTimeout(() => { if (note.textContent === text) note.hidden = true; }, 6000);
  };
  const dbDelForget = async () => {
    // Карточку удалённой базы гасим сразу: опрос статуса и правки не должны
    // продолжаться по несуществующему id.
    dbs.current = null;
    if (dbs.refreshTimer) { clearInterval(dbs.refreshTimer); dbs.refreshTimer = null; }
    $('#dbCard').hidden = true;
    await loadDatabases();
  };
  $('#dbDelete').addEventListener('click', () => {
    if (!dbs.current) return;
    dbDel.target = dbs.current;
    dbDel.expect = dbs.current.display_label || dbs.current.id;
    $('#dbDelName').textContent = dbDel.expect;
    $('#dbDelExpect').textContent = dbDel.expect;
    $('#dbDelInput').value = '';
    $('#dbDelErr').hidden = true;
    $('#dbDelYes').disabled = true;
    $('#dbDelYes').textContent = 'Удалить базу';
    openOverlay('dlgDbDelete');
    $('#dbDelInput').focus();
  });
  $('#dbDelInput').addEventListener('input', () => { $('#dbDelYes').disabled = !dbDelMatch(); });
  $('#dbDelInput').addEventListener('keydown', e => {
    if (e.key === 'Enter' && dbDelMatch() && !$('#dbDelYes').disabled) $('#dbDelYes').click();
  });
  $('#dbDelNo').addEventListener('click', () => { closeOverlays(); dbDel.target = null; });
  $('#dbDelYes').addEventListener('click', async () => {
    if (!dbDel.target || !dbDelMatch()) return;
    const target = dbDel.target;
    const name = dbDel.expect;
    const btn = $('#dbDelYes');
    btn.disabled = true;
    btn.textContent = 'Удаление…';
    $('#dbDelErr').hidden = true;
    try {
      await api(`/api/v1/admin/databases/${encodeURIComponent(target.id)}`, { method: 'DELETE' });
      closeOverlays();
      dbDel.target = null;
      await dbDelForget();
      dbDelNotify(`База «${name}» удалена.`);
    } catch (error) {
      if (error.status === 404) {
        closeOverlays();
        dbDel.target = null;
        await dbDelForget();
        dbDelNotify(`База «${name}» уже удалена или не найдена — список обновлён.`);
        return;
      }
      showError($('#dbDelErr'), error);
      btn.textContent = 'Удалить базу';
      btn.disabled = !dbDelMatch();
    }
  });
  //++agent TASK-225

  const renderRefreshState = db => {
    const tag = $('#refreshState');
    //**agent TASK-224 [25.09.2026 12:50:00] итерация 5: refresh_stage='active'
    // по контракту backend (TASK-222) = снимок собран и действует, а не
    // «в работе»; прежняя ветка показывала «Выполняется: active» и крутила
    // опрос бесконечно. Машинные коды фаз наружу не выводим.
    // if (db.refresh_stage) {
    //   tag.className = 'tag warn';
    //   tag.textContent = `Выполняется: ${db.refresh_stage}`;
    //   scheduleRefreshPoll();
    //++agent TASK-225 [26.09.2026] K: intent в needs_attention — повторы
    // остановлены, «Обновляются…» вводит в заблуждение (см. refreshProblem).
    if (db.refresh && db.refresh.state === 'needs_attention') {
      tag.className = 'tag err';
      tag.textContent = 'Нужна настройка';
      tag.title = 'Автоматические попытки остановлены — см. причину ниже';
    } else if (db.refresh_stage && db.refresh_stage !== 'active') {
    //++agent TASK-225
      tag.className = 'tag warn';
      tag.textContent = 'Обновляются…';
      tag.title = `Этап: ${db.refresh_stage}`;
      scheduleRefreshPoll();
    } else if (!db.refresh_stage) {
      tag.className = 'tag mut';
      tag.textContent = 'Ещё не получены';
      tag.title = '';
    //**agent TASK-224
    } else {
      tag.className = 'tag ok';
      tag.textContent = 'Актуальны';
      tag.title = '';
    }
  };

  //++agent TASK-225 [26.09.2026 02:40:00] backoff обновления метаданных:
  // показываем текст последней ошибки и «нужна настройка», чтобы
  // администратор не гадал, почему словарь не грузится.
  const renderRefreshProblem = db => {
    const box = $('#refreshProblem');
    const r = db.refresh || {};
    // Повторы идут — держим опрос статуса (тот же таймер TASK-224, renderDbHead с keepEdit).
    if (r.state === 'running' || r.state === 'retrying') scheduleRefreshPoll();
    if (!r.state || r.state === 'idle' || r.state === 'running') { box.hidden = true; return; }
    const when = r.next_attempt_at ? ` Следующая попытка - ${fmtTime(r.next_attempt_at)}.` : '';
    const head = r.state === 'needs_attention' ? 'Нужна настройка: обновление метаданных не удаётся.'
      : r.state === 'failed' ? 'Обновление метаданных завершилось ошибкой.'
      : `Обновление метаданных повторяется (попытка ${r.attempts || 1}).`;
    box.className = `note ${r.state === 'retrying' ? 'warn' : 'err'} mt8`;
    box.textContent = `${head}${r.last_error_text ? ` Причина: ${r.last_error_text}.` : ''}${when}`;
    box.hidden = false;
  };
  //++agent TASK-225
  const scheduleRefreshPoll = () => {
    if (dbs.refreshTimer) return;
    dbs.refreshTimer = setInterval(async () => {
      await loadDatabases();
      const current = dbs.current && dbs.list.find(d => d.id === dbs.current.id);
      //**agent TASK-224 [25.09.2026 12:50:00] итерация 5: 'active' — финал
      // if (!current || !current.refresh_stage) {
      //**agent TASK-225 [26.09.2026 04:10:00] опрос не гасим, пока идут повторы
      // обновления (backoff) — иначе плашка сбоя не появится без перезагрузки.
      // if (!current || !current.refresh_stage || current.refresh_stage === 'active') {
      const retrying = current && current.refresh && ['running', 'retrying'].includes(current.refresh.state);
      if (!current || ((!current.refresh_stage || current.refresh_stage === 'active') && !retrying)) {
      //**agent TASK-225
      //**agent TASK-224
        clearInterval(dbs.refreshTimer);
        dbs.refreshTimer = null;
      }
    }, 3000);
  };

  const selectDb = db => {
    dbs.current = db;
    $$('#dbList > button').forEach(b => b.classList.toggle('on', b.dataset.id === db.id));
    $('#dbCard').hidden = false;
    $('#mainErr').hidden = true;
    $('#toolsErr').hidden = true;
    //**agent TASK-225 [26.09.2026 02:40:00] вкладки setup/tools/journal
    // $('#dictErr').hidden = true;
    // $('#polErr').hidden = true;
    // renderDbHead(db);
    // renderMainTab(db);
    // loadTools(db);
    // loadDict(db);
    // loadPolicies(db);
    $('#dictErr').hidden = true;
    renderDbHead(db);
    renderMainTab(db);
    renderRefreshProblem(db);
    loadTools(db);
    loadMetaRoot().then(() => { if (setup.ed) renderDict(); });
    loadSetup(db);
    if (!$('#dt-journal').hidden) loadJournal();
    //**agent TASK-225
  };

  $$('#dbTabs button').forEach(btn => btn.addEventListener('click', () => {
    $$('#dbTabs button').forEach(b => b.classList.toggle('on', b === btn));
    //**agent TASK-225 [26.09.2026 02:40:00]
    // ['main', 'tools', 'dict', 'pol'].forEach(name => { $('#dt-' + name).hidden = name !== btn.dataset.dt; });
    ['main', 'setup', 'tools', 'journal'].forEach(name => { $('#dt-' + name).hidden = name !== btn.dataset.dt; });
    if (btn.dataset.dt === 'journal' && dbs.current) loadJournal();
    //**agent TASK-225
  }));

  // Основное
  let dbModeOn = true;
  //++agent TASK-225 [25.09.2026] состояние тумблера строгого режима.
  let dbStrictOn = true;
  //++agent TASK-225
  const ttlToFields = (seconds, numId, unitId) => {
    for (const unit of [86400, 3600, 60]) {
      if (seconds >= unit && seconds % unit === 0) {
        $(numId).value = seconds / unit;
        $(unitId).value = String(unit);
        return;
      }
    }
    $(numId).value = Math.max(1, Math.ceil(seconds / 60));
    $(unitId).value = '60';
  };
  const ttlFromFields = (numId, unitId) => {
    const num = Number($(numId).value);
    const unit = Number($(unitId).value);
    return Number.isFinite(num) && num >= 1 ? Math.floor(num) * unit : null;
  };
  const ttlHint = (numId, unitId, hintId) => {
    const seconds = ttlFromFields(numId, unitId);
    $(hintId).textContent = seconds === null ? 'Укажите значение не меньше 1.' : `= ${seconds.toLocaleString('ru-RU')} с`;
  };
  //++agent TASK-224 [08.10.2026] итерация 4: запись истории живёт не дольше
  // mapping (reveal без соответствий невозможен); после рестарта сервиса
  // история очищается целиком — маппинги в RAM не переживают процесс.
  const ttlEffectiveHint = () => {
    const mapping = ttlFromFields('#ttlMapNum', '#ttlMapUnit');
    const historyTtl = ttlFromFields('#ttlHistNum', '#ttlHistUnit');
    $('#ttlEffHint').textContent = mapping === null || historyTtl === null
      ? ''
      : `Запись истории хранится ${Math.min(mapping, historyTtl).toLocaleString('ru-RU')} с — меньший из двух сроков; при перезапуске сервиса история очищается полностью.`;
  };
  const ttlHints = () => {
    ttlHint('#ttlMapNum', '#ttlMapUnit', '#ttlMapHint');
    ttlHint('#ttlHistNum', '#ttlHistUnit', '#ttlHistHint');
    ttlEffectiveHint();
  };
  //--agent TASK-224

  const renderMainTab = db => {
    dbModeOn = db.mode === 'enabled';
    const sw = $('#dbMode');
    sw.classList.toggle('on', dbModeOn);
    sw.lastElementChild.textContent = dbModeOn ? 'Включено' : 'Выключено';
    //++agent TASK-225 [25.09.2026]
    dbStrictOn = db.strict_mode !== false;
    const strictSw = $('#dbStrict');
    strictSw.classList.toggle('on', dbStrictOn);
    strictSw.lastElementChild.textContent = dbStrictOn ? 'Включён' : 'Выключен';
    //++agent TASK-225
    ttlToFields(db.mapping_ttl_seconds, '#ttlMapNum', '#ttlMapUnit');
    ttlToFields(db.history_ttl_seconds, '#ttlHistNum', '#ttlHistUnit');
    ttlHints();
    renderRefreshState(db);
  };

  $('#dbMode').addEventListener('click', () => {
    if (dbModeOn) {
      askConfirm('Выключить маскирование?', 'Инструменты этой базы будут работать без маскирования — ответы пойдут с реальными значениями.', () => {
        dbModeOn = false;
        $('#dbMode').classList.remove('on');
        $('#dbMode').lastElementChild.textContent = 'Выключено';
      });
    } else {
      dbModeOn = true;
      $('#dbMode').classList.add('on');
      $('#dbMode').lastElementChild.textContent = 'Включено';
    }
  });
  //++agent TASK-225 [25.09.2026]
  // Выключение строгого режима меняет поведение на жёсткий отказ —
  // спрашиваем подтверждение как при выключении маскирования.
  $('#dbStrict').addEventListener('click', () => {
    if (dbStrictOn) {
      askConfirm('Выключить строгий режим?', 'Запросы с непроверенными колонками будут снова отклоняться вместо возврата маскированных значений.', () => {
        dbStrictOn = false;
        $('#dbStrict').classList.remove('on');
        $('#dbStrict').lastElementChild.textContent = 'Выключен';
      });
    } else {
      dbStrictOn = true;
      $('#dbStrict').classList.add('on');
      $('#dbStrict').lastElementChild.textContent = 'Включён';
    }
  });
  //++agent TASK-225
  //++agent TASK-224 [08.10.2026] обе пары полей влияют на effective-hint.
  for (const id of ['#ttlMapNum', '#ttlMapUnit', '#ttlHistNum', '#ttlHistUnit']) {
    $(id).addEventListener('input', ttlHints);
  }
  //--agent TASK-224
  $('#refreshBtn').addEventListener('click', async () => {
    if (!dbs.current) return;
    try {
      await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/refresh`, { method: 'POST' });
      const tag = $('#refreshState');
      tag.className = 'tag warn';
      tag.textContent = 'Выполняется…';
      scheduleRefreshPoll();
    } catch (error) {
      showError($('#mainErr'), error);
    }
  });
  $('#mainSave').addEventListener('click', async () => {
    if (!dbs.current) return;
    $('#mainErr').hidden = true;
    const mapping = ttlFromFields('#ttlMapNum', '#ttlMapUnit');
    const historyTtl = ttlFromFields('#ttlHistNum', '#ttlHistUnit');
    if (mapping === null || historyTtl === null) {
      showError($('#mainErr'), { message: 'Сроки хранения должны быть не меньше 1.' });
      return;
    }
    try {
      await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({
          mode: dbModeOn ? 'enabled' : 'disabled',
          mapping_ttl_seconds: mapping,
          history_ttl_seconds: historyTtl,
          //++agent TASK-225 [25.09.2026]
          strict_mode: dbStrictOn,
          //++agent TASK-225
        }),
      });
      await loadDatabases();
    } catch (error) {
      showError($('#mainErr'), error);
    }
  });

  //--agent TASK-225 [26.09.2026 02:40:00] старые вкладки «Инструменты», «Справочники», «Правила»
  // заменены версионированной настройкой (setup/*); legacy-маршруты изменения в UI не используются.
//  // Инструменты
//  const tools = { list: [], dirty: new Map() };
//  const loadTools = async db => {
//    tools.list = [];
//    tools.dirty.clear();
//    $('#toolsSave').disabled = true;
//    try {
//      tools.list = await api(`/api/v1/admin/databases/${encodeURIComponent(db.id)}/tools`);
//    } catch (error) {
//      if (error.status !== 401) showError($('#toolsErr'), error);
//      return;
//    }
//    renderTools();
//  };
//  const renderTools = () => {
//    const filter = $('#toolFilter').value.trim().toLowerCase();
//    const body = $('#toolsBody');
//    body.replaceChildren();
//    const visible = tools.list.filter(t => !filter || t.tool_name.toLowerCase().includes(filter));
//    if (!visible.length) {
//      const tr = body.insertRow();
//      const td = tr.insertCell();
//      td.colSpan = 2;
//      td.className = 'empty';
//      td.textContent = 'Инструменты не найдены';
//      return;
//    }
//    for (const tool of visible) {
//      const tr = body.insertRow();
//      tr.append(el('td', 'mono', tool.tool_name));
//      const seg = el('div', 'seg');
//      const current = tools.dirty.get(tool.tool_name) ?? tool.class;
//      for (const [value, label] of TOOL_CLASSES) {
//        const btn = el('button', current === value ? 'on' : '', label);
//        btn.type = 'button';
//        btn.addEventListener('click', () => {
//          if (value === tool.class) tools.dirty.delete(tool.tool_name);
//          else tools.dirty.set(tool.tool_name, value);
//          $('#toolsSave').disabled = tools.dirty.size === 0;
//          $('#toolsSave').textContent = tools.dirty.size ? `Сохранить изменения (${tools.dirty.size})` : 'Сохранить изменения';
//          $$('button', seg).forEach(b => b.classList.toggle('on', b === btn));
//        });
//        seg.append(btn);
//      }
//      const td = el('td');
//      td.append(seg);
//      tr.append(td);
//    }
//  };
//  $('#toolFilter').addEventListener('input', renderTools);
//  $('#toolsSave').addEventListener('click', async () => {
//    if (!dbs.current || !tools.dirty.size) return;
//    $('#toolsErr').hidden = true;
//    try {
//      for (const [toolName, cls] of tools.dirty) {
//        await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/tools/${encodeURIComponent(toolName)}`, {
//          method: 'PUT',
//          body: JSON.stringify({ class: cls }),
//        });
//      }
//      await loadTools(dbs.current);
//    } catch (error) {
//      showError($('#toolsErr'), error);
//    }
//  });
//
//  // Справочники
//  //++agent TASK-224 [24.09.2026]
//  // Дерево метаданных: узел-поле — родная гранулярность selector
//  // (source_path до поля). Чекбокс группы раскрывается в один selector на
//  // каждое листовое поле — контракт хранения безусловно тот же.
//  //--agent TASK-224
//  const dict = { id: null, mode: 'part', selectors: [], saved: '[]', savedMode: 'part' };
//  const meta = { ready: null, root: [], cache: new Map(), expanded: new Set(), search: null, poll: null };
//
//  const resetMeta = () => {
//    meta.ready = null;
//    meta.root = [];
//    meta.cache = new Map();
//    meta.expanded = new Set();
//    meta.search = null;
//    if (meta.poll) { clearInterval(meta.poll); meta.poll = null; }
//  };
//
//  const selKey = s => `${s.source_path}${s.category}${JSON.stringify(s.filter_ast || null)}`;
//  const diffCount = () => {
//    let n = dict.mode === dict.savedMode ? 0 : 1;
//    const saved = new Set(JSON.parse(dict.saved || '[]').map(selKey));
//    const cur = new Set(dict.selectors.map(selKey));
//    saved.forEach(k => { if (!cur.has(k)) n += 1; });
//    cur.forEach(k => { if (!saved.has(k)) n += 1; });
//    return n;
//  };
//
//  const selCovered = path => dict.selectors.some(s => s.source_path === path);
//  const selUnder = path => dict.selectors.some(s => s.source_path === path || s.source_path.startsWith(`${path}.`));
//
//  const loadMeta = path =>
//    api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/metadata?path=${encodeURIComponent(path)}`);
//
//  const loadDict = async db => {
//    dict.id = null;
//    dict.mode = 'part';
//    dict.selectors = [];
//    resetMeta();
//    $('#dictSearch').value = '';
//    try {
//      const configs = await api(`/api/v1/admin/databases/${encodeURIComponent(db.id)}/dictionaries`);
//      if (configs.length) {
//        dict.id = configs[0].id;
//        dict.mode = configs[0].mode;
//        dict.selectors = configs[0].selectors.map(s => ({ ...s }));
//      }
//      dict.savedMode = dict.mode;
//      dict.saved = JSON.stringify(dict.selectors.map(s => ({
//        source_path: s.source_path, category: s.category, filter_ast: s.filter_ast ?? null,
//      })));
//    } catch (error) {
//      if (error.status !== 401) showError($('#dictErr'), error);
//      return;
//    }
//    try {
//      const page = await loadMeta('');
//      meta.ready = page.manifest_ready;
//      meta.root = page.nodes;
//      meta.cache.set('', page.nodes);
//    } catch (error) {
//      if (error.status !== 401) showError($('#dictErr'), error);
//    }
//    renderDict();
//  };
//
//  // Все листовые поля под узлом (лениво догружает уровни). Узел, который
//  // одновременно является полем (kind=group + field_type), включает себя.
//  const collectLeaves = async node => {
//    if (node.kind === 'field') return [node];
//    const out = [];
//    if (node.field_type !== undefined) out.push({ path: node.path, password_mode: node.password_mode });
//    let children = meta.cache.get(node.path);
//    if (!children) {
//      children = (await loadMeta(node.path)).nodes;
//      meta.cache.set(node.path, children);
//    }
//    for (const child of children) out.push(...await collectLeaves(child));
//    return out;
//  };
//
//  // 'all' | 'some' | 'none' — по загруженным уровням; нераскрытая группа с
//  // выбранными потомками честно помечается частичным покрытием.
//  const coverage = node => {
//    if (node.kind === 'field') return selCovered(node.path) ? 'all' : 'none';
//    let leaves = 0;
//    let covered = 0;
//    let unknown = false;
//    const walk = n => {
//      if (n.kind === 'field') {
//        leaves += 1;
//        if (selCovered(n.path)) covered += 1;
//        return;
//      }
//      const children = meta.cache.get(n.path);
//      if (!children) {
//        if (selUnder(n.path)) unknown = true;
//        return;
//      }
//      children.forEach(walk);
//    };
//    (meta.cache.get(node.path) || []).forEach(walk);
//    if (covered === 0 && !unknown) return selUnder(node.path) ? 'some' : 'none';
//    if (!unknown && leaves > 0 && covered === leaves) return 'all';
//    return 'some';
//  };
//
//  const nodeView = (node, withPath) => {
//    const wrap = el('div');
//    const row = el('div', 'nrow');
//    const expanded = meta.expanded.has(node.path);
//    if (node.kind === 'group') {
//      const tw = el('button', 'tw', expanded ? '▾' : '▸');
//      tw.type = 'button';
//      tw.addEventListener('click', () => toggleExpand(node));
//      row.append(tw);
//    } else {
//      row.append(el('span', 'tw'));
//    }
//    const cb = document.createElement('input');
//    cb.type = 'checkbox';
//    const password = node.kind === 'field' && node.password_mode === true;
//    const state = coverage(node);
//    cb.checked = state === 'all';
//    cb.indeterminate = state === 'some';
//    if (password) {
//      cb.disabled = true;
//      cb.title = 'Парольное поле — значения режутся на границе всегда, выбор не требуется';
//    }
//    cb.addEventListener('change', () => toggleNode(node, cb.checked));
//    const name = el('span', 'nname', node.name);
//    name.title = node.path;
//    row.append(cb, name);
//    if (node.kind === 'group') {
//      row.append(el('span', 'fname', `${node.field_count} полей`));
//      if (node.password_count) row.append(el('span', 'fname', `парольных ${node.password_count}`));
//    } else {
//      if (withPath) {
//        const parent = node.path.includes('.') ? node.path.slice(0, node.path.lastIndexOf('.')) : node.path;
//        row.append(el('span', 'fname', parent));
//      }
//      if (node.field_type) row.append(el('span', 'fname', node.field_type));
//      if (password) row.append(el('span', 'tag mut', 'пароль'));
//    }
//    wrap.append(row);
//    if (node.kind === 'group' && expanded) {
//      const kids = el('div', 'kids');
//      const children = meta.cache.get(node.path);
//      if (!children) kids.append(el('p', 'empty', 'Загрузка…'));
//      else if (!children.length) kids.append(el('p', 'empty', 'Пусто'));
//      else children.forEach(child => kids.append(nodeView(child)));
//      wrap.append(kids);
//    }
//    return wrap;
//  };
//
//  const toggleExpand = async node => {
//    if (meta.expanded.has(node.path)) {
//      meta.expanded.delete(node.path);
//      renderTree();
//      return;
//    }
//    meta.expanded.add(node.path);
//    renderTree();
//    if (!meta.cache.has(node.path)) {
//      try {
//        meta.cache.set(node.path, (await loadMeta(node.path)).nodes);
//      } catch (error) {
//        meta.expanded.delete(node.path);
//        showError($('#dictErr'), error);
//      }
//      renderTree();
//    }
//  };
//
//  const toggleNode = async (node, checked) => {
//    $('#dictErr').hidden = true;
//    if (!checked) {
//      dict.selectors = dict.selectors.filter(s =>
//        !(s.source_path === node.path || s.source_path.startsWith(`${node.path}.`)));
//      renderDict();
//      return;
//    }
//    const category = $('#dictCatDefault').value.trim();
//    if (!category) {
//      showError($('#dictErr'), { message: 'Укажите категорию для новых источников в панели «Что маскируется».' });
//      renderDict();
//      return;
//    }
//    if (node.kind === 'field') {
//      if (!selCovered(node.path)) {
//        dict.selectors.push({ source_path: node.path, category, filter_ast: null, in_manifest: true });
//      }
//      renderDict();
//      return;
//    }
//    try {
//      const leaves = await collectLeaves(node);
//      const addable = leaves.filter(leaf => leaf.password_mode !== true && !selCovered(leaf.path));
//      if (dict.selectors.length + addable.length > 100) {
//        showError($('#dictErr'), {
//          message: `Выбор добавит ${addable.length} источников — лимит конфигурации 100. Отметьте объекты точечнее.`,
//        });
//        renderDict();
//        return;
//      }
//      addable.forEach(leaf => dict.selectors.push({
//        source_path: leaf.path, category, filter_ast: null, in_manifest: true,
//      }));
//      meta.expanded.add(node.path);
//      renderDict();
//    } catch (error) {
//      showError($('#dictErr'), error);
//      renderDict();
//    }
//  };
//
//  const renderTree = () => {
//    const box = $('#dictTree');
//    box.replaceChildren();
//    if (meta.search) {
//      const { nodes, truncated } = meta.search;
//      if (!nodes.length) box.append(el('p', 'empty', 'Ничего не найдено'));
//      else nodes.forEach(node => box.append(nodeView(node, true)));
//      if (truncated) box.append(el('p', 'empty', 'Показаны первые 200 совпадений — уточните запрос'));
//      return;
//    }
//    if (meta.ready === null) { box.append(el('p', 'empty', 'Загрузка…')); return; }
//    if (meta.ready === false) { box.append(el('p', 'empty', 'Метаданные не получены')); return; }
//    if (!meta.root.length) { box.append(el('p', 'empty', 'Манифест пуст')); return; }
//    meta.root.forEach(node => box.append(nodeView(node)));
//  };
//
//  // Панель «Что маскируется»: сохранённые вне manifest источники
//  // (in_manifest === false) остаются в списке и подсвечиваются красным —
//  // не удаляем молча.
//  const renderSelPanel = () => {
//    const stale = dict.selectors.filter(s => s.in_manifest === false).length;
//    const parts = [`Выбрано источников: ${dict.selectors.length}/100`];
//    const diff = diffCount();
//    if (diff) parts.push(`изменений: ${diff}`);
//    if (stale) parts.push(`нет в конфигурации: ${stale}`);
//    $('#dictCount').textContent = parts.join(' · ');
//    const list = $('#dictSelList');
//    list.replaceChildren();
//    if (!dict.selectors.length) {
//      list.append(el('p', 'empty', 'Ничего не выбрано'));
//      return;
//    }
//    const groups = new Map();
//    dict.selectors.forEach(s => {
//      const i = s.source_path.lastIndexOf('.');
//      const parent = i > 0 ? s.source_path.slice(0, i) : s.source_path;
//      if (!groups.has(parent)) groups.set(parent, []);
//      groups.get(parent).push(s);
//    });
//    for (const [parent, rows] of groups) {
//      list.append(el('div', 'mono small muted mt8', parent));
//      rows.forEach(s => {
//        const row = el('div', `selrow${s.in_manifest === false ? ' stale' : ''}`);
//        const name = el('span', 'sname mono small', s.source_path.split('.').pop());
//        name.title = s.source_path;
//        row.append(name);
//        if (s.in_manifest === false) row.append(el('span', 'tag err', 'нет в конфигурации'));
//        if (s.filter_ast) {
//          const tag = el('span', 'tag mut', 'условие');
//          tag.title = JSON.stringify(s.filter_ast);
//          row.append(tag);
//        }
//        const cat = el('input', 'input cat');
//        cat.value = s.category;
//        cat.maxLength = 32;
//        cat.addEventListener('change', () => { s.category = cat.value.trim(); renderSelPanel(); });
//        row.append(cat);
//        const rm = el('button', 'btn sm', '✕');
//        rm.type = 'button';
//        rm.title = 'Убрать источник';
//        rm.addEventListener('click', () => {
//          dict.selectors.splice(dict.selectors.indexOf(s), 1);
//          renderDict();
//        });
//        row.append(rm);
//        list.append(row);
//      });
//    }
//  };
//
//  const renderDict = () => {
//    $$('#dictMode button').forEach(b => b.classList.toggle('on', b.dataset.mode === dict.mode));
//    $('#dictModeHint').textContent = dict.mode === 'all'
//      ? 'Маскируются все справочники, разрешённые действующими правилами.'
//      : 'Маскируются только источники, отмеченные в дереве или добавленные вручную.';
//    $('#dictPart').hidden = dict.mode === 'all';
//    $('#dictNoManifest').hidden = meta.ready !== false;
//    renderTree();
//    renderSelPanel();
//  };
//
//  // Когда manifest подгрузился после «Обновить сейчас» — добираем флаги
//  // in_manifest для уже введённых/сохранённых selectors.
//  const mergeManifestFlags = async () => {
//    try {
//      const configs = await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/dictionaries`);
//      if (!configs.length) return;
//      const flags = new Map(configs[0].selectors.map(s => [s.source_path, s.in_manifest]));
//      dict.selectors.forEach(s => {
//        if (flags.has(s.source_path)) s.in_manifest = flags.get(s.source_path);
//      });
//    } catch (_) { /* флаги только для подсветки — молча пропускаем */ }
//  };
//
//  $('#dictRefresh').addEventListener('click', async () => {
//    if (!dbs.current) return;
//    try {
//      await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/refresh`, { method: 'POST' });
//      $('#dictRefreshState').textContent = 'выполняется…';
//      let tries = 0;
//      meta.poll = setInterval(async () => {
//        tries += 1;
//        try {
//          const page = await loadMeta('');
//          if (page.manifest_ready) {
//            clearInterval(meta.poll);
//            meta.poll = null;
//            meta.ready = true;
//            meta.root = page.nodes;
//            meta.cache = new Map([['', page.nodes]]);
//            $('#dictRefreshState').textContent = '';
//            await mergeManifestFlags();
//            renderDict();
//          } else if (tries > 20) {
//            clearInterval(meta.poll);
//            meta.poll = null;
//            $('#dictRefreshState').textContent = 'не завершено — попробуйте позже';
//          }
//        } catch (_) { /* опрос — молча до следующего тика */ }
//      }, 3000);
//    } catch (error) {
//      showError($('#dictErr'), error);
//    }
//  });
//
//  let dictSearchTimer = null;
//  $('#dictSearch').addEventListener('input', () => {
//    clearTimeout(dictSearchTimer);
//    dictSearchTimer = setTimeout(async () => {
//      const q = $('#dictSearch').value.trim();
//      if (!q) {
//        meta.search = null;
//        renderTree();
//        return;
//      }
//      if (!dbs.current) return;
//      try {
//        meta.search = await api(
//          `/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/metadata?q=${encodeURIComponent(q)}`);
//      } catch (error) {
//        meta.search = null;
//        showError($('#dictErr'), error);
//      }
//      renderTree();
//    }, 300);
//  });
//
//  $$('#dictMode button').forEach(btn => btn.addEventListener('click', () => {
//    if (btn.dataset.mode === 'all' && dict.selectors.length && dict.mode !== 'all') {
//      askConfirm('Маскировать все справочники?', 'Список выбранных источников будет сброшен при сохранении.', () => {
//        dict.mode = 'all';
//        renderDict();
//      });
//    } else {
//      dict.mode = btn.dataset.mode;
//      renderDict();
//    }
//  }));
//  $('#dictAdd').addEventListener('click', () => {
//    $('#dictErr').hidden = true;
//    const sourcePath = $('#dictPath').value.trim();
//    const category = $('#dictCat').value.trim();
//    let filterAst = null;
//    const filterRaw = $('#dictFilter').value.trim();
//    if (filterRaw && filterRaw !== 'null') {
//      try {
//        filterAst = JSON.parse(filterRaw);
//      } catch (_) {
//        showError($('#dictErr'), { message: 'Условие должно быть корректным JSON или пустым.' });
//        return;
//      }
//    }
//    if (!sourcePath || !category) {
//      showError($('#dictErr'), { message: 'Заполните источник и категорию.' });
//      return;
//    }
//    if (dict.mode === 'all') dict.mode = 'part';
//    dict.selectors.push({ source_path: sourcePath, category, filter_ast: filterAst, in_manifest: null });
//    if (!$('#dictCatDefault').value.trim()) $('#dictCatDefault').value = category;
//    $('#dictPath').value = '';
//    $('#dictCat').value = '';
//    $('#dictFilter').value = '';
//    renderDict();
//  });
//  $('#dictSave').addEventListener('click', async () => {
//    if (!dbs.current) return;
//    $('#dictErr').hidden = true;
//    // Служебное вычисляемое поле in_manifest не уходит в контракт хранения.
//    const selectors = dict.mode === 'all'
//      ? [{ source_path: '*', category: '*', filter_ast: null }]
//      : dict.selectors.map(s => ({ source_path: s.source_path, category: s.category, filter_ast: s.filter_ast ?? null }));
//    if (!selectors.length) {
//      showError($('#dictErr'), { message: 'В режиме «только выбранные» нужен хотя бы один источник.' });
//      return;
//    }
//    if (selectors.length > 100) {
//      showError($('#dictErr'), { message: `Выбрано ${selectors.length} источников — лимит конфигурации 100.` });
//      return;
//    }
//    if (selectors.some(s => !s.category)) {
//      showError($('#dictErr'), { message: 'У каждого источника должна быть заполнена категория.' });
//      return;
//    }
//    try {
//      await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/dictionaries/${encodeURIComponent(dict.id || crypto.randomUUID())}`, {
//        method: 'PUT',
//        body: JSON.stringify({ id: dict.id || '00000000-0000-0000-0000-000000000000', mode: dict.mode, selectors }),
//      });
//      await loadDict(dbs.current);
//    } catch (error) {
//      showError($('#dictErr'), error.status === 409
//        ? { message: 'Конфигурация справочников отклонена: проверьте список источников.' }
//        : error);
//    }
//  });
//
//  // Правила
//  let policies = [];
//  const loadPolicies = async db => {
//    try {
//      policies = await api(`/api/v1/admin/databases/${encodeURIComponent(db.id)}/policies`);
//    } catch (error) {
//      if (error.status !== 401) showError($('#polErr'), error);
//      return;
//    }
//    renderPolicies();
//  };
//  const renderPolicies = () => {
//    const body = $('#polBody');
//    body.replaceChildren();
//    if (!policies.length) {
//      const tr = body.insertRow();
//      const td = tr.insertCell();
//      td.colSpan = 4;
//      td.className = 'empty';
//      td.textContent = 'Версий правил пока нет';
//    }
//    for (const policy of policies) {
//      const tr = body.insertRow();
//      tr.append(el('td', '', String(policy.version)));
//      const [cls, label] = POLICY_STATUS[policy.status] || ['mut', policy.status];
//      const statusTd = el('td');
//      statusTd.append(el('span', `tag ${cls}`, label));
//      tr.append(statusTd);
//      tr.append(el('td', '', String(policy.rules.length)));
//      const actions = el('td');
//      if (policy.status === 'draft') {
//        const activate = el('button', 'btn sm', 'Сделать действующей');
//        activate.type = 'button';
//        activate.addEventListener('click', () => {
//          askConfirm('Сделать версию действующей?', `Версия ${policy.version} начнет применяться к новым вызовам; текущая действующая версия уйдёт в архив.`, async () => {
//            try {
//              await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/policies/${encodeURIComponent(policy.id)}/activate`, { method: 'POST' });
//              await loadPolicies(dbs.current);
//            } catch (error) {
//              showError($('#polErr'), error.code === 'SECRET_POLICY_UNSUPPORTED'
//                ? { message: 'Версия содержит secret-правила: они недоступны до включения предменеджерной защиты.' }
//                : error);
//            }
//          });
//        });
//        actions.append(activate);
//      }
//      const details = el('button', 'btn sm', 'Просмотр');
//      details.type = 'button';
//      details.classList.add('ml6');
//      actions.append(details);
//      tr.append(actions);
//      const rulesRow = body.insertRow();
//      rulesRow.hidden = true;
//      const rulesCell = rulesRow.insertCell();
//      rulesCell.colSpan = 4;
//      const inner = el('table');
//      const head = inner.createTHead().insertRow();
//      ['Селектор', 'Значение', 'Действие', 'Категория', 'Приоритет'].forEach(h => head.append(el('th', '', h)));
//      const innerBody = inner.createTBody();
//      for (const rule of policy.rules) {
//        const rr = innerBody.insertRow();
//        rr.append(el('td', '', rule.selector_kind));
//        rr.append(el('td', 'mono', rule.selector_value));
//        rr.append(el('td', '', rule.action));
//        rr.append(el('td', '', rule.category));
//        rr.append(el('td', '', String(rule.priority)));
//      }
//      rulesCell.append(inner);
//      details.addEventListener('click', () => { rulesRow.hidden = !rulesRow.hidden; });
//    }
//    const active = policies.find(p => p.status === 'active');
//    $('#polNew').disabled = !active;
//    $('#polNew').title = active ? '' : 'Нет действующей версии — нечего копировать';
//  };
//  $('#polNew').addEventListener('click', async () => {
//    const active = policies.find(p => p.status === 'active');
//    if (!active || !dbs.current) return;
//    try {
//      await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/policies`, {
//        method: 'POST',
//        body: JSON.stringify({ rules: active.rules }),
//      });
//      await loadPolicies(dbs.current);
//    } catch (error) {
//      showError($('#polErr'), error);
//    }
//  });
//
  //--agent TASK-225
  //++agent TASK-225 [26.09.2026 02:20:00] фаза 3 — «Настройка маскирования»,
  // «Инструменты», «Журнал настройки». Все изменения настройки идут только
  // через черновик (setup/draft + If-Match) и активацию B7 с поштучным
  // подтверждением ослаблений; UI не единственный барьер — сервер
  // перепроверяет diff сам. Значения из базы в админку не попадают: сухой
  // прогон отдаёт только координаты и статусы ячеек.
  const dbPath = suffix => `/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}${suffix}`;
  const ACTION_TAG = { secret: ['err', 'Секрет'], mask: ['acc', 'Скрыть'], keep: ['warn', 'Не маскировать'] };
  const SELECTOR_LABEL = {
    source_path: 'Путь', name: 'Имя поля', type: 'Тип', dictionary: 'Категория словаря', regex: 'Шаблон',
  };
  const TOOL_MODES = [
    ['data-mask', 'Маскировать данные', 'acc',
      'Ответ инструмента проходит через маскирование. Для всех инструментов, возвращающих данные базы.'],
    ['no-mask', 'Без маскирования', 'warn',
      'Ответ передаётся агенту как есть. Только для инструментов, которые не возвращают данных базы: метаданные, проверка синтаксиса, управление окнами и служебные операции.'],
    ['deny-pending-review', 'Запрещён до проверки', 'err',
      'Вызов отклоняется. Так работает любой новый инструмент, пока администратор не выберет режим.'],
  ];
  const TOOL_MODE = Object.fromEntries(TOOL_MODES.map(m => [m[0], m]));
  // Та же эвристика «похоже на чтение данных», что у сервера (spec §3.5).
  const dataLikeWord = name => (String(name).toLowerCase().match(/query|select|data|record|history|get_|read/) || [])[0] || '';

  const iconSvg = paths => {
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('class', 'ico');
    svg.setAttribute('aria-hidden', 'true');
    paths.forEach(d => {
      const path = document.createElementNS(NS, 'path');
      path.setAttribute('d', d);
      svg.append(path);
    });
    return svg;
  };
  $('#setupEmptyIco').append(iconSvg(['M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z', 'M9 12h6']));
  $('#dropIco').append(iconSvg(['M12 16V4', 'M7 9l5-5 5 5', 'M4 20h16']));

  const fmtBytes = n => {
    const v = Number(n) || 0;
    if (v >= 1024 * 1024 * 1024) return `${(v / 1024 / 1024 / 1024).toFixed(1).replace('.', ',')} ГБ`;
    if (v >= 1024 * 1024) return `${Math.round(v / 1024 / 1024).toLocaleString('ru-RU')} МБ`;
    if (v >= 1024) return `${(v / 1024).toFixed(1).replace('.', ',')} КБ`;
    return `${v} Б`;
  };
  const fmtMs = v => `${(Number(v) || 0) < 10 ? (Number(v) || 0).toFixed(1).replace('.', ',') : Math.round(Number(v) || 0)} мс`;
  const shortHash = h => (h && h.length > 16 ? `${h.slice(0, 10)}…${h.slice(-6)}` : (h || '—'));
  const hideNote = id => { const n = $(id); if (n) n.hidden = true; };
  const showNote = (id, text) => { const n = $(id); n.textContent = text; n.hidden = false; };

  // Путь ошибки разбора ($.rules[3].value) → человеческое место в файле.
  const humanAt = at => {
    const s = String(at || '');
    let m = s.match(/^\$\.dictionary\.sources\[(\d+)\]/);
    if (m) return `Словарь, источник ${Number(m[1]) + 1}`;
    m = s.match(/^\$\.rules\[(\d+)\]/);
    if (m) return `Правило ${Number(m[1]) + 1}`;
    m = s.match(/^\$\.tools\[(\d+)\]/);
    if (m) return `Инструмент ${Number(m[1]) + 1}`;
    if (s === '$' || !s) return 'Файл';
    return s.replace(/^\$\./, '');
  };
  const issuesList = (node, head, errors, truncated) => {
    node.replaceChildren(document.createTextNode(head));
    const ul = el('ul', 'errlist');
    (errors || []).forEach(issue => ul.append(el('li', '', `${humanAt(issue.at)}: ${issue.message || issue.code}`)));
    node.append(ul);
    if (truncated) node.append(el('div', 'small', 'Показаны первые ошибки — исправьте их и повторите.'));
    node.hidden = false;
  };

  // --- состояние вкладки «Настройка маскирования» ---
  const setup = {
    policies: [],
    activeDict: { mode: 'part', sources: [] },
    activeRules: [],
    draft: null, // GET setup/draft: {version, draft_hash, dictionary, rules, tools}
    ed: null, // редактируемая/просматриваемая копия: {editable, version, hash, mode, sources, rules}
    savedDict: '', savedRules: '',
    focus: null, // deep-link из «Почему скрыто»: {rule, source, version}
  };
  const activeVersion = () => setup.policies.find(p => p.status === 'active') || null;

  const normSource = s => ({
    source_path: s.source_path,
    category: s.category,
    filter_ast: s.filter !== undefined ? s.filter : (s.filter_ast ?? null),
    reason: s.reason || '',
    estimated_values: s.estimated_values,
    in_manifest: s.in_manifest,
  });
  const sourceOut = s => {
    const out = { source_path: s.source_path, category: s.category, reason: s.reason };
    if (s.filter_ast) out.filter = s.filter_ast;
    if (Number.isInteger(s.estimated_values)) out.estimated_values = s.estimated_values;
    return out;
  };
  const ruleOut = r => {
    const out = {
      selector: r.selector, value: r.value, action: r.action, category: r.category,
      priority: Number(r.priority) || 0, enabled: r.enabled !== false, reason: r.reason,
    };
    if (r.selector === 'regex' && r.tests && ((r.tests.match || []).length || (r.tests.no_match || []).length)) {
      out.tests = {};
      if ((r.tests.match || []).length) out.tests.match = r.tests.match;
      if ((r.tests.no_match || []).length) out.tests.no_match = r.tests.no_match;
    }
    return out;
  };
  const dictSnapshot = () => JSON.stringify({ mode: setup.ed.mode, sources: setup.ed.sources.map(sourceOut) });
  const rulesSnapshot = () => JSON.stringify(setup.ed.rules.map(ruleOut));
  const ruleKey = r => `${r.selector}\u0001${r.selector === 'regex' ? r.value : String(r.value).toLowerCase()}`;
  const ruleSig = r => `${ruleKey(r)}\u0001${r.action}\u0001${r.category}\u0001${Number(r.priority) || 0}\u0001${r.enabled !== false}`;
  const srcSig = s => `${s.source_path.toLowerCase()}\u0001${s.category}\u0001${JSON.stringify(s.filter_ast || null)}`;

  const loadSetup = async db => {
    hideNote('#setupErr');
    hideNote('#setupOk');
    $('#setupWizard').hidden = true;
    setup.draft = null;
    try {
      // D2 закрыт: список версий и содержимое — read-only setup/versions (без аудита).
      const base = `/api/v1/admin/databases/${encodeURIComponent(db.id)}/setup/versions`;
      setup.policies = (await api(base) || []).map(v => ({ ...v, rules: [] }));
      const active = activeVersion();
      if (active) {
        const content = await api(`${base}/${active.version}`);
        active.rules = content.rules || [];
        setup.activeRules = active.rules.map(r => ({ ...r, enabled: r.enabled !== false, reason: r.reason || '' }));
        setup.activeDict = {
          mode: (content.dictionary || {}).mode || 'part',
          sources: ((content.dictionary || {}).sources || []).map(normSource),
        };
      } else {
        setup.activeRules = [];
        setup.activeDict = { mode: 'part', sources: [] };
      }
    } catch (error) {
      if (error.status !== 401) showError($('#setupErr'), error);
      return;
    }
    try {
      setup.draft = await api(`/api/v1/admin/databases/${encodeURIComponent(db.id)}/setup/draft`);
    } catch (error) {
      if (error.code !== 'NO_DRAFT' && error.status !== 404 && error.status !== 401) showError($('#setupErr'), error);
      setup.draft = null;
    }
    renderSetup();
  };

  const buildEditorModel = () => {
    const d = setup.draft;
    if (d) {
      setup.ed = {
        editable: true, version: d.version, hash: d.draft_hash, origin: d.origin,
        mode: d.dictionary.mode,
        sources: d.dictionary.sources.map(normSource),
        rules: d.rules.map(r => ({ ...r, tests: r.tests ? { ...r.tests } : null })),
      };
    } else {
      const active = activeVersion();
      setup.ed = {
        editable: false, version: active ? active.version : null, hash: null,
        mode: setup.activeDict.mode,
        sources: setup.activeDict.sources.map(s => ({ ...s })),
        rules: setup.activeRules.map(r => ({ ...r })),
      };
    }
    setup.savedDict = dictSnapshot();
    setup.savedRules = rulesSnapshot();
  };

  const renderSetup = () => {
    const db = dbs.current;
    const active = activeVersion();
    const draft = setup.draft;
    if (active) {
      const srcCount = setup.activeDict.sources.length;
      $('#verInfo').textContent = `Действует версия ${active.version} · ${srcCount} ${ruPlural(srcCount, 'источник', 'источника', 'источников')} словаря · ${active.rules.length} ${ruPlural(active.rules.length, 'правило', 'правила', 'правил')}${draft ? ` · есть черновик ${draft.version}` : ''}`;
    } else {
      $('#verInfo').textContent = draft ? `Действующей версии нет · черновик ${draft.version}` : 'Действующей версии нет';
    }
    //++agent TASK-225 [26.09.2026] K: при needs_attention загрузка
    // остановлена — «Словарь загружается…» не показываем.
    const loading = db.refresh_stage && db.refresh_stage !== 'active'
      && !(db.refresh && db.refresh.state === 'needs_attention');
    //++agent TASK-225
    $('#verDictLoad').hidden = !loading;
    $('#verDictLoad').textContent = 'Словарь загружается…';
    $('#setupExportBtn').disabled = !active && !draft;
    $('#setupDraftBtn').textContent = draft ? `Открыть черновик ${draft.version}` : 'Новый черновик';
    const empty = !active && !draft;
    $('#setupEmpty').hidden = !empty;
    $('#setupEditor').hidden = empty;
    if (empty) {
      //++agent TASK-225 [27.09.2026 08:10:00]
      // Промпт адресует конкретную базу: имя неоднозначно (DEV-копия и
      // рабочая база часто называются похоже), поэтому id записи сервиса +
      // координаты ИБ, а навык назван явно.
      const where = [db.cluster_server, db.infobase_name].filter(Boolean).join(' / ');
      const ask = `«Выполни навык masking-initial-setup для базы ${db.display_label || db.infobase_name || db.id}`
        + `${where ? ` (${where})` : ''}, id в сервисе маскирования: ${db.id}»`;
      //++agent TASK-225
      $('#emptyAsk').textContent = ask;
      $('#emptyNoManifest').hidden = meta.ready !== false;
      return;
    }
    buildEditorModel();
    renderDraftNote();
    renderDict();
    renderRules();
    renderVersions();
    applyFocus();
  };

  const renderDraftNote = () => {
    const ed = setup.ed;
    const active = activeVersion();
    if (ed.editable) {
      const from = setup.draft.origin === 'import' ? ' (из файла)' : setup.draft.origin === 'rollback' ? ` (копия версии ${setup.draft.origin_ref})` : '';
      $('#draftNoteText').replaceChildren(document.createTextNode('Вы редактируете '), el('b', '', `черновик ${ed.version}${from}`),
        document.createTextNode('. Изменения не действуют до активации.'));
    } else {
      $('#draftNoteText').replaceChildren(document.createTextNode('Показана '), el('b', '', `действующая версия ${active ? active.version : ''}`),
        document.createTextNode(' — только просмотр. Изменения делаются в черновике.'));
    }
    $('#draftCompare').hidden = !ed.editable;
    $('#draftActivate').hidden = !ed.editable;
    $('#draftDiscard').hidden = !ed.editable;
    $('#draftStart').hidden = ed.editable;
    hideNote('#draftConflict');
  };

  // 409 DRAFT_CHANGED: кто-то изменил черновик — локальные правки не
  // отправляем поверх, предлагаем загрузить свежую версию.
  const draftConflict = error => {
    const d = error.details || {};
    const note = $('#draftConflict');
    note.replaceChildren(document.createTextNode(
      `Черновик изменён другим сеансом${d.updated_at ? ` (${fmtTime(d.updated_at)})` : ''}. Ваши несохранённые изменения не отправлены. `));
    const btn = el('button', 'btn link', 'Загрузить свежий черновик');
    btn.type = 'button';
    btn.addEventListener('click', () => loadSetup(dbs.current));
    note.append(btn);
    note.hidden = false;
  };

  const putDraftArea = async (area, body) => {
    const result = await api(dbPath(`/setup/draft/${area}`), {
      method: 'PUT',
      headers: { 'If-Match': `"${setup.ed.hash}"` },
      body: JSON.stringify(body),
    });
    setup.ed.hash = result.draft_hash;
    if (setup.draft) setup.draft.draft_hash = result.draft_hash;
    return result;
  };

  const createDraft = async from => {
    await api(dbPath('/setup/draft'), { method: 'POST', body: JSON.stringify({ from }) });
    await loadDatabases();
    await loadSetup(dbs.current);
  };

  $('#draftStart').addEventListener('click', async () => {
    try { await createDraft('active'); } catch (error) {
      showError($('#setupErr'), error.code === 'DRAFT_EXISTS' ? { message: 'Черновик уже есть — обновите страницу.' } : error);
    }
  });
  $('#setupDraftBtn').addEventListener('click', async () => {
    if (setup.draft) {
      $('#setupWizard').hidden = true;
      $('#setupEditor').hidden = false;
      $('#setupEmpty').hidden = true;
      return;
    }
    try { await createDraft(activeVersion() ? 'active' : 'empty'); } catch (error) { showError($('#setupErr'), error); }
  });
  $('#emptyManual').addEventListener('click', async () => {
    try { await createDraft('empty'); } catch (error) { showError($('#setupErr'), error); }
  });
  $('#emptyAskCopy').addEventListener('click', e => copyText($('#emptyAsk').textContent, e.currentTarget));
  $('#emptyRefresh').addEventListener('click', () => $('#refreshBtn').click());
  $('#draftDiscard').addEventListener('click', () => {
    if (!setup.draft) return;
    askConfirm(`Удалить черновик ${setup.draft.version}?`, 'Все изменения черновика будут потеряны. Действующая версия не изменится.', async () => {
      try {
        await api(dbPath('/setup/draft'), { method: 'DELETE', headers: { 'If-Match': `"${setup.ed.hash}"` } });
        await loadDatabases();
        await loadSetup(dbs.current);
      } catch (error) {
        if (error.code === 'DRAFT_CHANGED') draftConflict(error); else showError($('#setupErr'), error);
      }
    });
  });
  $('#draftCompare').addEventListener('click', () => openWizard('draft', 2));
  $('#draftActivate').addEventListener('click', () => openWizard('draft', 2));

  const setSub = name => {
    $$('#setupSub button').forEach(b => b.classList.toggle('on', b.dataset.st === name));
    ['dict', 'rules', 'versions'].forEach(n => { $(`#st-${n}`).hidden = n !== name; });
  };
  $$('#setupSub button').forEach(btn => btn.addEventListener('click', () => setSub(btn.dataset.st)));

  // ---------- Словарь (дерево TASK-224 поверх черновика) ----------
  const meta = { ready: null, root: [], cache: new Map(), expanded: new Set(), search: null, poll: null, filter: 'all' };
  const resetMeta = () => {
    meta.ready = null;
    meta.root = [];
    meta.cache = new Map();
    meta.expanded = new Set();
    meta.search = null;
    if (meta.poll) { clearInterval(meta.poll); meta.poll = null; }
  };
  const loadMeta = path => api(dbPath(`/metadata?path=${encodeURIComponent(path)}`));
  const loadMetaRoot = async () => {
    resetMeta();
    try {
      const page = await loadMeta('');
      meta.ready = page.manifest_ready;
      meta.root = page.nodes;
      meta.cache.set('', page.nodes);
    } catch (error) {
      if (error.status !== 401) showError($('#dictErr'), error);
    }
  };

  const eds = () => (setup.ed ? setup.ed.sources : []);
  const selCovered = path => eds().some(s => s.source_path === path);
  const selUnder = path => eds().some(s => s.source_path === path || s.source_path.startsWith(`${path}.`));
  const activeSrcSig = () => new Map(setup.activeDict.sources.map(s => [s.source_path.toLowerCase(), srcSig(s)]));
  // Пути, по которым черновик отличается от действующей: добавлен/снят/изменён.
  const changedPaths = () => {
    const act = activeSrcSig();
    const out = new Map();
    eds().forEach(s => {
      const k = s.source_path.toLowerCase();
      if (!act.has(k)) out.set(k, 'added');
      else if (act.get(k) !== srcSig(s)) out.set(k, 'changed');
    });
    const cur = new Set(eds().map(s => s.source_path.toLowerCase()));
    setup.activeDict.sources.forEach(s => { if (!cur.has(s.source_path.toLowerCase())) out.set(s.source_path.toLowerCase(), 'removed'); });
    return out;
  };

  const collectLeaves = async node => {
    if (node.kind === 'field') return [node];
    const out = [];
    if (node.field_type !== undefined) out.push({ path: node.path, password_mode: node.password_mode });
    let children = meta.cache.get(node.path);
    if (!children) {
      children = (await loadMeta(node.path)).nodes;
      meta.cache.set(node.path, children);
    }
    for (const child of children) out.push(...await collectLeaves(child));
    return out;
  };
  const coverage = node => {
    if (node.kind === 'field') return selCovered(node.path) ? 'all' : 'none';
    let leaves = 0;
    let covered = 0;
    let unknown = false;
    const walk = n => {
      if (n.kind === 'field') {
        leaves += 1;
        if (selCovered(n.path)) covered += 1;
        return;
      }
      const children = meta.cache.get(n.path);
      if (!children) {
        if (selUnder(n.path)) unknown = true;
        return;
      }
      children.forEach(walk);
    };
    (meta.cache.get(node.path) || []).forEach(walk);
    if (covered === 0 && !unknown) return selUnder(node.path) ? 'some' : 'none';
    if (!unknown && leaves > 0 && covered === leaves) return 'all';
    return 'some';
  };

  const nodeView = (node, withPath, changed) => {
    const wrap = el('div');
    const row = el('div', 'nrow');
    const expanded = meta.expanded.has(node.path);
    if (node.kind === 'group') {
      const tw = el('button', 'tw', expanded ? '▾' : '▸');
      tw.type = 'button';
      tw.addEventListener('click', () => toggleExpand(node));
      row.append(tw);
    } else {
      row.append(el('span', 'tw'));
    }
    const password = node.kind === 'field' && node.password_mode === true;
    if (password) {
      const lock = el('span', 'lock', 'П');
      lock.title = 'Поле-пароль — значения вырезаются всегда, выбор не требуется';
      row.append(lock);
    } else {
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      const cov = coverage(node);
      cb.checked = cov === 'all';
      cb.indeterminate = cov === 'some';
      cb.disabled = !setup.ed || !setup.ed.editable;
      if (cb.disabled) cb.title = 'Только просмотр — создайте черновик, чтобы изменить';
      cb.addEventListener('change', () => toggleNode(node, cb.checked));
      row.append(cb);
    }
    const mark = changed && changed.get(node.path.toLowerCase());
    if (mark) row.append(el('i', 'chgdot'));
    const name = el('span', `nname${mark === 'removed' ? ' del' : ''}`, node.name);
    name.title = node.path;
    row.append(name);
    if (node.kind === 'group') {
      row.append(el('span', 'fname', `${node.field_count} ${ruPlural(node.field_count, 'поле', 'поля', 'полей')}${node.password_count ? ` · паролей ${node.password_count}` : ''}`));
    } else {
      if (withPath) {
        const parent = node.path.includes('.') ? node.path.slice(0, node.path.lastIndexOf('.')) : node.path;
        row.append(el('span', 'fname', parent));
      }
      if (password) row.append(el('span', 'fname', 'пароль · всегда'));
      else if (node.field_type) row.append(el('span', 'fname', node.field_type));
      const src = eds().find(s => s.source_path === node.path);
      if (src) row.append(el('span', 'tag plain', src.category));
      if (mark === 'added') row.append(el('span', 'tag ok plain', 'новый'));
      if (mark === 'removed') row.append(el('span', 'fname', 'снят в черновике'));
    }
    wrap.append(row);
    if (node.kind === 'group' && expanded) {
      const kids = el('div', 'kids');
      const children = meta.cache.get(node.path);
      if (!children) kids.append(el('p', 'empty', 'Загрузка…'));
      else if (!children.length) kids.append(el('p', 'empty', 'Пусто'));
      else children.forEach(child => kids.append(nodeView(child, false, changed)));
      wrap.append(kids);
    }
    return wrap;
  };

  const toggleExpand = async node => {
    if (meta.expanded.has(node.path)) {
      meta.expanded.delete(node.path);
      renderTree();
      return;
    }
    meta.expanded.add(node.path);
    renderTree();
    if (!meta.cache.has(node.path)) {
      try {
        meta.cache.set(node.path, (await loadMeta(node.path)).nodes);
      } catch (error) {
        meta.expanded.delete(node.path);
        showError($('#dictErr'), error);
      }
      renderTree();
    }
  };

  const newSource = path => ({
    source_path: path,
    category: $('#dictCatDefault').value.trim(),
    filter_ast: null,
    reason: $('#dictReasonDefault').value.trim(),
    in_manifest: true,
  });
  const toggleNode = async (node, checked) => {
    hideNote('#dictErr');
    if (!checked) {
      setup.ed.sources = eds().filter(s => !(s.source_path === node.path || s.source_path.startsWith(`${node.path}.`)));
      renderDict();
      return;
    }
    if (!$('#dictCatDefault').value.trim() || !$('#dictReasonDefault').value.trim()) {
      showError($('#dictErr'), { message: 'Укажите категорию и обоснование для новых источников в панели справа.' });
      renderDict();
      return;
    }
    if (node.kind === 'field') {
      if (!selCovered(node.path)) setup.ed.sources.push(newSource(node.path));
      renderDict();
      return;
    }
    try {
      const leaves = await collectLeaves(node);
      const addable = leaves.filter(leaf => leaf.password_mode !== true && !selCovered(leaf.path));
      if (eds().length + addable.length > 100) {
        showError($('#dictErr'), { message: `Выбор добавит ${addable.length} источников — лимит настройки 100. Отметьте объекты точечнее.` });
        renderDict();
        return;
      }
      addable.forEach(leaf => setup.ed.sources.push(newSource(leaf.path)));
      meta.expanded.add(node.path);
      renderDict();
    } catch (error) {
      showError($('#dictErr'), error);
      renderDict();
    }
  };

  // Плоский список для фильтров «Только отмеченные / Только изменённые».
  const flatRow = (path, changed) => {
    const leaf = path.split('.').pop();
    const src = eds().find(s => s.source_path === path)
      || setup.activeDict.sources.find(s => s.source_path.toLowerCase() === path.toLowerCase());
    return nodeView({
      kind: 'field', name: leaf, path: src ? src.source_path : path, field_type: undefined,
      password_mode: false,
    }, true, changed);
  };
  const renderTree = () => {
    const box = $('#dictTree');
    box.replaceChildren();
    const changed = changedPaths();
    if (meta.filter !== 'all' && !meta.search) {
      const paths = meta.filter === 'sel'
        ? eds().map(s => s.source_path)
        : [...changed.keys()].map(k => {
          const s = eds().find(x => x.source_path.toLowerCase() === k)
            || setup.activeDict.sources.find(x => x.source_path.toLowerCase() === k);
          return s ? s.source_path : k;
        });
      if (!paths.length) box.append(el('p', 'empty', meta.filter === 'sel' ? 'Ничего не отмечено' : 'Черновик не отличается от действующей версии'));
      paths.sort().forEach(p => {
        const view = flatRow(p, changed);
        const src = eds().find(s => s.source_path === p);
        if (src && src.in_manifest === false) {
          view.firstChild.classList.add('stale');
          view.firstChild.append(el('span', 'fname warnc', '⚠ нет в метаданных'));
        }
        box.append(view);
      });
      return;
    }
    if (meta.search) {
      const { nodes, truncated } = meta.search;
      if (!nodes.length) box.append(el('p', 'empty', 'Ничего не найдено'));
      else nodes.forEach(node => box.append(nodeView(node, true, changed)));
      if (truncated) box.append(el('p', 'empty', 'Показаны первые 200 совпадений — уточните запрос'));
      return;
    }
    if (meta.ready === null) { box.append(el('p', 'empty', 'Загрузка…')); return; }
    if (meta.ready === false) { box.append(el('p', 'empty', 'Метаданные не получены')); return; }
    if (!meta.root.length) { box.append(el('p', 'empty', 'Манифест пуст')); return; }
    meta.root.forEach(node => box.append(nodeView(node, false, changed)));
    // Источники вне manifest в дереве не видны — перечисляем их отдельно.
    const stale = eds().filter(s => s.in_manifest === false);
    stale.forEach(s => {
      const view = flatRow(s.source_path, changed);
      view.firstChild.classList.add('stale');
      view.firstChild.append(el('span', 'fname warnc', '⚠ нет в метаданных'));
      box.append(view);
    });
  };

  const refreshCategories = () => {
    const cats = new Set();
    eds().forEach(s => s.category && cats.add(s.category));
    setup.activeDict.sources.forEach(s => s.category && cats.add(s.category));
    if (setup.ed) setup.ed.rules.forEach(r => r.category && cats.add(r.category));
    $('#catList').replaceChildren(...[...cats].sort().map(c => { const o = el('option'); o.value = c; return o; }));
  };

  const renderSelPanel = () => {
    const sources = eds();
    const stale = sources.filter(s => s.in_manifest === false).length;
    const parts = [`Выбрано источников: ${sources.length}/100`];
    if (setup.ed && setup.ed.editable && dictSnapshot() !== setup.savedDict) parts.push('есть несохранённые изменения');
    if (stale) parts.push(`нет в метаданных: ${stale}`);
    $('#dictCount').textContent = parts.join(' · ');
    const list = $('#dictSelList');
    list.replaceChildren();
    if (!sources.length) {
      list.append(el('p', 'empty', 'Ничего не выбрано'));
      return;
    }
    const changed = changedPaths();
    const groups = new Map();
    sources.forEach(s => {
      const i = s.source_path.lastIndexOf('.');
      const parent = i > 0 ? s.source_path.slice(0, i) : s.source_path;
      if (!groups.has(parent)) groups.set(parent, []);
      groups.get(parent).push(s);
    });
    for (const [parent, rows] of groups) {
      list.append(el('div', 'mono small muted mt8', parent));
      rows.forEach(s => {
        const row = el('div', `selrow${s.in_manifest === false ? ' stale' : ''}${srcEdit.path === s.source_path ? ' cur' : ''}`);
        if (changed.get(s.source_path.toLowerCase())) row.append(el('i', 'chgdot'));
        const name = el('span', 'sname mono small lnk', s.source_path.split('.').pop());
        name.title = `${s.source_path} — открыть: категория, условие, обоснование`;
        name.addEventListener('click', () => openSource(s.source_path));
        row.append(name);
        if (s.in_manifest === false) row.append(el('span', 'tag err', 'нет в метаданных'));
        if (s.filter_ast) {
          const tag = el('span', 'tag mut', 'условие');
          tag.title = condPhraseText(astToModel(s.filter_ast));
          row.append(tag);
        }
        row.append(el('span', 'tag plain', s.category || '—'));
        list.append(row);
      });
    }
  };

  const renderDict = () => {
    if (!setup.ed) return;
    const editable = setup.ed.editable;
    $$('#dictMode button').forEach(b => {
      b.classList.toggle('on', b.dataset.mode === setup.ed.mode);
      b.disabled = !editable;
    });
    $('#dictModeHint').textContent = setup.ed.mode === 'all'
      ? 'Маскируются все справочники, разрешённые правилами «Скрыть» по пути реквизита.'
      : 'Маскируются только источники, отмеченные в дереве или добавленные вручную.';
    $('#dictPart').hidden = setup.ed.mode === 'all';
    $('#dictNoManifest').hidden = meta.ready !== false;
    $('#dictSave').hidden = !editable;
    $('#dictAdd').disabled = !editable;
    $('#dictSaveHint').textContent = editable && dictSnapshot() !== setup.savedDict ? 'Есть несохранённые изменения словаря' : '';
    refreshCategories();
    renderTree();
    renderSelPanel();
    renderSrcEditor();
  };

  // Когда manifest подгрузился — флаги in_manifest берём из свежего черновика.
  $('#dictRefresh').addEventListener('click', async () => {
    if (!dbs.current) return;
    try {
      await api(dbPath('/refresh'), { method: 'POST' });
      $('#dictRefreshState').textContent = 'выполняется…';
      let tries = 0;
      meta.poll = setInterval(async () => {
        tries += 1;
        try {
          const page = await loadMeta('');
          if (page.manifest_ready) {
            clearInterval(meta.poll);
            meta.poll = null;
            meta.ready = true;
            meta.root = page.nodes;
            meta.cache = new Map([['', page.nodes]]);
            $('#dictRefreshState').textContent = '';
            renderDict();
          } else if (tries > 20) {
            clearInterval(meta.poll);
            meta.poll = null;
            $('#dictRefreshState').textContent = 'не завершено — см. «Основное», причина сбоя';
          }
        } catch (_) { /* опрос — молча до следующего тика */ }
      }, 3000);
    } catch (error) {
      showError($('#dictErr'), error);
    }
  });

  let dictSearchTimer = null;
  $('#dictSearch').addEventListener('input', () => {
    clearTimeout(dictSearchTimer);
    dictSearchTimer = setTimeout(async () => {
      const q = $('#dictSearch').value.trim();
      if (!q) {
        meta.search = null;
        renderTree();
        return;
      }
      if (!dbs.current) return;
      try {
        meta.search = await api(dbPath(`/metadata?q=${encodeURIComponent(q)}`));
      } catch (error) {
        meta.search = null;
        showError($('#dictErr'), error);
      }
      renderTree();
    }, 300);
  });
  $$('#treeF button').forEach(btn => btn.addEventListener('click', () => {
    meta.filter = btn.dataset.f;
    $$('#treeF button').forEach(b => b.classList.toggle('on', b === btn));
    renderTree();
  }));
  $$('#dictMode button').forEach(btn => btn.addEventListener('click', () => {
    if (!setup.ed || !setup.ed.editable) return;
    if (btn.dataset.mode === 'all' && setup.ed.mode !== 'all') {
      askConfirm('Маскировать все справочники?', 'Список выбранных источников будет заменён одним источником «*» при сохранении. В этом режиме маскируются строковые реквизиты справочников, для которых есть правило «Скрыть» по пути.', () => {
        setup.ed.mode = 'all';
        renderDict();
      });
    } else {
      setup.ed.mode = btn.dataset.mode;
      if (setup.ed.mode === 'part') setup.ed.sources = setup.ed.sources.filter(s => s.source_path !== '*');
      renderDict();
    }
  }));
  $('#dictAdd').addEventListener('click', () => {
    hideNote('#dictErr');
    const sourcePath = $('#dictPath').value.trim();
    const category = $('#dictCat').value.trim();
    const reason = $('#dictReasonDefault').value.trim();
    if (!sourcePath || !category || !reason) {
      showError($('#dictErr'), { message: 'Заполните путь, категорию и обоснование для новых источников.' });
      return;
    }
    if (selCovered(sourcePath)) {
      showError($('#dictErr'), { message: 'Такой источник уже есть в словаре.' });
      return;
    }
    if (setup.ed.mode === 'all') setup.ed.mode = 'part';
    setup.ed.sources.push({ source_path: sourcePath, category, filter_ast: null, reason, in_manifest: null });
    if (!$('#dictCatDefault').value.trim()) $('#dictCatDefault').value = category;
    $('#dictPath').value = '';
    $('#dictCat').value = '';
    renderDict();
    openSource(sourcePath);
  });
  $('#dictSave').addEventListener('click', async () => {
    if (!setup.ed || !setup.ed.editable) return;
    hideNote('#dictErr');
    const sources = setup.ed.mode === 'all'
      ? [{ source_path: '*', category: $('#dictCatDefault').value.trim() || 'all', reason: $('#dictReasonDefault').value.trim() || 'Все справочники' }]
      : setup.ed.sources.map(sourceOut);
    if (sources.length > 100) {
      showError($('#dictErr'), { message: `Выбрано ${sources.length} источников — лимит настройки 100.` });
      return;
    }
    const bad = sources.find(s => !s.category || !s.reason);
    if (bad) {
      showError($('#dictErr'), { message: `У источника ${bad.source_path} не заполнена категория или обоснование — откройте его в списке справа.` });
      return;
    }
    try {
      await putDraftArea('dictionary', { mode: setup.ed.mode, sources });
      setup.savedDict = dictSnapshot();
      // Флаги in_manifest и нормализованные поля — из свежего черновика.
      setup.draft = await api(dbPath('/setup/draft'));
      buildEditorModel();
      renderDict();
      renderRules();
    } catch (error) {
      if (error.code === 'DRAFT_CHANGED') draftConflict(error);
      else if (error.code === 'SETUP_INVALID' && error.details) issuesList($('#dictErr'), 'Словарь не сохранён:', error.details.errors);
      else showError($('#dictErr'), error);
    }
  });
  $('#dictReasonDefault').value = 'Выбрано администратором в дереве метаданных';

  // ---------- Источник: категория, конструктор условий, обоснование ----------
  const srcEdit = { path: null, model: null, fields: [] };
  const COND_OPS = [['eq', 'равно'], ['ne', 'не равно'], ['in', 'одно из']];
  const newGroup = () => ({ type: 'group', op: 'and', not: false, items: [] });
  // filter_ast → модель конструктора: группы and/or с флагом «Не», условия eq/ne/in.
  const astToModel = ast => {
    const root = newGroup();
    if (!ast) return root;
    const conv = node => {
      if (!node || typeof node !== 'object') return null;
      if (node.op === 'and' || node.op === 'or') {
        return { type: 'group', op: node.op, not: false, items: (node.args || []).map(conv).filter(Boolean) };
      }
      if (node.op === 'not') {
        const inner = conv(node.arg);
        if (!inner) return null;
        if (inner.type === 'group') { inner.not = !inner.not; return inner; }
        return { type: 'group', op: 'and', not: true, items: [inner] };
      }
      if (node.op === 'eq' || node.op === 'ne') return { type: 'cond', field: node.field, op: node.op, value: node.value };
      if (node.op === 'in') return { type: 'cond', field: node.field, op: 'in', value: node.values || [] };
      return null;
    };
    const top = conv(ast);
    if (!top) return root;
    if (top.type === 'group') return top;
    root.items.push(top);
    return root;
  };
  const modelToAst = g => {
    const args = g.items.map(item => (item.type === 'group'
      ? modelToAst(item)
      : item.op === 'in'
        ? { op: 'in', field: item.field, values: Array.isArray(item.value) ? item.value : [] }
        : { op: item.op, field: item.field, value: item.value })).filter(Boolean);
    if (!args.length) return null;
    const node = args.length === 1 && !g.not ? args[0] : (args.length === 1 ? args[0] : { op: g.op, args });
    return g.not ? { op: 'not', arg: node } : node;
  };
  const fieldInfo = name => srcEdit.fields.find(f => f.name === name) || null;
  const isBoolField = name => /булево|boolean/i.test((fieldInfo(name) || {}).field_type || '');
  const isNumField = name => /^число|number/i.test((fieldInfo(name) || {}).field_type || '');
  const scalarText = v => (v === true ? 'Истина' : v === false ? 'Ложь' : v === null || v === undefined ? '' : String(v));
  const parseScalar = (text, field) => {
    const t = String(text).trim();
    if (isBoolField(field) || /^(истина|ложь|true|false)$/i.test(t)) {
      if (/^(истина|true)$/i.test(t)) return true;
      if (/^(ложь|false)$/i.test(t)) return false;
    }
    if (isNumField(field) && t !== '' && !Number.isNaN(Number(t.replace(',', '.')))) return Number(t.replace(',', '.'));
    return t;
  };
  const condPhraseText = g => {
    const part = item => {
      if (item.type === 'group') return `(${condPhraseText(item)})`;
      const op = (COND_OPS.find(o => o[0] === item.op) || [, item.op])[1];
      const val = item.op === 'in'
        ? `(${(Array.isArray(item.value) ? item.value : []).map(scalarText).join(', ')})`
        : scalarText(item.value);
      return `${item.field || '?'} ${op === 'равно' ? '=' : op === 'не равно' ? '≠' : op} ${val}`;
    };
    if (!g.items.length) return 'все строки';
    const text = g.items.map(part).join(g.op === 'and' ? ' и ' : ' или ');
    return g.not ? `НЕ (${text})` : text;
  };
  const condErrors = g => {
    const errs = [];
    const walk = (grp, depth) => {
      if (depth > 15) errs.push('Слишком глубокая вложенность групп.');
      if (grp.items.length > 32) errs.push('В группе не больше 32 условий.');
      grp.items.forEach(item => {
        if (item.type === 'group') { if (!item.items.length) errs.push('Пустая группа — добавьте условие или удалите группу.'); walk(item, depth + 1); return; }
        if (!item.field) errs.push('Поле не выбрано.');
        else if (!/^[_\p{L}][_\p{L}\p{N}]*$/u.test(item.field)) errs.push(`Имя поля «${item.field}» недопустимо.`);
        else if (srcEdit.fields.length && !fieldInfo(item.field)) errs.push(`Поле «${item.field}» не найдено в метаданных.`);
        if (item.op === 'in' ? !(item.value || []).length : (item.value === '' || item.value === undefined)) errs.push(`Значение не указано${item.field ? ` (${item.field})` : ''}.`);
      });
    };
    walk(g, 0);
    return [...new Set(errs)];
  };

  const renderCond = () => {
    const box = $('#condBuilder');
    box.replaceChildren();
    const editable = setup.ed && setup.ed.editable;
    const groupView = (g, parent) => {
      const wrap = el('div', 'cb-g');
      const head = el('div', 'row');
      const opSel = el('select', 'input sm');
      [['and', 'Все условия (И)'], ['or', 'Любое из (ИЛИ)']].forEach(([v, t]) => { const o = el('option', '', t); o.value = v; opSel.append(o); });
      opSel.value = g.op;
      opSel.disabled = !editable;
      opSel.addEventListener('change', () => { g.op = opSel.value; renderCond(); });
      const notLbl = el('label', 'small row');
      const notCb = document.createElement('input');
      notCb.type = 'checkbox';
      notCb.checked = g.not;
      notCb.disabled = !editable;
      notCb.addEventListener('change', () => { g.not = notCb.checked; renderCond(); });
      notLbl.append(notCb, document.createTextNode(' Не'));
      head.append(opSel, notLbl);
      if (parent) {
        const rmG = el('button', 'btn sm ghost icon', '×');
        rmG.type = 'button';
        rmG.title = 'Удалить группу';
        rmG.disabled = !editable;
        rmG.addEventListener('click', () => { parent.items.splice(parent.items.indexOf(g), 1); renderCond(); });
        head.append(rmG);
      }
      wrap.append(head);
      g.items.forEach(item => {
        if (item.type === 'group') { wrap.append(groupView(item, g)); return; }
        const r = el('div', 'cb-r');
        const fSel = el('select', 'input sm');
        const names = srcEdit.fields.map(f => f.name);
        if (item.field && !names.includes(item.field)) names.unshift(item.field);
        if (!item.field) { const o = el('option', '', '— поле —'); o.value = ''; fSel.append(o); }
        names.forEach(n => {
          const o = el('option', '', n);
          o.value = n;
          const f = fieldInfo(n);
          if (!f && srcEdit.fields.length) o.textContent = `${n} (нет в метаданных)`;
          fSel.append(o);
        });
        fSel.value = item.field || '';
        fSel.disabled = !editable;
        fSel.addEventListener('change', () => { item.field = fSel.value; renderCond(); });
        const oSel = el('select', 'input sm');
        COND_OPS.forEach(([v, t]) => { const o = el('option', '', t); o.value = v; oSel.append(o); });
        oSel.value = item.op;
        oSel.disabled = !editable;
        oSel.addEventListener('change', () => {
          const was = item.op;
          item.op = oSel.value;
          if (item.op === 'in' && was !== 'in') item.value = item.value === '' || item.value === undefined ? [] : [item.value];
          if (item.op !== 'in' && was === 'in') item.value = (item.value || [])[0] ?? '';
          renderCond();
        });
        let vIn;
        if (item.op !== 'in' && isBoolField(item.field)) {
          vIn = el('select', 'input sm');
          [['', '—'], ['true', 'Истина'], ['false', 'Ложь']].forEach(([v, t]) => { const o = el('option', '', t); o.value = v; vIn.append(o); });
          vIn.value = item.value === true ? 'true' : item.value === false ? 'false' : '';
          vIn.addEventListener('change', () => { item.value = vIn.value === '' ? '' : vIn.value === 'true'; renderCond(); });
        } else {
          vIn = el('input', 'input sm');
          vIn.placeholder = item.op === 'in' ? 'значения через запятую' : 'значение';
          vIn.value = item.op === 'in' ? (item.value || []).map(scalarText).join(', ') : scalarText(item.value);
          vIn.addEventListener('change', () => {
            item.value = item.op === 'in'
              ? vIn.value.split(',').map(x => x.trim()).filter(Boolean).map(x => parseScalar(x, item.field))
              : parseScalar(vIn.value, item.field);
            renderCond();
          });
        }
        vIn.disabled = !editable;
        const rm = el('button', 'btn sm ghost icon', '×');
        rm.type = 'button';
        rm.title = 'Удалить условие';
        rm.disabled = !editable;
        rm.addEventListener('click', () => { g.items.splice(g.items.indexOf(item), 1); renderCond(); });
        r.append(fSel, oSel, vIn, rm);
        wrap.append(r);
      });
      if (editable) {
        const acts = el('div', 'row');
        const addC = el('button', 'btn sm ghost', '+ Условие');
        addC.type = 'button';
        addC.addEventListener('click', () => { g.items.push({ type: 'cond', field: '', op: 'eq', value: '' }); renderCond(); });
        const addG = el('button', 'btn sm ghost', '+ Группа');
        addG.type = 'button';
        addG.addEventListener('click', () => { const ng = newGroup(); ng.items.push({ type: 'cond', field: '', op: 'eq', value: '' }); g.items.push(ng); renderCond(); });
        acts.append(addC, addG);
        wrap.append(acts);
      }
      return wrap;
    };
    box.append(groupView(srcEdit.model, null));
    const phrase = $('#condPhrase');
    phrase.replaceChildren(document.createTextNode(srcEdit.model.items.length ? 'Брать значения, где ' : 'Условия нет — '), el('b', '', condPhraseText(srcEdit.model)));
    $('#condJson').textContent = JSON.stringify(modelToAst(srcEdit.model), null, 1);
    const errs = condErrors(srcEdit.model);
    $('#condErr').textContent = errs.join(' ');
    $('#condErr').hidden = !errs.length;
  };

  const openSource = async path => {
    const src = eds().find(s => s.source_path === path);
    if (!src) return;
    srcEdit.path = path;
    srcEdit.model = astToModel(src.filter_ast);
    srcEdit.fields = [];
    renderSelPanel();
    renderSrcEditor();
    const object = path.includes('.') ? path.slice(0, path.lastIndexOf('.')) : path;
    try {
      const res = await api(dbPath(`/metadata?fields_of=${encodeURIComponent(object)}`));
      if (srcEdit.path !== path) return;
      srcEdit.fields = (res.fields || []).filter(f => !f.password_mode);
      renderCond();
    } catch (_) { /* поля для выбора — удобство; без них конструктор работает с вводом */ }
  };
  const renderSrcEditor = () => {
    const src = srcEdit.path ? eds().find(s => s.source_path === srcEdit.path) : null;
    $('#srcEditor').hidden = !src;
    $('#srcListPane').hidden = !!src;
    if (!src) { srcEdit.path = null; return; }
    const editable = setup.ed.editable;
    $('#srcPath').textContent = src.source_path;
    $('#srcCat').value = src.category;
    $('#srcReason').value = src.reason || '';
    $('#srcCat').disabled = !editable;
    $('#srcReason').disabled = !editable;
    $('#srcApply').hidden = !editable;
    $('#srcRemove').hidden = !editable;
    renderCond();
  };
  $('#srcClose').addEventListener('click', () => { srcEdit.path = null; renderDict(); });
  $('#srcApply').addEventListener('click', () => {
    const src = eds().find(s => s.source_path === srcEdit.path);
    if (!src) return;
    const errs = condErrors(srcEdit.model);
    if (errs.length) { $('#condErr').hidden = false; return; }
    if (!$('#srcCat').value.trim() || !$('#srcReason').value.trim()) {
      showError($('#condErr'), { message: 'Категория и обоснование обязательны.' });
      return;
    }
    src.category = $('#srcCat').value.trim();
    src.reason = $('#srcReason').value.trim();
    src.filter_ast = modelToAst(srcEdit.model);
    srcEdit.path = null;
    renderDict();
  });
  $('#srcRemove').addEventListener('click', () => {
    setup.ed.sources = eds().filter(s => s.source_path !== srcEdit.path);
    srcEdit.path = null;
    renderDict();
  });

  // ---------- Правила ----------
  let rulesFilter = 'all';
  const activeRuleSigs = () => new Set(setup.activeRules.map(ruleSig));
  const rulesDirty = () => setup.ed && setup.ed.editable && rulesSnapshot() !== setup.savedRules;
  const renderRules = () => {
    if (!setup.ed) return;
    const editable = setup.ed.editable;
    const body = $('#rulesBody');
    body.replaceChildren();
    // Встроенные правила — видимы, но не редактируются.
    const builtin = body.insertRow();
    builtin.className = 'builtin';
    builtin.append(el('td', '', '—'), el('td', '', 'Имя поля / вид значения'), el('td', 'mono', 'пароль, token, api_key, secret, ФИО…'));
    const bt = el('td');
    bt.append(el('span', 'tag err', 'Секрет'), document.createTextNode(' '), el('span', 'tag acc', 'Скрыть'));
    builtin.append(bt, el('td', 'hide-sm', 'secret · fio'), el('td', 'hide-sm', '—'), el('td', 'muted', 'Встроенное: маскируется всегда, нельзя отключить'), el('td'));
    const act = activeRuleSigs();
    const rules = setup.ed.rules;
    let shown = 0;
    rules.forEach((rule, index) => {
      const changed = editable && !act.has(ruleSig(rule));
      if (rulesFilter === 'chg' && !changed) return;
      shown += 1;
      const tr = body.insertRow();
      tr.dataset.ruleId = rule.rule_id || '';
      if (rule.action === 'keep') tr.classList.add('weakrow');
      if (rule.enabled === false) tr.classList.add('offrow');
      const onTd = el('td');
      const on = document.createElement('input');
      on.type = 'checkbox';
      on.checked = rule.enabled !== false;
      on.disabled = !editable;
      on.title = on.checked ? 'Включено' : 'Выключено — правило не действует';
      on.addEventListener('change', () => { rule.enabled = on.checked; renderRules(); });
      onTd.append(on);
      tr.append(onTd, el('td', '', SELECTOR_LABEL[rule.selector] || rule.selector));
      const val = el('td', 'mono brk', rule.value);
      tr.append(val);
      const [cls, label] = ACTION_TAG[rule.action] || ['mut', rule.action];
      const actTd = el('td');
      actTd.append(el('span', `tag ${cls}`, label));
      if (changed) { actTd.append(document.createTextNode(' ')); const d = el('i', 'chgdot'); d.title = 'Изменено в черновике'; actTd.append(d); }
      tr.append(actTd, el('td', 'hide-sm', rule.category), el('td', 'hide-sm', String(rule.priority ?? 0)));
      let reason = rule.reason || '';
      if (rule.selector === 'regex' && rule.tests) {
        const n = (rule.tests.match || []).length + (rule.tests.no_match || []).length;
        if (n) reason += `${reason ? ' · ' : ''}тест-примеров ${n}`;
      }
      tr.append(el('td', 'small', reason || '—'));
      const acts = el('td', 'acts');
      if (editable) {
        const ed = el('button', 'btn sm', 'Изменить');
        ed.type = 'button';
        ed.addEventListener('click', () => openRuleDialog(index));
        const rm = el('button', 'btn sm ghost icon', '×');
        rm.type = 'button';
        rm.title = 'Удалить правило из черновика';
        rm.addEventListener('click', () => { rules.splice(index, 1); renderRules(); });
        acts.append(ed, rm);
      }
      tr.append(acts);
    });
    if (editable) {
      // Удалённые из действующей версии правила — видимы в «Только изменённые».
      const cur = new Set(rules.map(ruleSig));
      setup.activeRules.filter(r => !cur.has(ruleSig(r)) && !rules.some(x => ruleKey(x) === ruleKey(r))).forEach(r => {
        if (rulesFilter !== 'chg') return;
        shown += 1;
        const tr = body.insertRow();
        tr.className = 'offrow';
        tr.append(el('td', '', '—'), el('td', '', SELECTOR_LABEL[r.selector] || r.selector), el('td', 'mono brk del', r.value));
        const [cls, label] = ACTION_TAG[r.action] || ['mut', r.action];
        const t = el('td');
        t.append(el('span', `tag ${cls} plain`, label));
        tr.append(t, el('td', 'hide-sm', r.category), el('td', 'hide-sm', String(r.priority)), el('td', 'small', 'удалено в черновике'), el('td'));
      });
    }
    if (!shown && rulesFilter === 'chg') {
      const td = body.insertRow().insertCell();
      td.colSpan = 8;
      td.className = 'empty';
      td.textContent = 'Правила черновика не отличаются от действующей версии';
    } else if (!rules.length && rulesFilter === 'all') {
      const td = body.insertRow().insertCell();
      td.colSpan = 8;
      td.className = 'empty';
      td.textContent = 'Своих правил нет — действуют только встроенные';
    }
    $('#ruleAdd').hidden = !editable;
    $('#rulesSave').hidden = !editable;
    $('#rulesSave').disabled = !rulesDirty();
    $('#rulesSaveHint').textContent = rulesDirty() ? 'Есть несохранённые изменения правил' : '';
    refreshCategories();
  };
  $$('#rulesPill button').forEach(btn => btn.addEventListener('click', () => {
    rulesFilter = btn.dataset.f;
    $$('#rulesPill button').forEach(b => b.classList.toggle('on', b === btn));
    renderRules();
  }));
  $('#rulesSave').addEventListener('click', async () => {
    hideNote('#rulesErr');
    try {
      await putDraftArea('rules', { rules: setup.ed.rules.map(ruleOut) });
      setup.draft = await api(dbPath('/setup/draft'));
      buildEditorModel();
      renderRules();
      renderDict();
    } catch (error) {
      if (error.code === 'DRAFT_CHANGED') draftConflict(error);
      else if (error.code === 'SETUP_INVALID' && error.details) issuesList($('#rulesErr'), 'Правила не сохранены:', error.details.errors);
      else showError($('#rulesErr'), error);
    }
  });

  // Диалог правила: тип селектора, значение, тест-примеры шаблона (живая
  // проверка браузерным RegExp — окончательная проверка на сервере).
  const ruleDlg = { index: null, action: 'mask' };
  const SEL_HINT = {
    source_path: 'Полный путь реквизита: Справочник.Контрагенты.ИНН. «*текст*» — путь содержит текст; «*» — все. Другие звёздочки не поддерживаются.',
    name: 'Имя поля в ответе: ИНН. «*текст*» — имя содержит текст (без учёта регистра).',
    type: 'Тип значения поля из метаданных. «*текст*» — тип содержит текст.',
    dictionary: 'Категория источника словаря (например, inn): задаёт действие для значений этой категории.',
    regex: 'Регулярное выражение по значению. Для «Скрыть»/«Секрет» нужен хотя бы один пример, который должен совпасть.',
  };
  const liveTests = () => {
    const regex = $('#ruleSel').value === 'regex';
    $('#ruleTestsField').hidden = !regex;
    $('#ruleSelHint').textContent = SEL_HINT[$('#ruleSel').value] || '';
    $('#ruleValueLabel').textContent = regex ? 'Шаблон' : 'Значение';
    if (!regex) return;
    let re = null;
    try { re = new RegExp($('#ruleValue').value, 'u'); } catch (_) { re = null; }
    const mark = (tagId, input, want) => {
      const tag = $(tagId);
      const v = input.value;
      if (!v) { tag.className = 'tag plain mut'; tag.textContent = want ? 'совпадает' : 'не совпадает'; return; }
      if (!re) { tag.className = 'tag err plain'; tag.textContent = 'шаблон с ошибкой'; return; }
      const ok = re.test(v) === want;
      tag.className = `tag ${ok ? 'ok' : 'err'} plain`;
      tag.textContent = `${want ? 'совпадает' : 'не совпадает'} ${ok ? '✓' : '✗'}`;
    };
    mark('#tstMatchTag', $('#tstMatch'), true);
    mark('#tstNoTag', $('#tstNo'), false);
  };
  const setRuleAction = a => {
    ruleDlg.action = a;
    $$('#ruleActSeg button').forEach(b => b.classList.toggle('on', b.dataset.a === a));
    $('#ruleWeakNote').hidden = a !== 'keep';
    $('#ruleSecretNote').hidden = a !== 'secret';
  };
  $$('#ruleActSeg button').forEach(b => b.addEventListener('click', () => setRuleAction(b.dataset.a)));
  ['#ruleSel', '#ruleValue', '#tstMatch', '#tstNo'].forEach(id => $(id).addEventListener('input', liveTests));
  $('#ruleSel').addEventListener('change', liveTests);
  const openRuleDialog = index => {
    ruleDlg.index = index;
    const r = index === null ? null : setup.ed.rules[index];
    $('#ruleDlgTitle').textContent = r ? 'Правило' : 'Новое правило';
    $('#ruleOk').textContent = r ? 'Применить' : 'Добавить в черновик';
    hideNote('#ruleDlgErr');
    $('#ruleSel').value = r ? r.selector : 'name';
    $('#ruleValue').value = r ? r.value : '';
    $('#ruleCat').value = r ? r.category : '';
    $('#rulePrio').value = r ? String(r.priority ?? 0) : '0';
    $('#ruleReason').value = r ? r.reason || '' : '';
    $('#ruleEnabled').checked = r ? r.enabled !== false : true;
    $('#tstMatch').value = r && r.tests && r.tests.match ? r.tests.match[0] || '' : '';
    $('#tstNo').value = r && r.tests && r.tests.no_match ? r.tests.no_match[0] || '' : '';
    setRuleAction(r ? r.action : 'mask');
    liveTests();
    openOverlay('dlgRule');
    $('#ruleValue').focus();
  };
  $('#ruleAdd').addEventListener('click', () => openRuleDialog(null));
  $('#ruleCancel').addEventListener('click', closeOverlays);
  $('#ruleOk').addEventListener('click', () => {
    const sel = $('#ruleSel').value;
    const value = $('#ruleValue').value.trim();
    const errs = [];
    if (!value) errs.push('Укажите значение.');
    if (sel !== 'regex' && value.includes('*') && value !== '*' && !/^\*[^*]+\*$/.test(value)) {
      errs.push('Звёздочка допустима только в формах «*» и «*текст*».');
    }
    if (sel === 'regex') {
      try { new RegExp(value, 'u'); } catch (e) { errs.push(`Шаблон не компилируется: ${e.message}`); }
      if (ruleDlg.action !== 'keep' && !$('#tstMatch').value) errs.push('Для шаблона «Скрыть»/«Секрет» нужен пример, который должен совпасть.');
    }
    if (!$('#ruleCat').value.trim()) errs.push('Укажите категорию.');
    if (!$('#ruleReason').value.trim()) errs.push('Укажите обоснование.');
    const prio = Number($('#rulePrio').value);
    if (!Number.isInteger(prio)) errs.push('Приоритет — целое число.');
    const rule = {
      selector: sel, value, action: ruleDlg.action, category: $('#ruleCat').value.trim(),
      priority: prio, enabled: $('#ruleEnabled').checked, reason: $('#ruleReason').value.trim(),
      tests: sel === 'regex' ? {
        match: $('#tstMatch').value ? [$('#tstMatch').value] : [],
        no_match: $('#tstNo').value ? [$('#tstNo').value] : [],
      } : null,
    };
    const dup = setup.ed.rules.findIndex((x, i) => i !== ruleDlg.index && ruleKey(x) === ruleKey(rule) && x.action === rule.action);
    if (dup >= 0) errs.push('Такое правило уже есть в черновике.');
    if (errs.length) { showError($('#ruleDlgErr'), { message: errs.join(' ') }); return; }
    if (ruleDlg.index === null) setup.ed.rules.push(rule);
    else setup.ed.rules[ruleDlg.index] = { ...setup.ed.rules[ruleDlg.index], ...rule };
    closeOverlays();
    renderRules();
  });

  // ---------- Версии ----------
  const renderVersions = () => {
    const body = $('#versionsBody');
    body.replaceChildren();
    hideNote('#versionsErr');
    const list = [...setup.policies].sort((a, b) => b.version - a.version);
    if (!list.length) {
      const td = body.insertRow().insertCell();
      td.colSpan = 4;
      td.className = 'empty';
      td.textContent = 'Версий пока нет';
      return;
    }
    const STATE = { draft: ['mut', 'Черновик'], active: ['ok', 'Действует'], retired: ['mut plain', 'Архив'] };
    list.forEach(p => {
      const tr = body.insertRow();
      tr.append(el('td', '', ''));
      tr.lastChild.append(el('b', '', String(p.version)));
      const [cls, label] = STATE[p.status] || ['mut', p.status];
      const st = el('td');
      st.append(el('span', `tag ${cls}`, label));
      const who = p.created_by ? (p.created_by.login || ({ agent: 'агент', service: 'сервис', human: 'администратор' })[p.created_by.kind] || '—') : '—';
      const ORIGIN = { import: 'из файла', manual: 'вручную', rollback: 'откат', migration: 'перенос' };
      tr.append(st, el('td', 'small', `${ORIGIN[p.origin] || p.origin || ''} · ${who} · ${fmtTime(p.activated_at || p.created_at)}`));
      const acts = el('td', 'acts');
      const btn = (text, cls2, fn) => { const b = el('button', `btn sm${cls2 ? ` ${cls2}` : ''}`, text); b.type = 'button'; b.addEventListener('click', fn); acts.append(b); };
      if (p.status !== 'active' && activeVersion()) btn('Сравнить', '', () => openWizard('compare', 2, p.version));
      btn('Экспорт', '', () => openExport(p.status === 'draft' ? 'draft' : p.status === 'active' ? 'active' : String(p.version)));
      if (p.status === 'draft') btn('Активировать…', 'primary', () => openWizard('draft', 2));
      if (p.status === 'retired') btn('Вернуть эту версию', '', () => openRollback(p.version));
      tr.append(acts);
    });
  };
  const rb = { version: null };
  const openRollback = version => {
    rb.version = version;
    const active = activeVersion();
    $('#rbTitle').textContent = `Вернуть версию ${version}`;
    $('#rbText').textContent = `Будет создан черновик — копия версии ${version}. Он станет действующим только после сравнения и подтверждения${active ? `; версия ${active.version} уйдёт в архив` : ''}. Откат может ослабить настройку — такие изменения подтверждаются поштучно.${setup.draft ? ` Текущий черновик ${setup.draft.version} будет заменён.` : ''}`;
    $('#rbCard').hidden = false;
  };
  $('#rbCancel').addEventListener('click', () => { $('#rbCard').hidden = true; });
  $('#rbGo').addEventListener('click', async () => {
    try {
      await api(dbPath('/setup/rollback'), { method: 'POST', body: JSON.stringify({ version: rb.version, replace_draft: !!setup.draft }) });
      $('#rbCard').hidden = true;
      await loadDatabases();
      await loadSetup(dbs.current);
      openWizard('draft', 2);
    } catch (error) {
      showError($('#versionsErr'), error.code === 'VERSION_IS_ACTIVE' ? { message: 'Эта версия уже действует.' } : error);
    }
  });

  // ---------- Мастер: файл → сравнение → сухой прогон → активация ----------
  const wiz = {
    mode: 'import', step: 1, to: 'draft', diff: null, draftVersion: null, draftHash: null,
    confirmed: new Set(), accepted: new Set(), excluded: new Set(), dry: null, showAll: false,
    imported: null, activated: false,
  };
  const wizGo = step => {
    wiz.step = step;
    $$('.wz').forEach(p => p.classList.toggle('on', p.id === `wz${step}`));
    $$('#wiz li').forEach(li => {
      const n = Number(li.dataset.w);
      li.classList.toggle('on', n === step);
      li.classList.toggle('done', n < step);
      li.classList.toggle('off', (wiz.mode !== 'import' && n === 1) || (wiz.mode === 'compare' && n !== 2) || (n > 1 && !wiz.draftVersion && wiz.mode === 'import'));
    });
    if (step === 2) loadDiff();
    if (step === 3) renderDry();
    if (step === 4) renderActivate();
  };
  $$('#wiz li').forEach(li => li.addEventListener('click', () => {
    if (li.classList.contains('off')) return;
    wizGo(Number(li.dataset.w));
  }));
  const openWizard = (mode, step, toVersion) => {
    wiz.mode = mode;
    wiz.to = mode === 'compare' ? String(toVersion) : 'draft';
    wiz.diff = null;
    wiz.dry = null;
    wiz.activated = false;
    wiz.confirmed = new Set();
    wiz.accepted = null; // null = «ещё не видели diff» → принять все по умолчанию
    wiz.excluded = new Set();
    //++agent TASK-225 [26.09.2026] H.6: отказанные удаления инструментов
    wiz.declined = new Set();
    //++agent TASK-225
    wiz.draftVersion = mode === 'import' ? null : (setup.draft ? setup.draft.version : null);
    if (mode === 'import') {
      wiz.imported = null;
      $('#importCard').hidden = true;
      hideNote('#importErr');
      $('#wizTo2').disabled = true;
      $('#importFile').value = '';
    }
    $('#setupEmpty').hidden = true;
    $('#setupEditor').hidden = true;
    $('#setupWizard').hidden = false;
    hideNote('#setupOk');
    wizGo(step);
    $('#setupWizard').scrollIntoView({ block: 'start' });
  };
  const closeWizard = () => {
    $('#setupWizard').hidden = true;
    renderSetup();
  };
  $('#setupImportBtn').addEventListener('click', () => openWizard('import', 1));
  $('#emptyImport').addEventListener('click', () => openWizard('import', 1));
  $('#wizCancel').addEventListener('click', closeWizard);
  $('#wizTo2').addEventListener('click', () => wizGo(2));
  $('#wiz2Back').addEventListener('click', () => (wiz.mode === 'import' ? wizGo(1) : closeWizard()));
  $('#wizTo3').addEventListener('click', () => wizGo(3));
  $('#wiz3Back').addEventListener('click', () => wizGo(2));
  $('#wizTo4').addEventListener('click', () => wizGo(4));
  $('#wiz4Back').addEventListener('click', () => (wiz.activated ? closeWizard() : wizGo(3)));

  // Шаг 1: файл.
  const drop = $('#dropZone');
  drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', e => {
    e.preventDefault();
    drop.classList.remove('over');
    const file = e.dataTransfer && e.dataTransfer.files[0];
    if (file) importFile(file);
  });
  $('#importFile').addEventListener('change', () => {
    const file = $('#importFile').files[0];
    // Сброс значения: повторный выбор того же файла снова даст change.
    $('#importFile').value = '';
    if (file) importFile(file);
  });
  const importFile = async (file, replace) => {
    hideNote('#importErr');
    $('#importCard').hidden = true;
    $('#wizTo2').disabled = true;
    if (file.size > 1_048_576) {
      showError($('#importErr'), { message: `Файл ${file.name} больше 1 МБ — такой файл сервис не примет.` });
      return;
    }
    const buffer = await file.arrayBuffer();
    let local = null;
    try { local = JSON.parse(new TextDecoder().decode(buffer)); } catch (_) { local = null; }
    if (!local || typeof local !== 'object') {
      showError($('#importErr'), { message: 'Это не файл настройки маскирования: содержимое не является JSON-объектом.' });
      return;
    }
    if (!local.schema) {
      showError($('#importErr'), { message: 'Это не файл настройки маскирования (нет поля schema).' });
      return;
    }
    // Имя файла в заголовке — только ASCII (ограничение HTTP-заголовков).
    const asciiName = /^[\x20-\x7e]{1,255}$/.test(file.name) ? file.name : encodeURIComponent(file.name).slice(0, 255);
    try {
      const res = await api(dbPath(`/setup/imports?replace_draft=${replace ? 1 : 0}`), {
        method: 'POST',
        headers: { 'X-File-Name': asciiName },
        body: buffer,
      });
      wiz.imported = { res, file, local };
      wiz.draftVersion = res.draft_version;
      wiz.draftHash = res.draft_hash;
      renderImportCard();
      $('#wizTo2').disabled = false;
      await loadDatabases();
      await loadSetup(dbs.current);
      $('#setupEditor').hidden = true;
      $('#setupWizard').hidden = false;
    } catch (error) {
      if (error.code === 'DRAFT_EXISTS') {
        const d = error.details || {};
        askConfirm('Заменить черновик?', `У базы уже есть черновик ${d.draft_version || ''}. Импорт заменит его — несохранённые в нём изменения будут потеряны.`, () => importFile(file, true));
        $('#confirmYes').textContent = 'Заменить черновик';
        return;
      }
      if (error.code === 'SETUP_INVALID' && error.details) {
        const errs = error.details.errors || [];
        const unsupported = errs.find(x => x.code === 'SETUP_SCHEMA_UNSUPPORTED');
        if (unsupported) {
          showError($('#importErr'), { message: `Версия схемы ${local.schema} не поддерживается этим сервисом (поддерживается masking-setup/v1). Обновите сервис или попросите агента выгрузить в v1.` });
          return;
        }
        issuesList($('#importErr'), `Файл не принят, найдено ${errs.length} ${ruPlural(errs.length, 'ошибка', 'ошибки', 'ошибок')}:`, errs, error.details.truncated);
        return;
      }
      if (error.status === 413) {
        showError($('#importErr'), { message: 'Файл больше 1 МБ — сервис его не принял.' });
        return;
      }
      showError($('#importErr'), error);
    }
  };
  const renderImportCard = () => {
    const { res, file, local } = wiz.imported;
    $('#impName').textContent = file.name;
    const kv = $('#impKv');
    kv.replaceChildren();
    const add = (k, v) => { kv.append(el('dt', '', k)); const dd = el('dd'); if (typeof v === 'string') dd.textContent = v; else dd.append(v); kv.append(dd); };
    add('Размер', fmtBytes(res.size_bytes));
    const sha = el('span', 'mono', shortHash(res.sha256));
    sha.title = res.sha256;
    const shaWrap = el('span');
    shaWrap.append(sha, copyButton(res.sha256, 'копировать'));
    add('sha256', shaWrap);
    add('Схема', `${res.schema} ✓`);
    const gb = res.generated_by || {};
    const who = { agent: 'агент', human: 'человек', service: 'сервис' }[gb.kind] || gb.kind || '—';
    const created = [who, gb.name, gb.tool].filter(Boolean).join(' · ');
    const when = local && local.generated_at ? ` · ${new Date(local.generated_at).toLocaleString('ru-RU')}` : '';
    const hint = res.database_hint && (res.database_hint.label || res.database_hint.id);
    add('Создан', `${created}${when}${hint ? ` · база-источник ${hint}` : ''}`);
    if (gb.note) add('Примечание', gb.note);
    const c = res.counts || {};
    const regexTests = (local && Array.isArray(local.rules) ? local.rules : [])
      .reduce((n, r) => n + ((r.tests && r.tests.match) || []).length + ((r.tests && r.tests.no_match) || []).length, 0);
    add('Содержимое', `Словарь: ${c.sources} ${ruPlural(c.sources, 'источник', 'источника', 'источников')} · Правила: ${c.rules} · Тест-примеров шаблонов: ${regexTests}${regexTests ? ' (все прошли)' : ''}${c.tools ? ` · Инструменты: ${c.tools}` : ''}`);
    add('Черновик', `${res.draft_version} — создан из файла; до активации ничего не меняется`);
    const mm = $('#impMismatch');
    mm.hidden = !res.database_mismatch;
    if (res.database_mismatch) {
      mm.textContent = `Файл подготовлен для другой базы (${(res.database_hint && (res.database_hint.label || res.database_hint.id)) || 'неизвестно'}). Это нормально, если структура метаданных та же. Пути будут проверены по метаданным этой базы.`;
    }
    $('#importCard').hidden = false;
  };

  // Шаг 2: сравнение.
  const actionWord = a => (ACTION_TAG[a] || [, a || 'нет правила'])[1];
  const sideText = side => {
    if (!side) return 'нет';
    if (side.mode) return `режим «${(TOOL_MODE[side.mode] || [, side.mode])[1]}»`;
    const parts = [];
    if (side.action) parts.push(actionWord(side.action));
    if (side.source_path && !side.action) parts.push('в словаре');
    if (side.category) parts.push(`категория ${side.category}`);
    if (side.priority !== undefined && side.action) parts.push(`приоритет ${side.priority}`);
    if (side.enabled === false) parts.push('выключено');
    if (side.filter !== undefined || side.filter_ast !== undefined) {
      const f = side.filter !== undefined ? side.filter : side.filter_ast;
      parts.push(f ? `условие: ${condPhraseText(astToModel(f))}` : 'без условия');
    }
    return parts.join(', ') || 'есть';
  };
  const subjectText = ch => {
    const s = ch.subject || {};
    if (ch.area === 'tool') return `Инструмент ${s.tool || ''}`;
    if (ch.area === 'dictionary') return s.source_path || s.category || '';
    const sel = SELECTOR_LABEL[s.selector] || s.selector || '';
    return `${sel} ${s.value || s.key || ''}`.trim();
  };
  const loadDiff = async () => {
    const body = $('#cmpBody');
    body.replaceChildren(el('p', 'muted', 'Загружаем сравнение…'));
    body.firstChild.prepend(el('span', 'spin'), document.createTextNode(' '));
    $('#wizTo3').hidden = wiz.mode === 'compare';
    try {
      const diff = await api(dbPath(`/setup/diff?from=active&to=${encodeURIComponent(wiz.to)}`));
      wiz.diff = diff;
      if (wiz.to === 'draft') {
        wiz.draftVersion = diff.to_version;
        wiz.draftHash = diff.to_hash;
      }
      const sIds = diff.changes.filter(c => c.class === 'strengthening').map(c => c.id);
      if (wiz.accepted === null) wiz.accepted = new Set(sIds);
      else wiz.accepted = new Set([...wiz.accepted].filter(id => sIds.includes(id)));
      const wIds = new Set(diff.changes.filter(c => c.class === 'weakening').map(c => c.id));
      wiz.confirmed = new Set([...wiz.confirmed].filter(id => wIds.has(id)));
      const xIds = new Set(diff.warnings.filter(w => w.excludable).map(w => w.id));
      wiz.excluded = new Set([...wiz.excluded].filter(id => xIds.has(id)));
      //++agent TASK-225 [26.09.2026] H.6: declined держим только по
      // живым TOOL_REMOVED текущего diff.
      const rIds = new Set(toolRemovals().map(c => c.id));
      wiz.declined = new Set([...wiz.declined].filter(id => rIds.has(id)));
      //++agent TASK-225
      renderDiff();
    } catch (error) {
      body.replaceChildren();
      const n = el('div', 'note err');
      showError(n, error.code === 'NO_DRAFT' ? { message: 'У базы нет черновика — сравнивать нечего.' } : error);
      body.append(n);
    }
  };
  $$('#cmpPill button').forEach(btn => btn.addEventListener('click', () => {
    wiz.showAll = btn.dataset.f === 'all';
    $$('#cmpPill button').forEach(b => b.classList.toggle('on', b === btn));
    renderDiff();
  }));
  const KIND_TAG = {
    RULE_ADDED: 'Новое правило', RULE_REMOVED: 'Правило снято', RULE_UPDATED: 'Правило изменено',
    RULE_ACTION_CHANGED: 'Изменено действие', RULE_PATTERN_NARROWED: 'Шаблон сужен', RULE_PATTERN_WIDENED: 'Шаблон расширен',
    SOURCE_CHANGED: 'Источник изменён', SOURCE_UPDATED: 'Источник изменён', DICTIONARY_MODE_CHANGED: 'Режим словаря изменён',
    TOOL_ADDED: 'Инструмент добавлен', TOOL_REMOVED: 'Инструмент убран', TOOL_UPDATED: 'Инструмент изменён',
    TOOL_MODE_CHANGED: 'Режим инструмента изменён', TOOL_NOT_SEEN: 'Инструмент ещё не вызывался',
    DATABASE_MISMATCH: 'Файл для другой базы', DICTIONARY_LIMIT: 'Лимит словаря', MANIFEST_UNAVAILABLE: 'Метаданные не получены',
    MASKING_SOURCE_LARGE_VALUES: 'Крупный источник', PATH_NOT_IN_MANIFEST: 'Путь не найден в метаданных',
    REGEX_KEEP_NO_EFFECT: '«Не маскировать» по шаблону не действует', SECRET_ACTIVATION_BLOCKED: 'Секрет пока не применяется',
    SOURCE_LARGE: 'Крупный источник',
    KEEP_ADDED: 'Новое «Не маскировать»', KEEP_WIDENED: '«Не маскировать» расширено', MASK_REMOVED: 'Снято скрытие',
    SECRET_REMOVED: 'Снят секрет', SECRET_TO_MASK: 'Секрет → скрытие', MASK_TO_KEEP: 'Скрытие → не маскировать',
    SECRET_TO_KEEP: 'Секрет → не маскировать', PATTERN_NARROWED: 'Шаблон сужен', REGEX_REMOVED: 'Шаблон удалён',
    SOURCE_REMOVED: 'Источник словаря удалён', FILTER_NARROWED: 'Условие источника сужено',
    FILTER_CHANGED: 'Условие источника изменено — проверьте', DICTIONARY_CATEGORY_WEAKER: 'Категория словаря ослаблена',
    DICTIONARY_MODE_UNVERIFIABLE: 'Режим словаря не проверить', TOOL_NO_MASK: 'Инструмент без маскирования',
    SOURCE_ADDED: 'Новый источник словаря', FILTER_WIDENED: 'Условие источника расширено', MASK_ADDED: 'Новое правило',
    SECRET_ADDED: 'Новое правило', RULE_ADDED: 'Новое правило', MASK_TO_SECRET: 'Скрытие → секрет', KEEP_REMOVED: '«Не маскировать» снято',
    KEEP_TO_MASK: '«Не маскировать» → скрытие', KEEP_TO_SECRET: '«Не маскировать» → секрет', PATTERN_WIDENED: 'Шаблон расширен',
    KEEP_NARROWED: '«Не маскировать» сужено', TOOL_RESTRICTED: 'Инструмент ограничен', TOOL_ENABLED: 'Инструмент разрешён',
  };
  const changeRow = (ch, kind) => {
    const row = el('div', kind === 'flat' ? 'chg flat' : 'chg');
    const readOnly = wiz.mode === 'compare';
    const content = el('div', kind === 'flat' ? 'grow' : '');
    const tagText = KIND_TAG[ch.kind] || ch.kind;
    content.append(el('span', `tag ${ch.class === 'weakening' ? 'err' : ch.class === 'strengthening' ? 'ok' : 'mut'} plain`, tagText), document.createTextNode(' '));
    content.append(el('span', '', ch.label || subjectText(ch)));
    if (ch.before || ch.after) {
      const ba = el('div', 'ba');
      ba.append(el('span', 'was', sideText(ch.before)), document.createTextNode(' → '), el('span', 'now', sideText(ch.after)));
      content.append(ba);
    }
    const reason = (ch.after && ch.after.reason) || (ch.before && ch.before.reason);
    if (reason) content.append(el('div', 'why', `Обоснование: «${reason}»`));
    if (ch.kind === 'TOOL_NO_MASK' && ch.after && ch.after.name_looks_like_data) {
      content.append(el('div', 'why warnc', 'Имя инструмента похоже на чтение данных.'));
    }
    if (ch.class === 'weakening') {
      const lbl = el('label', 'cf');
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = wiz.confirmed.has(ch.id);
      cb.disabled = readOnly;
      cb.addEventListener('change', () => {
        if (cb.checked) wiz.confirmed.add(ch.id); else wiz.confirmed.delete(ch.id);
        row.classList.toggle('ok-c', cb.checked);
        updateDiffCounters();
      });
      lbl.append(cb, document.createTextNode(' Подтверждаю'));
      row.classList.toggle('ok-c', cb.checked);
      row.append(lbl, content);
    } else if (ch.class === 'strengthening') {
      const lbl = el('label', 'cf');
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.className = 'stcb';
      cb.checked = wiz.accepted.has(ch.id);
      cb.disabled = readOnly;
      cb.title = 'Снимите флаг, чтобы не переносить это усиление в действующую версию';
      cb.addEventListener('change', () => {
        if (cb.checked) wiz.accepted.add(ch.id); else wiz.accepted.delete(ch.id);
        row.classList.toggle('off-c', !cb.checked);
        updateDiffCounters();
      });
      lbl.append(cb);
      row.classList.toggle('off-c', !cb.checked);
      row.append(lbl, content);
    } else if (ch.kind === 'TOOL_REMOVED') {
      //++agent TASK-225 [26.09.2026] H.6: удаление инструмента —
      // отказываемо; галочка по умолчанию включена (удалить).
      const lbl = el('label', 'cf');
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = !wiz.declined.has(ch.id);
      cb.disabled = readOnly;
      cb.title = 'Снимите флаг, чтобы оставить инструмент с текущим режимом';
      cb.addEventListener('change', () => {
        if (cb.checked) wiz.declined.delete(ch.id); else wiz.declined.add(ch.id);
        row.classList.toggle('off-c', !cb.checked);
        updateDiffCounters();
      });
      lbl.append(cb, document.createTextNode(' Удалить'));
      row.classList.toggle('off-c', !cb.checked);
      row.append(lbl, content);
      //++agent TASK-225
    } else {
      row.append(content);
    }
    return row;
  };
  //++agent TASK-225 [26.09.2026] H.6/Q: удаления инструментов —
  // один фильтр на всех потребителей.
  const toolRemovals = () => wiz.diff.changes.filter(c => c.kind === 'TOOL_REMOVED');
  //++agent TASK-225
  const block = (cls, shield, shieldCls, title, tip) => {
    const b = el('div', `blk${cls ? ` ${cls}` : ''}`);
    const h = el('div', 'blk-h');
    h.append(el('span', `shield${shieldCls ? ` ${shieldCls}` : ''}`, shield), el('b', '', title));
    if (tip) { const ii = el('span', 'ii', 'i'); ii.title = tip; h.append(ii); }
    b.append(h);
    return [b, h];
  };
  const renderDiff = () => {
    const diff = wiz.diff;
    const body = $('#cmpBody');
    body.replaceChildren();
    const active = activeVersion();
    const toLabel = wiz.to === 'draft' ? `Черновик ${diff.to_version}${setup.draft && setup.draft.origin === 'import' ? ' (из файла)' : ''}` : `Версия ${diff.to_version}`;
    $('#cmpTitle').textContent = active ? `${toLabel} против действующей версии ${diff.from_version}` : `${toLabel} — действующей версии нет, сравнение с пустой настройкой`;
    const weak = diff.changes.filter(c => c.class === 'weakening');
    const strong = diff.changes.filter(c => c.class === 'strengthening');
    //++agent TASK-225 [26.09.2026] H.6: удаления — свой блок,
    // в «нейтральных» не прячем.
    const removals = toolRemovals();
    const neutral = diff.changes.filter(c => c.class === 'neutral' && c.kind !== 'TOOL_REMOVED');
    //++agent TASK-225
    if (!diff.changes.length && !diff.warnings.length) {
      body.append(el('div', 'note ok', 'Отличий нет — версия совпадает с действующей настройкой.'));
    }
    // A. Ослабления
    const [bw, hw] = block('weak', '−', '', 'Ослабления — подтвердите каждое',
      'После этого изменения агент увидит в открытом виде то, что сейчас скрыто. Подтвердите каждое отдельно.');
    hw.append(el('span', 'tag err', ''));
    hw.lastChild.id = 'weakCnt';
    if (!weak.length) bw.append(el('p', 'empty', active ? 'Ослаблений нет.' : 'Ослаблений нет: до этого база не была настроена.'));
    weak.forEach(ch => bw.append(changeRow(ch)));
    body.append(bw);
    // B. Усиления — построчные флаги, «Принимаю все» = выделить все.
    const [bs, hs] = block('', '+', 'plus', 'Усиления');
    const allLbl = el('label', 'cf right-auto');
    const all = document.createElement('input');
    all.type = 'checkbox';
    all.id = 'strAll';
    all.disabled = wiz.mode === 'compare' || !strong.length;
    all.addEventListener('change', () => {
      strong.forEach(ch => { if (all.checked) wiz.accepted.add(ch.id); else wiz.accepted.delete(ch.id); });
      renderDiff();
    });
    allLbl.append(all, document.createTextNode(' Принимаю все усиления'));
    hs.append(allLbl, el('span', 'tag mut', ''));
    hs.lastChild.id = 'strCnt';
    if (!strong.length) bs.append(el('p', 'empty', 'Усилений нет.'));
    strong.forEach(ch => bs.append(changeRow(ch, 'flat')));
    if (strong.length && wiz.mode !== 'compare') bs.append(el('p', 'small muted p14 m0', 'Снимите флаг, чтобы не переносить отдельное усиление в действующую версию: оно вернётся к состоянию действующей. «Принимаю все» ставит или снимает все флаги.'));
    body.append(bs);
    //++agent TASK-225 [26.09.2026] H.6: удаления инструментов —
    // отказываемые (галочка = удалить, по умолчанию включена).
    if (removals.length) {
      const [br, hr] = block('warnb', '×', 'w', 'Удаления инструментов',
        'Инструменты, которых нет в файле настройки. После активации их записи удаляются; при повторном вызове инструмент появится с меткой «новый» и будет запрещён до выбора режима. Удаления предлагаются только для черновика, созданного импортом файла — ручной черновик или откат не удаляют классификации.');
      const noneLbl = el('label', 'cf right-auto');
      const none = document.createElement('input');
      none.type = 'checkbox';
      none.id = 'remNone';
      none.disabled = wiz.mode === 'compare';
      none.checked = removals.every(ch => wiz.declined.has(ch.id));
      none.addEventListener('change', () => {
        removals.forEach(ch => { if (none.checked) wiz.declined.add(ch.id); else wiz.declined.delete(ch.id); });
        renderDiff();
      });
      noneLbl.append(none, document.createTextNode(' Отказаться от всех удалений'));
      hr.append(noneLbl);
      removals.forEach(ch => br.append(changeRow(ch, 'flat')));
      body.append(br);
    }
    //++agent TASK-225
    // C. Предупреждения — исключаемы построчно.
    const [bx, hx] = block('warnb', '!', 'w', 'Предупреждения');
    hx.append(el('span', 'tag warn', String(diff.warnings.length)));
    if (!diff.warnings.length) bx.append(el('p', 'empty', 'Предупреждений нет.'));
    diff.warnings.forEach(w => {
      const row = el('div', 'chg flat');
      const text = el('div', 'grow');
      text.append(el('span', 'tag warn plain', KIND_TAG[w.kind] || w.kind), document.createTextNode(' '), el('span', '', w.label || ''));
      const subj = w.subject && (w.subject.source_path || w.subject.value || w.subject.key || w.subject.tool);
      if (subj && !(w.label || '').includes(subj)) text.append(document.createTextNode(' '), el('span', 'mono', subj));
      const d = w.detail || {};
      if (w.kind === 'SOURCE_LARGE' && d.values) {
        text.append(el('div', 'why', `~${Number(d.values).toLocaleString('ru-RU')} значений${d.estimated ? ' (оценка из файла)' : ''}${d.load_time_estimate_s ? ` · загрузка ~${Math.ceil(d.load_time_estimate_s / 60)} мин` : ''}${d.memory_estimate_bytes ? ` · память ~${fmtBytes(d.memory_estimate_bytes)}` : ''}. Замер — на шаге «Сухой прогон».`));
      }
      row.append(text);
      if (w.excludable && wiz.mode !== 'compare') {
        const ex = wiz.excluded.has(w.id);
        row.classList.toggle('off-c', ex);
        const b = el('button', 'btn sm', ex ? 'Вернуть в черновик' : 'Исключить из черновика');
        b.type = 'button';
        b.title = 'Элемент (правило, источник или инструмент) не попадёт в активируемую версию';
        b.addEventListener('click', () => {
          if (wiz.excluded.has(w.id)) wiz.excluded.delete(w.id); else wiz.excluded.add(w.id);
          renderDiff();
        });
        row.append(b);
      } else if (!w.excludable) {
        row.append(el('span', 'tag mut plain', 'к файлу целиком'));
      }
      bx.append(row);
    });
    body.append(bx);
    // Нейтральные — только в режиме «Все».
    if (wiz.showAll) {
      const [bn, hn] = block('', '=', 'n', 'Без влияния на маскирование');
      hn.append(el('span', 'tag mut', String(neutral.length)));
      if (!neutral.length) bn.append(el('p', 'empty', 'Нет.'));
      neutral.forEach(ch => bn.append(changeRow(ch, 'flat')));
      body.append(bn);
    } else if (neutral.length) {
      body.append(el('p', 'small muted', `Ещё ${neutral.length} ${ruPlural(neutral.length, 'изменение', 'изменения', 'изменений')} без влияния на маскирование (обоснования, приоритеты) — «Все».`));
    }
    updateDiffCounters();
  };
  const updateDiffCounters = () => {
    const diff = wiz.diff;
    if (!diff) return;
    const weak = diff.changes.filter(c => c.class === 'weakening');
    const strong = diff.changes.filter(c => c.class === 'strengthening');
    const n = weak.filter(c => wiz.confirmed.has(c.id)).length;
    const left = weak.length - n;
    if ($('#weakCnt')) $('#weakCnt').textContent = `${n} из ${weak.length}`;
    const sn = strong.filter(c => wiz.accepted.has(c.id)).length;
    if ($('#strCnt')) $('#strCnt').textContent = `${sn} из ${strong.length}`;
    const all = $('#strAll');
    if (all) { all.checked = strong.length > 0 && sn === strong.length; all.indeterminate = sn > 0 && sn < strong.length; }
    $('#leftHint').textContent = wiz.mode === 'compare' ? '' : left
      ? `Осталось подтвердить: ${left} ${ruPlural(left, 'ослабление', 'ослабления', 'ослаблений')}`
      : 'Все ослабления подтверждены';
  };

  // Шаг 3: сухой прогон.
  const renderDry = () => {
    const body = $('#dryBody');
    $('#dryTitle').textContent = `Сухой прогон черновика ${wiz.draftVersion || ''}`;
    if (!wiz.dry) {
      body.replaceChildren(el('p', 'muted', 'Проверка прогоняет последние записи истории действующей версией и черновиком и показывает, какие ячейки поменяют статус, и сколько времени и памяти займёт проверка. Шаг можно пропустить.'));
      $('#dryRun').textContent = 'Запустить';
      return;
    }
    const r = wiz.dry;
    body.replaceChildren();
    $('#dryRun').textContent = 'Повторить';
    if (r.error) {
      const n = el('div', 'note err');
      n.textContent = r.error;
      body.append(n);
      return;
    }
    if (r.history_empty) {
      body.append(el('div', 'note info', r.reason === 'no_lineage'
        ? 'Сухой прогон недоступен: в истории нет записей с данными о происхождении колонок (записи созданы до обновления сервиса). Шаг можно пропустить.'
        : 'Сухой прогон недоступен: история базы пуста (она очищается при перезапуске сервиса). Шаг можно пропустить.'));
      return;
    }
    const stat = (value, label, cls) => { const d = el('div'); d.append(el('b', cls || '', value), el('span', '', label)); return d; };
    const t = r.totals || {};
    const s1 = el('div', 'stats');
    s1.append(stat(String(r.checked), 'проверено записей'), stat(String(r.changed), 'изменится'),
      stat(`+${t.became_masked || 0}`, 'ячеек станет скрыто', 'okc'), stat(`−${t.became_open || 0}`, 'станет видно агенту', 'errc'));
    body.append(s1);
    const tm = r.timing || {};
    const a = tm.active || {};
    const d = tm.draft || {};
    const mem = tm.dictionary_memory || {};
    const slower = (d.median_ms || 0) > (a.median_ms || 0) * 1.5;
    const s2 = el('div', 'stats');
    const delta = (mem.draft_estimated_bytes || 0) - (mem.active_bytes || 0);
    s2.append(stat(fmtMs(a.median_ms), 'проверка сейчас, медиана'), stat(fmtMs(d.median_ms), 'с черновиком, медиана', slower ? 'warnc' : ''),
      stat(fmtMs(d.p_max_ms), 'с черновиком, худшая запись', (d.over_budget || 0) > 0 ? 'errc' : ''),
      stat(`${delta >= 0 ? '+' : '−'}${fmtBytes(Math.abs(delta))}`, `память под словарь${mem.estimated ? ' (оценка)' : ''}: ${fmtBytes(mem.draft_estimated_bytes)}`));
    body.append(s2);
    if ((d.over_budget || 0) > 0 || slower) {
      const top = (tm.top_sources || [])[0];
      const n = el('div', 'note warn');
      n.append(document.createTextNode(`${(d.over_budget || 0) > 0 ? `У ${d.over_budget} ${ruPlural(d.over_budget, 'записи', 'записей', 'записей')} проверка с черновиком дольше бюджета ${tm.budget_ms} мс. ` : ''}${slower ? `Проверка ответа станет медленнее примерно в ${Math.max(1, Math.round((d.median_ms || 0) / Math.max(a.median_ms || 0.01, 0.01)))} раза. ` : ''}`));
      if (top) n.append(document.createTextNode('Больше всего добавляет источник '), el('span', 'mono', top.source_path), document.createTextNode(` (~${Number(top.values).toLocaleString('ru-RU')} значений). `));
      const back = el('button', 'btn link', 'Исключить на шаге «Сравнение»');
      back.type = 'button';
      back.addEventListener('click', () => wizGo(2));
      n.append(back);
      body.append(n);
    }
    if ((tm.top_sources || []).length) {
      const p = el('p', 'small muted');
      p.textContent = `Крупнейшие источники словаря: ${tm.top_sources.map(x => `${x.source_path} — ${Number(x.values).toLocaleString('ru-RU')} знач., ${fmtBytes(x.bytes)} (${Math.round((x.share || 0) * 100)}%)`).join('; ')}.`;
      body.append(p);
    }
    if ((r.dictionary_not_loaded || []).length) {
      body.append(el('div', 'note info', `Новые источники словаря прогон не учитывает — их значения ещё не загружены (${r.dictionary_not_loaded.length}): ${r.dictionary_not_loaded.join(', ')}. Они начнут действовать после активации и загрузки словаря.`));
    }
    const skipped = (r.skipped || []).length;
    if (skipped || t.unevaluable_cells) {
      body.append(el('p', 'small muted', `${skipped ? `Пропущено записей: ${skipped} (соответствия для раскрытия истекли). ` : ''}${t.unevaluable_cells ? `Ячеек «секрет» не оценить: ${t.unevaluable_cells} — исходное значение не сохраняется.` : ''}`));
    }
    const pill = el('div', 'pill mb14');
    const recs = r.records || [];
    [['chg', 'Только изменённые'], ['all', 'Все записи']].forEach(([f, label]) => {
      const b = el('button', (wiz.dryFilter || 'chg') === f ? 'on' : '', label);
      b.type = 'button';
      b.addEventListener('click', () => { wiz.dryFilter = f; renderDry(); });
      pill.append(b);
    });
    body.append(pill);
    const visible = recs.filter(x => (wiz.dryFilter || 'chg') === 'all' || x.became_masked + x.became_open > 0);
    const wrap = el('div', 'tablewrap');
    const table = el('table');
    const head = table.createTHead().insertRow();
    ['Время', 'Инструмент', 'Чат', 'Изменения'].forEach(h => head.append(el('th', '', h)));
    const tb = table.createTBody();
    if (!visible.length) {
      const td = tb.insertRow().insertCell();
      td.colSpan = 4;
      td.className = 'empty';
      td.textContent = 'Черновик не меняет статус ни одной ячейки в проверенных записях';
    }
    visible.forEach(rec => {
      const tr = tb.insertRow();
      tr.className = `click${wiz.dryRec === rec.history_id ? ' on-row' : ''}`;
      tr.append(el('td', '', fmtTime(rec.created_at)), el('td', 'mono', rec.tool));
      const chat = el('td', 'small clip', rec.title || rec.chat_id);
      chat.title = rec.title || rec.chat_id;
      tr.append(chat);
      const ch = el('td');
      if (rec.became_masked) ch.append(el('span', 'tag ok', `+${rec.became_masked}`), document.createTextNode(' '));
      if (rec.became_open) ch.append(el('span', 'tag err', `−${rec.became_open}`));
      if (!rec.became_masked && !rec.became_open) ch.append(el('span', 'muted', 'без изменений'));
      tr.append(ch);
      tr.addEventListener('click', () => { wiz.dryRec = rec.history_id; renderDry(); });
    });
    wrap.append(table);
    body.append(wrap);
    const rec = recs.find(x => x.history_id === wiz.dryRec);
    if (rec) {
      body.append(el('h3', 'mt16', `${rec.tool} · ${fmtTime(rec.created_at)} — ячейки, которые поменяют статус`));
      const cw = el('div', 'dg-scroll');
      const ct = el('table', 'dg-table');
      const chh = ct.createTHead().insertRow();
      ['Блок', 'Строка', 'Колонка', 'Сейчас', 'Станет', 'Причина'].forEach(h => { const th = el('th'); th.append(el('span', 'dg-sort', h)); chh.append(th); });
      const cb = ct.createTBody();
      const STATUS = { open: 'открыто', masked: 'скрыто', secret: 'секрет', unknown: 'не оценить' };
      (rec.cells || []).forEach(c => {
        const tr = cb.insertRow();
        tr.append(el('td', '', String((c.block ?? 0) + 1)), el('td', '', c.row === null || c.row === undefined ? 'текст' : String(c.row + 1)), el('td', 'mono', c.column || '—'),
          el('td', '', STATUS[c.before] || c.before));
        const after = el('td', c.after === 'masked' ? 'bm' : 'bo');
        after.append(document.createTextNode(STATUS[c.after] || c.after));
        if (c.after === 'open' || c.after === 'unknown') { after.append(document.createTextNode(' ')); after.append(el('span', 'tag err plain', 'станет видно агенту')); }
        tr.append(after);
        const rs = c.reason;
        tr.append(el('td', 'small', rs ? [rs.kind === 'dictionary' ? 'словарь' : rs.kind === 'rule' ? 'правило' : rs.kind === 'builtin' ? 'встроенное' : rs.kind, rs.category, rs.source_path].filter(Boolean).join(' · ') : '—'));
      });
      if (!(rec.cells || []).length) {
        const td = cb.insertRow().insertCell();
        td.colSpan = 6;
        td.className = 'empty';
        td.textContent = 'Ячейки не меняются';
      }
      cw.append(ct);
      body.append(cw);
      if (rec.cells_truncated) body.append(el('p', 'small muted', 'Показаны первые 2000 изменившихся ячеек.'));
      // D3: маскированная сетка записи — статусы всех ячеек «было → станет», без значений.
      const grid = rec.grid;
      if (grid && Array.isArray(grid.cells) && grid.cells.length) {
        const SHORT = { open: 'открыто', masked: 'скрыто', secret: 'секрет', unknown: '?' };
        const byBlock = new Map();
        grid.cells.forEach(c => {
          const b = c.block ?? 0;
          if (!byBlock.has(b)) byBlock.set(b, []);
          byBlock.get(b).push(c);
        });
        for (const [b, cells] of byBlock) {
          const cols = (grid.columns && grid.columns[b]) || [...new Set(cells.map(c => c.column))];
          const rows = [...new Set(cells.map(c => c.row ?? 0))].sort((x, y) => x - y).slice(0, 50);
          body.append(el('h3', 'mt16', `Сетка блока ${b + 1}: статус ячеек с черновиком`));
          const gw = el('div', 'dg-scroll');
          const gt = el('table', 'dg-table');
          const gh = gt.createTHead().insertRow();
          gh.append(el('th', '', '№'));
          cols.forEach(c => { const th = el('th'); th.append(el('span', 'dg-sort', c)); gh.append(th); });
          const gb = gt.createTBody();
          const idx = new Map(cells.map(c => [`${c.row ?? 0}|${c.column}`, c]));
          rows.forEach(r => {
            const tr = gb.insertRow();
            tr.append(el('td', 'muted', String(r + 1)));
            cols.forEach(col => {
              const c = idx.get(`${r}|${col}`);
              if (!c) { tr.append(el('td', 'muted', '')); return; }
              const changed = c.before !== c.after;
              const td = el('td', changed ? (c.after === 'masked' ? 'bm' : 'bo') : '', changed ? `${SHORT[c.before] || c.before} → ${SHORT[c.after] || c.after}` : (SHORT[c.after] || c.after));
              if (c.reason) td.title = [c.reason.kind, c.reason.category, c.reason.source_path].filter(Boolean).join(' · ');
              tr.append(td);
            });
          });
          gw.append(gt);
          body.append(gw);
          if (rows.length === 50 || grid.truncated) body.append(el('p', 'small muted', 'Показана часть сетки.'));
        }
      }
      body.append(el('p', 'small muted mt8', 'Значения ячеек администратору не показываются — только координаты и причина.'));
      const lg = el('p', 'small muted');
      lg.append(el('span', 'lg okb'), document.createTextNode(' станет скрыто · '), el('span', 'lg errb'), document.createTextNode(' станет видно агенту'));
      body.append(lg);
    }
  };
  $('#dryRun').addEventListener('click', async () => {
    const body = $('#dryBody');
    body.replaceChildren(el('p', 'muted'));
    body.firstChild.append(el('span', 'spin'), document.createTextNode(' Прогоняем черновик на последних записях истории…'));
    $('#dryRun').disabled = true;
    try {
      wiz.dry = await api(dbPath('/setup/dry-run'), { method: 'POST', body: JSON.stringify({ version: 'draft', limit: 50 }) });
      wiz.dryRec = null;
    } catch (error) {
      wiz.dry = {
        error: error.code === 'DRY_RUN_BUSY'
          ? 'Сухой прогон уже выполняется — повторите через несколько секунд.'
          : `Не удалось выполнить прогон: ${error.message}. Повторите.`,
      };
    }
    $('#dryRun').disabled = false;
    renderDry();
  });

  // Шаг 4: активация.
  const renderActivate = () => {
    const diff = wiz.diff;
    const active = activeVersion();
    const v = wiz.draftVersion;
    $('#actTitle').textContent = `Активировать версию ${v || ''}`;
    $('#actText').textContent = `Версия ${v} станет действующей.${active ? ` Версия ${active.version} уйдёт в архив — к ней можно вернуться (Версии › Вернуть эту версию).` : ''}`;
    hideNote('#actErr');
    if (!wiz.activated) hideNote('#actOk');
    const checks = $('#actChecks');
    checks.replaceChildren();
    if (!diff) {
      checks.append(el('li', '', 'Сначала откройте шаг «Сравнение».'));
      $('#actBtn').disabled = true;
      $('#actHint').textContent = 'Сравнение ещё не загружено.';
      return;
    }
    const weak = diff.changes.filter(c => c.class === 'weakening');
    const strong = diff.changes.filter(c => c.class === 'strengthening');
    const n = weak.filter(c => wiz.confirmed.has(c.id)).length;
    const sn = strong.filter(c => wiz.accepted.has(c.id)).length;
    const li = (text, ok) => checks.append(el('li', ok ? 'ok' : '', text));
    li(`Подтверждено ослаблений: ${n} из ${weak.length}`, n === weak.length);
    li(`Принято усилений: ${sn} из ${strong.length}${sn < strong.length ? ' — непринятые вернутся к состоянию действующей' : ''}`, true);
    li(`Исключено предупреждений: ${wiz.excluded.size}`, true);
    if (wiz.dry && !wiz.dry.error && !wiz.dry.history_empty) li(`Сухой прогон: станет скрыто ${(wiz.dry.totals || {}).became_masked || 0}, станет видно ${(wiz.dry.totals || {}).became_open || 0}`, true);
    const ok = n === weak.length && !wiz.activated;
    $('#actBtn').disabled = !ok;
    $('#actBtn').textContent = `Активировать версию ${v || ''}`;
    $('#actHint').textContent = wiz.activated ? '' : (n === weak.length ? '' : 'Сначала подтвердите все ослабления на шаге «Сравнение».');
    if (setup.ed && setup.ed.editable && (dictSnapshot() !== setup.savedDict || rulesSnapshot() !== setup.savedRules)) {
      $('#actHint').textContent = `${$('#actHint').textContent} В редакторе есть несохранённые изменения — они не войдут в активируемую версию.`.trim();
    }
  };
  $('#actBtn').addEventListener('click', async () => {
    hideNote('#actErr');
    $('#actBtn').disabled = true;
    try {
      const res = await api(dbPath('/setup/activate'), {
        method: 'POST',
        body: JSON.stringify({
          version: wiz.draftVersion,
          draft_hash: wiz.draftHash,
          confirmed_weakenings: [...wiz.confirmed],
          accepted_strengthenings: [...wiz.accepted],
          excluded_warnings: [...wiz.excluded],
          //++agent TASK-225 [26.09.2026] H.6: отказы от удалений.
          declined_tool_removals: [...wiz.declined],
          //++agent TASK-225
          comment: $('#actComment').value.trim() || undefined,
        }),
      });
      wiz.activated = true;
      const at = new Date(res.activated_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
      showNote('#actOk', `Версия ${res.active_version} действует с ${at}. Словарь перезагружается — новые значения начнут маскироваться после завершения (обычно до минуты).${(res.reverted_strengthenings || []).length ? ` Не принято усилений: ${res.reverted_strengthenings.length}.` : ''}${(res.excluded_items || []).length ? ` Исключено элементов: ${res.excluded_items.length}.` : ''}`);
      $('#actComment').value = '';
      $('#actHint').textContent = '';
      await loadDatabases();
      scheduleRefreshPoll();
      const fresh = dbs.list.find(x => x.id === dbs.current.id);
      if (fresh) dbs.current = fresh;
      await loadSetup(dbs.current);
      $('#setupEditor').hidden = true;
      $('#setupWizard').hidden = false;
      $('#wiz4Back').textContent = 'К настройке';
      renderActivate();
    } catch (error) {
      $('#actBtn').disabled = false;
      const d = error.details || {};
      if (error.code === 'WEAKENING_NOT_CONFIRMED') {
        showError($('#actErr'), { message: `Сервер нашёл неподтверждённые ослабления (${(d.missing || []).length}). Возможно, исключение элемента или отказ от усиления сам ослабил настройку. Сравнение обновлено — подтвердите их.` });
        wizGo(2);
      } else if (error.code === 'STALE_CONFIRMATION' || error.code === 'DRAFT_CHANGED') {
        showError($('#actErr'), { message: 'Черновик изменился после сравнения — сравнение обновлено, проверьте подтверждения заново.' });
        wiz.confirmed = new Set();
        wizGo(2);
      } else if (error.code === 'SECRET_POLICY_UNSUPPORTED') {
        showError($('#actErr'), { message: 'В версии есть включённые правила «Секрет» — сервис пока не может их применить. Замените «Секрет» на «Скрыть» в черновике (Правила) или выключите такие правила. Пароли, ключи и токены по имени поля уже вырезаются встроенными правилами.' });
      } else if (error.code === 'WARNING_NOT_EXCLUDABLE') {
        showError($('#actErr'), { message: 'Часть предупреждений нельзя исключить — они относятся к файлу целиком. Сравнение обновлено.' });
        wizGo(2);
      } else if (error.code === 'NOT_A_DRAFT') {
        showError($('#actErr'), { message: 'Эта версия уже не черновик — обновите вкладку.' });
      } else {
        showError($('#actErr'), error);
      }
    }
  });

  // ---------- Экспорт (Admin: любая версия; include_tools — за флажком) ----------
  const exportState = { what: 'active' };
  const exportFileName = () => {
    const db = dbs.current;
    const label = (db.display_label || db.label || db.id).replace(/[^\p{L}\p{N}_.-]+/gu, '_');
    const active = activeVersion();
    const which = $('#exDraft').checked ? (setup.draft ? setup.draft.version : 'draft')
      : $('#exOther').checked ? $('#exOtherSel').value : (active ? active.version : 'active');
    return `masking-setup-${label}-v${which}-${new Date().toISOString().slice(0, 10)}.json`;
  };
  const openExport = what => {
    const active = activeVersion();
    $('#exActive').disabled = !active;
    $('#exActiveLabel').textContent = active ? `Действующую версию ${active.version}` : 'Действующую версию (нет)';
    $('#exDraft').disabled = !setup.draft;
    $('#exDraftLabel').textContent = setup.draft ? `Черновик ${setup.draft.version}` : 'Черновик (нет)';
    const others = setup.policies.filter(p => p.status === 'retired').sort((a, b) => b.version - a.version);
    $('#exOtherSel').replaceChildren(...others.map(p => { const o = el('option', '', String(p.version)); o.value = String(p.version); return o; }));
    $('#exOther').disabled = !others.length;
    $('#exTools').checked = false;
    const pick = what || (active ? 'active' : 'draft');
    if (pick === 'active') $('#exActive').checked = true;
    else if (pick === 'draft') $('#exDraft').checked = true;
    else { $('#exOther').checked = true; $('#exOtherSel').value = pick; }
    exportState.what = pick;
    $('#exName').textContent = exportFileName();
    openOverlay('dlgExport');
  };
  ['#exActive', '#exDraft', '#exOther', '#exOtherSel'].forEach(id => $(id).addEventListener('change', () => { $('#exName').textContent = exportFileName(); }));
  $('#exOtherSel').addEventListener('focus', () => { $('#exOther').checked = true; $('#exName').textContent = exportFileName(); });
  $('#setupExportBtn').addEventListener('click', () => openExport());
  $('#exCancel').addEventListener('click', closeOverlays);
  $('#exGo').addEventListener('click', async () => {
    const version = $('#exDraft').checked ? 'draft' : $('#exOther').checked ? $('#exOtherSel').value : 'active';
    const url = dbPath(`/setup/export?version=${encodeURIComponent(version)}&include_tools=${$('#exTools').checked ? 1 : 0}`);
    closeOverlays();
    try {
      await downloadFile(url, exportFileName());
    } catch (error) {
      showError($('#setupErr'), error);
    }
  });

  // ---------- Инструменты (С4, B10) ----------
  const tools = { list: [], dirty: new Map(), filter: 'all' };
  const loginOf = id => {
    if (!id) return 'авто';
    const u = users.find(x => x.user_id === id);
    return u ? u.login : (/^[0-9a-f-]{36}$/i.test(id) ? shortId(id) : id);
  };
  const loadTools = async db => {
    tools.list = [];
    tools.dirty.clear();
    hideNote('#toolsErr');
    try {
      tools.list = await api(`/api/v1/admin/databases/${encodeURIComponent(db.id)}/tools`);
    } catch (error) {
      if (error.status !== 401) showError($('#toolsErr'), error);
      return;
    }
    renderTools();
  };
  const updateToolsBadge = () => {
    const n = tools.list.filter(t => t.auto_added).length;
    $('#toolsBadge').hidden = !n;
    $('#toolsBadge').textContent = String(n);
    $('#toolsBadge').title = n ? `Новых инструментов без выбранного режима: ${n}` : '';
    $$('#toolsPill button').forEach(b => {
      b.textContent = b.dataset.f === 'new' ? `Только новые (${n})` : `Все (${tools.list.length})`;
    });
  };
  const renderTools = () => {
    updateToolsBadge();
    const q = $('#toolFilter').value.trim().toLowerCase();
    const body = $('#toolsBody');
    body.replaceChildren();
    const visible = tools.list.filter(t => (!q || t.tool_name.toLowerCase().includes(q)) && (tools.filter === 'all' || t.auto_added));
    if (!visible.length) {
      const td = body.insertRow().insertCell();
      td.colSpan = 5;
      td.className = 'empty';
      td.textContent = tools.filter === 'new' ? 'Новых инструментов нет' : 'Инструменты не найдены';
    }
    for (const tool of visible) {
      const tr = body.insertRow();
      if (tool.auto_added) tr.className = 'newrow';
      const name = el('td', 'mono');
      name.append(document.createTextNode(tool.tool_name));
      if (tool.auto_added) {
        name.append(document.createTextNode(' '));
        const tag = el('span', 'tag warn', 'новый');
        tag.title = `Инструмент впервые вызван ${fmtTime(tool.first_seen_at)}. Пока режим не выбран, его вызовы отклоняются (${tool.denied_count || 0}).`;
        name.append(tag);
      }
      tr.append(name);
      const current = tools.dirty.get(tool.tool_name) ?? tool.class;
      const sel = el('select', 'input sm');
      TOOL_MODES.forEach(([value, label]) => { const o = el('option', '', label); o.value = value; sel.append(o); });
      sel.value = current;
      sel.title = (TOOL_MODE[current] || [])[3] || '';
      sel.addEventListener('change', () => {
        const next = sel.value;
        const apply = () => {
          if (next === tool.class) tools.dirty.delete(tool.tool_name); else tools.dirty.set(tool.tool_name, next);
          $('#toolsSave').disabled = tools.dirty.size === 0;
          $('#toolsReset').hidden = tools.dirty.size === 0;
          $('#toolsSave').textContent = tools.dirty.size ? `Сохранить изменения (${tools.dirty.size})` : 'Сохранить изменения';
          sel.title = (TOOL_MODE[next] || [])[3] || '';
        };
        if (next === 'no-mask' && tool.class !== 'no-mask') {
          askBypass(tool.tool_name, apply, () => { sel.value = current; });
        } else {
          apply();
        }
      });
      const selTd = el('td');
      selTd.append(sel);
      tr.append(selTd);
      tr.append(el('td', 'hide-sm small', tool.auto_added ? `впервые ${fmtTime(tool.first_seen_at)}` : fmtTime(tool.updated_at)));
      tr.append(el('td', 'hide-sm', String(tool.denied_count || 0)));
      tr.append(el('td', `hide-sm${tool.reviewer ? '' : ' muted'}`, loginOf(tool.reviewer)));
      //++agent TASK-225 [26.09.2026] удаление записи классификации —
      // снятые из 1С инструменты не должны вечно висеть в списке.
      const delTd = el('td');
      const delBtn = el('button', 'btn sm', 'Удалить');
      delBtn.type = 'button';
      delBtn.title = 'Убрать инструмент из списка. Если его снова вызовут, он появится с меткой «новый» и будет запрещён до выбора режима.';
      delBtn.addEventListener('click', () => {
        askConfirm('Удалить инструмент из списка?', `Запись о режиме «${tool.tool_name}» будет удалена. Если инструмент вызовут снова, он появится с меткой «новый», и его вызовы будут отклоняться до выбора режима.`, async () => {
          try {
            await api(dbPath(`/tools/${encodeURIComponent(tool.tool_name)}`), { method: 'DELETE' });
            tools.dirty.delete(tool.tool_name);
            await loadTools(dbs.current);
          } catch (error) {
            showError($('#toolsErr'), error);
            renderTools();
          }
        });
      });
      delTd.append(delBtn);
      tr.append(delTd);
      //++agent TASK-225
    }
    $('#toolsSave').disabled = tools.dirty.size === 0;
    $('#toolsReset').hidden = tools.dirty.size === 0;
  };
  // Диалог С4: bypass только после явного подтверждения (сервер требует
  // confirm_bypass:true — диалог и есть это подтверждение).
  const bypass = { yes: null, no: null };
  const askBypass = (toolName, yes, no) => {
    bypass.yes = yes;
    bypass.no = no;
    $('#bypassTitle').textContent = `Отключить маскирование для «${toolName}»?`;
    const word = dataLikeWord(toolName);
    $('#bypassHeur').hidden = !word;
    $('#bypassHeur').textContent = word ? `Имя инструмента похоже на чтение данных (содержит «${word}»).` : '';
    openOverlay('dlgBypass');
  };
  $('#bypassYes').addEventListener('click', () => { closeOverlays(); if (bypass.yes) bypass.yes(); bypass.yes = null; bypass.no = null; });
  $('#bypassNo').addEventListener('click', () => { closeOverlays(); if (bypass.no) bypass.no(); bypass.yes = null; bypass.no = null; });
  $$('#toolsPill button').forEach(btn => btn.addEventListener('click', () => {
    tools.filter = btn.dataset.f;
    $$('#toolsPill button').forEach(b => b.classList.toggle('on', b === btn));
    renderTools();
  }));
  $('#toolFilter').addEventListener('input', renderTools);
  $('#toolsReset').addEventListener('click', () => { tools.dirty.clear(); renderTools(); $('#toolsSave').textContent = 'Сохранить изменения'; });
  $('#toolsSave').addEventListener('click', async () => {
    if (!dbs.current || !tools.dirty.size) return;
    hideNote('#toolsErr');
    try {
      for (const [toolName, cls] of tools.dirty) {
        await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/tools/${encodeURIComponent(toolName)}`, {
          method: 'PUT',
          body: JSON.stringify(cls === 'no-mask' ? { class: cls, confirm_bypass: true } : { class: cls }),
        });
        tools.dirty.delete(toolName);
      }
      $('#toolsSave').textContent = 'Сохранить изменения';
      await loadTools(dbs.current);
      loadDatabases();
    } catch (error) {
      showError($('#toolsErr'), error.code === 'BYPASS_NOT_CONFIRMED'
        ? { message: 'Сервер не принял режим «Без маскирования» без подтверждения.' }
        : error);
      renderTools();
    }
  });

  // ---------- Журнал настройки (B11) ----------
  const JOURNAL_TEXT = {
    import: j => `Импорт файла ${j.file_name || ''}${j.sha256 ? ` · sha256 ${shortHash(j.sha256)}` : ''} → черновик ${j.version ?? ''}`,
    import_rejected: j => `Импорт отклонён: ${j.file_name || 'файл'}${j.details && j.details.codes ? ` (${j.details.codes.slice(0, 5).join(', ')})` : ''}`,
    draft_create: j => `Создан черновик ${j.version ?? ''}${j.details && j.details.from === 'empty' ? ' (пустой)' : ' (из действующей)'}`,
    draft_edit: j => `Изменён черновик ${j.version ?? ''}${j.details && j.details.area ? ` · ${({ dictionary: 'словарь', rules: 'правила', tools: 'инструменты', revert: 'возврат элементов' })[j.details.area] || j.details.area}` : ''}`,
    draft_discard: j => `Удалён черновик ${j.version ?? ''}`,
    activate: j => {
      const d = j.details || {};
      return `Активирована версия ${j.version ?? ''} · ослаблений подтверждено ${(d.confirmed_weakenings || []).length}${(d.reverted_strengthenings || []).length ? ` · не принято усилений ${d.reverted_strengthenings.length}` : ''}${(d.excluded_warnings || []).length ? ` · исключено ${d.excluded_warnings.length}` : ''}${d.comment ? ` · «${d.comment}»` : ''}`;
    },
    rollback: j => `Черновик ${j.version ?? ''} — копия версии ${j.details && j.details.from_version}`,
    export: j => `Экспорт версии ${j.version ?? ''}${j.sha256 ? ` · sha256 ${shortHash(j.sha256)}` : ''}`,
    tool_mode: j => `Режим инструмента${j.details && j.details.tool ? ` ${j.details.tool}` : ''}${j.details && j.details.after ? ` → ${(TOOL_MODE[j.details.after] || [, j.details.after])[1]}` : ''}`,
    migration: j => `Перенос настройки при обновлении сервиса → версия ${j.version ?? ''}`,
  };
  const loadJournal = async () => {
    const body = $('#journalBody');
    hideNote('#journalErr');
    body.replaceChildren();
    const loadingTd = body.insertRow().insertCell();
    loadingTd.colSpan = 3;
    loadingTd.className = 'empty';
    loadingTd.textContent = 'Загрузка…';
    try {
      const rows = await api(dbPath('/setup/journal?limit=100'));
      body.replaceChildren();
      if (!rows.length) {
        const td = body.insertRow().insertCell();
        td.colSpan = 3;
        td.className = 'empty';
        td.textContent = 'Записей пока нет';
      }
      rows.forEach(j => {
        const tr = body.insertRow();
        tr.append(el('td', '', fmtTime(j.at)),
          el('td', '', j.actor && j.actor.login ? j.actor.login : ({ agent: 'агент', service: 'сервис', human: 'администратор' })[j.actor && j.actor.kind] || '—'),
          el('td', '', (JOURNAL_TEXT[j.action] || (x => x.action))(j)));
      });
    } catch (error) {
      body.replaceChildren();
      if (error.status !== 401) showError($('#journalErr'), { message: `Журнал настройки недоступен: ${error.message}.`, correlationId: error.correlationId });
    }
  };

  // Deep-link из «Почему скрыто» (§6.3 link.admin_path): /admin#db=…&tab=setup&rule=…|source=…&version=N.
  const applyFocus = () => {
    const f = setup.focus;
    if (!f || !setup.ed) return;
    setup.focus = null;
    if (f.rule) {
      setSub('rules');
      const row = $(`#rulesBody tr[data-rule-id="${CSS.escape(f.rule)}"]`);
      if (row) { row.classList.add('hlrow'); row.scrollIntoView({ block: 'center' }); }
      else showNote('#setupOk', `Причина относится к правилу версии ${f.version}${setup.ed.editable ? '' : ''}; в показанной версии оно не найдено — сравните версии во вкладке «Версии».`);
    } else if (f.source) {
      setSub('dict');
      // Сервер (D8) может прислать вместо пути категорию словаря — ищем и по ней.
      const found = eds().find(s => s.source_path.toLowerCase() === f.source.toLowerCase())
        || eds().find(s => (s.category || '').toLowerCase() === f.source.toLowerCase());
      if (found) openSource(found.source_path);
      else showNote('#setupOk', `Источник ${f.source} (версия ${f.version}) в показанной версии не найден.`);
    }
  };
  const parseAdminHash = () => {
    const h = new URLSearchParams(location.hash.replace(/^#/, ''));
    if (!h.get('db')) return null;
    return { db: h.get('db'), tab: h.get('tab'), rule: h.get('rule'), source: h.get('source'), version: h.get('version') };
  };
  //++agent TASK-225
  await loadUsers();
  //++agent TASK-225 [26.09.2026 02:50:00] глубокая ссылка из «Почему скрыто» (Viewer):
  // открыть базу, вкладку настройки и нужное правило/источник.
  // Ссылка из Viewer в уже открытой админке меняет только hash — перечитываем страницу.
  window.addEventListener('hashchange', () => { if (parseAdminHash()) location.reload(); });
  const link = parseAdminHash();
  if (link) {
    switchSection('dbs');
    await loadDatabases();
    const target = dbs.list.find(d => d.id === link.db);
    if (target) {
      setup.focus = link.rule || link.source ? link : null;
      selectDb(target);
      const tabBtn = $(`#dbTabs button[data-dt="${link.tab === 'tools' ? 'tools' : 'setup'}"]`);
      if (tabBtn) tabBtn.click();
    }
  }
  //++agent TASK-225
}

// ---------- общий запуск ----------

document.addEventListener('keydown', event => {
  if (event.key === 'Escape') closeOverlays();
});
document.addEventListener('click', event => {
  // Клик по фону оверлея и по элементу вне меню профиля.
  if (event.target.classList && event.target.classList.contains('overlay')) closeOverlays();
  if (!event.target.closest || !event.target.closest('.profile')) {
    $$('.menu').forEach(m => m.classList.remove('on'));
  }
});

applyStoredTheme();
const page = document.body.dataset.page;
if (page === 'start') startPage();
else if (page === 'activate') activatePage();
else if (page === 'viewer') viewerPage();
else if (page === 'admin') adminPage();
/*--agent TASK-224*/
