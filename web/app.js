'use strict';
/*++agent TASK-224 [24.09.2026] — единый JS нового UI (старт/активация/admin/viewer).
   CSRF только в памяти вкладки (Б11); reveal-данные не кэшируются и не
   сохраняются в web storage; тема — единственное значение в localStorage. */

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

const state = { session: null };

class ApiErr extends Error {
  constructor(status, code, message, correlationId) {
    super(message || 'Операция не выполнена');
    this.status = status;
    this.code = code || '';
    this.correlationId = correlationId || '';
  }
}

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
    throw new ApiErr(response.status, err.code, err.message, err.correlation_id);
  }
  if (response.status === 204 || response.status === 202) return null;
  return response.json();
}

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
// снаружи через renderCell; CSV-экспорт отдаёт ТОЛЬКО маскированные строки
// (exportRows), при показе раскрытых значений выключен с причиной.
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

function renderReport(target, report, maskedReport, grids, exportPrefix) {
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
        // CSV — всегда маскированная версия блока, независимо от того, что
        // показано на экране.
        exportRows: () => (maskedBlock
          ? { columns: maskedBlock.columns || block.columns, rows: maskedBlock.rows || block.rows }
          : { columns: block.columns, rows: block.rows }),
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
        },
      });
      if (maskedReport) {
        grid.setExportEnabled(false,
          'Экспорт недоступен, пока показаны реальные значения — CSV выгружает только маскированные.');
      }
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
    title.textContent = text;
    title.title = text;
    //++agent TASK-224 [25.09.2026 12:25:00] итерация 5: свёрнут до 2 строк;
    // «Развернуть» — только если текст реально обрезан.
    title.classList.add('clamp');
    const more = $('#reportMore');
    more.textContent = 'Развернуть';
    requestAnimationFrame(() => { more.hidden = title.scrollHeight <= title.clientHeight + 1; });
    //++agent TASK-224
    const [cls, label] = OUTCOME_LABELS[record.outcome] || ['mut', record.outcome];
    const status = $('#reportStatus');
    status.className = `tag ${cls}`;
    status.textContent = label;
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
    renderReport($('#reportBody'), record.report, null, viewer.grids, record.id);
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
        const [cls, label] = OUTCOME_LABELS[item.outcome] || ['mut', item.outcome];
        btn.append(el('b', '', fmtTime(item.created_at)), document.createTextNode(' '),
          el('span', 'mono small', item.tool_name), document.createElement('br'),
          el('span', `tag ${cls}`, label));
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
  //**agent TASK-224
  //--agent TASK-224

  await loadDatabases();
  crumbs();
}

// ---------- Admin ----------

const TOOL_CLASSES = [
  ['data-mask', 'Маскировать'],
  ['metadata-bypass', 'Только метаданные'],
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
    if (db.refresh_stage && db.refresh_stage !== 'active') {
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

  const scheduleRefreshPoll = () => {
    if (dbs.refreshTimer) return;
    dbs.refreshTimer = setInterval(async () => {
      await loadDatabases();
      const current = dbs.current && dbs.list.find(d => d.id === dbs.current.id);
      //**agent TASK-224 [25.09.2026 12:50:00] итерация 5: 'active' — финал
      // if (!current || !current.refresh_stage) {
      if (!current || !current.refresh_stage || current.refresh_stage === 'active') {
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
    $('#dictErr').hidden = true;
    $('#polErr').hidden = true;
    renderDbHead(db);
    renderMainTab(db);
    loadTools(db);
    loadDict(db);
    loadPolicies(db);
  };

  $$('#dbTabs button').forEach(btn => btn.addEventListener('click', () => {
    $$('#dbTabs button').forEach(b => b.classList.toggle('on', b === btn));
    ['main', 'tools', 'dict', 'pol'].forEach(name => { $('#dt-' + name).hidden = name !== btn.dataset.dt; });
  }));

  // Основное
  let dbModeOn = true;
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
        }),
      });
      await loadDatabases();
    } catch (error) {
      showError($('#mainErr'), error);
    }
  });

  // Инструменты
  const tools = { list: [], dirty: new Map() };
  const loadTools = async db => {
    tools.list = [];
    tools.dirty.clear();
    $('#toolsSave').disabled = true;
    try {
      tools.list = await api(`/api/v1/admin/databases/${encodeURIComponent(db.id)}/tools`);
    } catch (error) {
      if (error.status !== 401) showError($('#toolsErr'), error);
      return;
    }
    renderTools();
  };
  const renderTools = () => {
    const filter = $('#toolFilter').value.trim().toLowerCase();
    const body = $('#toolsBody');
    body.replaceChildren();
    const visible = tools.list.filter(t => !filter || t.tool_name.toLowerCase().includes(filter));
    if (!visible.length) {
      const tr = body.insertRow();
      const td = tr.insertCell();
      td.colSpan = 2;
      td.className = 'empty';
      td.textContent = 'Инструменты не найдены';
      return;
    }
    for (const tool of visible) {
      const tr = body.insertRow();
      tr.append(el('td', 'mono', tool.tool_name));
      const seg = el('div', 'seg');
      const current = tools.dirty.get(tool.tool_name) ?? tool.class;
      for (const [value, label] of TOOL_CLASSES) {
        const btn = el('button', current === value ? 'on' : '', label);
        btn.type = 'button';
        btn.addEventListener('click', () => {
          if (value === tool.class) tools.dirty.delete(tool.tool_name);
          else tools.dirty.set(tool.tool_name, value);
          $('#toolsSave').disabled = tools.dirty.size === 0;
          $('#toolsSave').textContent = tools.dirty.size ? `Сохранить изменения (${tools.dirty.size})` : 'Сохранить изменения';
          $$('button', seg).forEach(b => b.classList.toggle('on', b === btn));
        });
        seg.append(btn);
      }
      const td = el('td');
      td.append(seg);
      tr.append(td);
    }
  };
  $('#toolFilter').addEventListener('input', renderTools);
  $('#toolsSave').addEventListener('click', async () => {
    if (!dbs.current || !tools.dirty.size) return;
    $('#toolsErr').hidden = true;
    try {
      for (const [toolName, cls] of tools.dirty) {
        await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/tools/${encodeURIComponent(toolName)}`, {
          method: 'PUT',
          body: JSON.stringify({ class: cls }),
        });
      }
      await loadTools(dbs.current);
    } catch (error) {
      showError($('#toolsErr'), error);
    }
  });

  // Справочники
  //++agent TASK-224 [24.09.2026]
  // Дерево метаданных: узел-поле — родная гранулярность selector
  // (source_path до поля). Чекбокс группы раскрывается в один selector на
  // каждое листовое поле — контракт хранения безусловно тот же.
  //--agent TASK-224
  const dict = { id: null, mode: 'part', selectors: [], saved: '[]', savedMode: 'part' };
  const meta = { ready: null, root: [], cache: new Map(), expanded: new Set(), search: null, poll: null };

  const resetMeta = () => {
    meta.ready = null;
    meta.root = [];
    meta.cache = new Map();
    meta.expanded = new Set();
    meta.search = null;
    if (meta.poll) { clearInterval(meta.poll); meta.poll = null; }
  };

  const selKey = s => `${s.source_path}${s.category}${JSON.stringify(s.filter_ast || null)}`;
  const diffCount = () => {
    let n = dict.mode === dict.savedMode ? 0 : 1;
    const saved = new Set(JSON.parse(dict.saved || '[]').map(selKey));
    const cur = new Set(dict.selectors.map(selKey));
    saved.forEach(k => { if (!cur.has(k)) n += 1; });
    cur.forEach(k => { if (!saved.has(k)) n += 1; });
    return n;
  };

  const selCovered = path => dict.selectors.some(s => s.source_path === path);
  const selUnder = path => dict.selectors.some(s => s.source_path === path || s.source_path.startsWith(`${path}.`));

  const loadMeta = path =>
    api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/metadata?path=${encodeURIComponent(path)}`);

  const loadDict = async db => {
    dict.id = null;
    dict.mode = 'part';
    dict.selectors = [];
    resetMeta();
    $('#dictSearch').value = '';
    try {
      const configs = await api(`/api/v1/admin/databases/${encodeURIComponent(db.id)}/dictionaries`);
      if (configs.length) {
        dict.id = configs[0].id;
        dict.mode = configs[0].mode;
        dict.selectors = configs[0].selectors.map(s => ({ ...s }));
      }
      dict.savedMode = dict.mode;
      dict.saved = JSON.stringify(dict.selectors.map(s => ({
        source_path: s.source_path, category: s.category, filter_ast: s.filter_ast ?? null,
      })));
    } catch (error) {
      if (error.status !== 401) showError($('#dictErr'), error);
      return;
    }
    try {
      const page = await loadMeta('');
      meta.ready = page.manifest_ready;
      meta.root = page.nodes;
      meta.cache.set('', page.nodes);
    } catch (error) {
      if (error.status !== 401) showError($('#dictErr'), error);
    }
    renderDict();
  };

  // Все листовые поля под узлом (лениво догружает уровни). Узел, который
  // одновременно является полем (kind=group + field_type), включает себя.
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

  // 'all' | 'some' | 'none' — по загруженным уровням; нераскрытая группа с
  // выбранными потомками честно помечается частичным покрытием.
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

  const nodeView = (node, withPath) => {
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
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    const password = node.kind === 'field' && node.password_mode === true;
    const state = coverage(node);
    cb.checked = state === 'all';
    cb.indeterminate = state === 'some';
    if (password) {
      cb.disabled = true;
      cb.title = 'Парольное поле — значения режутся на границе всегда, выбор не требуется';
    }
    cb.addEventListener('change', () => toggleNode(node, cb.checked));
    const name = el('span', 'nname', node.name);
    name.title = node.path;
    row.append(cb, name);
    if (node.kind === 'group') {
      row.append(el('span', 'fname', `${node.field_count} полей`));
      if (node.password_count) row.append(el('span', 'fname', `парольных ${node.password_count}`));
    } else {
      if (withPath) {
        const parent = node.path.includes('.') ? node.path.slice(0, node.path.lastIndexOf('.')) : node.path;
        row.append(el('span', 'fname', parent));
      }
      if (node.field_type) row.append(el('span', 'fname', node.field_type));
      if (password) row.append(el('span', 'tag mut', 'пароль'));
    }
    wrap.append(row);
    if (node.kind === 'group' && expanded) {
      const kids = el('div', 'kids');
      const children = meta.cache.get(node.path);
      if (!children) kids.append(el('p', 'empty', 'Загрузка…'));
      else if (!children.length) kids.append(el('p', 'empty', 'Пусто'));
      else children.forEach(child => kids.append(nodeView(child)));
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

  const toggleNode = async (node, checked) => {
    $('#dictErr').hidden = true;
    if (!checked) {
      dict.selectors = dict.selectors.filter(s =>
        !(s.source_path === node.path || s.source_path.startsWith(`${node.path}.`)));
      renderDict();
      return;
    }
    const category = $('#dictCatDefault').value.trim();
    if (!category) {
      showError($('#dictErr'), { message: 'Укажите категорию для новых источников в панели «Что маскируется».' });
      renderDict();
      return;
    }
    if (node.kind === 'field') {
      if (!selCovered(node.path)) {
        dict.selectors.push({ source_path: node.path, category, filter_ast: null, in_manifest: true });
      }
      renderDict();
      return;
    }
    try {
      const leaves = await collectLeaves(node);
      const addable = leaves.filter(leaf => leaf.password_mode !== true && !selCovered(leaf.path));
      if (dict.selectors.length + addable.length > 100) {
        showError($('#dictErr'), {
          message: `Выбор добавит ${addable.length} источников — лимит конфигурации 100. Отметьте объекты точечнее.`,
        });
        renderDict();
        return;
      }
      addable.forEach(leaf => dict.selectors.push({
        source_path: leaf.path, category, filter_ast: null, in_manifest: true,
      }));
      meta.expanded.add(node.path);
      renderDict();
    } catch (error) {
      showError($('#dictErr'), error);
      renderDict();
    }
  };

  const renderTree = () => {
    const box = $('#dictTree');
    box.replaceChildren();
    if (meta.search) {
      const { nodes, truncated } = meta.search;
      if (!nodes.length) box.append(el('p', 'empty', 'Ничего не найдено'));
      else nodes.forEach(node => box.append(nodeView(node, true)));
      if (truncated) box.append(el('p', 'empty', 'Показаны первые 200 совпадений — уточните запрос'));
      return;
    }
    if (meta.ready === null) { box.append(el('p', 'empty', 'Загрузка…')); return; }
    if (meta.ready === false) { box.append(el('p', 'empty', 'Метаданные не получены')); return; }
    if (!meta.root.length) { box.append(el('p', 'empty', 'Манифест пуст')); return; }
    meta.root.forEach(node => box.append(nodeView(node)));
  };

  // Панель «Что маскируется»: сохранённые вне manifest источники
  // (in_manifest === false) остаются в списке и подсвечиваются красным —
  // не удаляем молча.
  const renderSelPanel = () => {
    const stale = dict.selectors.filter(s => s.in_manifest === false).length;
    const parts = [`Выбрано источников: ${dict.selectors.length}/100`];
    const diff = diffCount();
    if (diff) parts.push(`изменений: ${diff}`);
    if (stale) parts.push(`нет в конфигурации: ${stale}`);
    $('#dictCount').textContent = parts.join(' · ');
    const list = $('#dictSelList');
    list.replaceChildren();
    if (!dict.selectors.length) {
      list.append(el('p', 'empty', 'Ничего не выбрано'));
      return;
    }
    const groups = new Map();
    dict.selectors.forEach(s => {
      const i = s.source_path.lastIndexOf('.');
      const parent = i > 0 ? s.source_path.slice(0, i) : s.source_path;
      if (!groups.has(parent)) groups.set(parent, []);
      groups.get(parent).push(s);
    });
    for (const [parent, rows] of groups) {
      list.append(el('div', 'mono small muted mt8', parent));
      rows.forEach(s => {
        const row = el('div', `selrow${s.in_manifest === false ? ' stale' : ''}`);
        const name = el('span', 'sname mono small', s.source_path.split('.').pop());
        name.title = s.source_path;
        row.append(name);
        if (s.in_manifest === false) row.append(el('span', 'tag err', 'нет в конфигурации'));
        if (s.filter_ast) {
          const tag = el('span', 'tag mut', 'условие');
          tag.title = JSON.stringify(s.filter_ast);
          row.append(tag);
        }
        const cat = el('input', 'input cat');
        cat.value = s.category;
        cat.maxLength = 32;
        cat.addEventListener('change', () => { s.category = cat.value.trim(); renderSelPanel(); });
        row.append(cat);
        const rm = el('button', 'btn sm', '✕');
        rm.type = 'button';
        rm.title = 'Убрать источник';
        rm.addEventListener('click', () => {
          dict.selectors.splice(dict.selectors.indexOf(s), 1);
          renderDict();
        });
        row.append(rm);
        list.append(row);
      });
    }
  };

  const renderDict = () => {
    $$('#dictMode button').forEach(b => b.classList.toggle('on', b.dataset.mode === dict.mode));
    $('#dictModeHint').textContent = dict.mode === 'all'
      ? 'Маскируются все справочники, разрешённые действующими правилами.'
      : 'Маскируются только источники, отмеченные в дереве или добавленные вручную.';
    $('#dictPart').hidden = dict.mode === 'all';
    $('#dictNoManifest').hidden = meta.ready !== false;
    renderTree();
    renderSelPanel();
  };

  // Когда manifest подгрузился после «Обновить сейчас» — добираем флаги
  // in_manifest для уже введённых/сохранённых selectors.
  const mergeManifestFlags = async () => {
    try {
      const configs = await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/dictionaries`);
      if (!configs.length) return;
      const flags = new Map(configs[0].selectors.map(s => [s.source_path, s.in_manifest]));
      dict.selectors.forEach(s => {
        if (flags.has(s.source_path)) s.in_manifest = flags.get(s.source_path);
      });
    } catch (_) { /* флаги только для подсветки — молча пропускаем */ }
  };

  $('#dictRefresh').addEventListener('click', async () => {
    if (!dbs.current) return;
    try {
      await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/refresh`, { method: 'POST' });
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
            await mergeManifestFlags();
            renderDict();
          } else if (tries > 20) {
            clearInterval(meta.poll);
            meta.poll = null;
            $('#dictRefreshState').textContent = 'не завершено — попробуйте позже';
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
        meta.search = await api(
          `/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/metadata?q=${encodeURIComponent(q)}`);
      } catch (error) {
        meta.search = null;
        showError($('#dictErr'), error);
      }
      renderTree();
    }, 300);
  });

  $$('#dictMode button').forEach(btn => btn.addEventListener('click', () => {
    if (btn.dataset.mode === 'all' && dict.selectors.length && dict.mode !== 'all') {
      askConfirm('Маскировать все справочники?', 'Список выбранных источников будет сброшен при сохранении.', () => {
        dict.mode = 'all';
        renderDict();
      });
    } else {
      dict.mode = btn.dataset.mode;
      renderDict();
    }
  }));
  $('#dictAdd').addEventListener('click', () => {
    $('#dictErr').hidden = true;
    const sourcePath = $('#dictPath').value.trim();
    const category = $('#dictCat').value.trim();
    let filterAst = null;
    const filterRaw = $('#dictFilter').value.trim();
    if (filterRaw && filterRaw !== 'null') {
      try {
        filterAst = JSON.parse(filterRaw);
      } catch (_) {
        showError($('#dictErr'), { message: 'Условие должно быть корректным JSON или пустым.' });
        return;
      }
    }
    if (!sourcePath || !category) {
      showError($('#dictErr'), { message: 'Заполните источник и категорию.' });
      return;
    }
    if (dict.mode === 'all') dict.mode = 'part';
    dict.selectors.push({ source_path: sourcePath, category, filter_ast: filterAst, in_manifest: null });
    if (!$('#dictCatDefault').value.trim()) $('#dictCatDefault').value = category;
    $('#dictPath').value = '';
    $('#dictCat').value = '';
    $('#dictFilter').value = '';
    renderDict();
  });
  $('#dictSave').addEventListener('click', async () => {
    if (!dbs.current) return;
    $('#dictErr').hidden = true;
    // Служебное вычисляемое поле in_manifest не уходит в контракт хранения.
    const selectors = dict.mode === 'all'
      ? [{ source_path: '*', category: '*', filter_ast: null }]
      : dict.selectors.map(s => ({ source_path: s.source_path, category: s.category, filter_ast: s.filter_ast ?? null }));
    if (!selectors.length) {
      showError($('#dictErr'), { message: 'В режиме «только выбранные» нужен хотя бы один источник.' });
      return;
    }
    if (selectors.length > 100) {
      showError($('#dictErr'), { message: `Выбрано ${selectors.length} источников — лимит конфигурации 100.` });
      return;
    }
    if (selectors.some(s => !s.category)) {
      showError($('#dictErr'), { message: 'У каждого источника должна быть заполнена категория.' });
      return;
    }
    try {
      await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/dictionaries/${encodeURIComponent(dict.id || crypto.randomUUID())}`, {
        method: 'PUT',
        body: JSON.stringify({ id: dict.id || '00000000-0000-0000-0000-000000000000', mode: dict.mode, selectors }),
      });
      await loadDict(dbs.current);
    } catch (error) {
      showError($('#dictErr'), error.status === 409
        ? { message: 'Конфигурация справочников отклонена: проверьте список источников.' }
        : error);
    }
  });

  // Правила
  let policies = [];
  const loadPolicies = async db => {
    try {
      policies = await api(`/api/v1/admin/databases/${encodeURIComponent(db.id)}/policies`);
    } catch (error) {
      if (error.status !== 401) showError($('#polErr'), error);
      return;
    }
    renderPolicies();
  };
  const renderPolicies = () => {
    const body = $('#polBody');
    body.replaceChildren();
    if (!policies.length) {
      const tr = body.insertRow();
      const td = tr.insertCell();
      td.colSpan = 4;
      td.className = 'empty';
      td.textContent = 'Версий правил пока нет';
    }
    for (const policy of policies) {
      const tr = body.insertRow();
      tr.append(el('td', '', String(policy.version)));
      const [cls, label] = POLICY_STATUS[policy.status] || ['mut', policy.status];
      const statusTd = el('td');
      statusTd.append(el('span', `tag ${cls}`, label));
      tr.append(statusTd);
      tr.append(el('td', '', String(policy.rules.length)));
      const actions = el('td');
      if (policy.status === 'draft') {
        const activate = el('button', 'btn sm', 'Сделать действующей');
        activate.type = 'button';
        activate.addEventListener('click', () => {
          askConfirm('Сделать версию действующей?', `Версия ${policy.version} начнет применяться к новым вызовам; текущая действующая версия уйдёт в архив.`, async () => {
            try {
              await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/policies/${encodeURIComponent(policy.id)}/activate`, { method: 'POST' });
              await loadPolicies(dbs.current);
            } catch (error) {
              showError($('#polErr'), error.code === 'SECRET_POLICY_UNSUPPORTED'
                ? { message: 'Версия содержит secret-правила: они недоступны до включения предменеджерной защиты.' }
                : error);
            }
          });
        });
        actions.append(activate);
      }
      const details = el('button', 'btn sm', 'Просмотр');
      details.type = 'button';
      details.classList.add('ml6');
      actions.append(details);
      tr.append(actions);
      const rulesRow = body.insertRow();
      rulesRow.hidden = true;
      const rulesCell = rulesRow.insertCell();
      rulesCell.colSpan = 4;
      const inner = el('table');
      const head = inner.createTHead().insertRow();
      ['Селектор', 'Значение', 'Действие', 'Категория', 'Приоритет'].forEach(h => head.append(el('th', '', h)));
      const innerBody = inner.createTBody();
      for (const rule of policy.rules) {
        const rr = innerBody.insertRow();
        rr.append(el('td', '', rule.selector_kind));
        rr.append(el('td', 'mono', rule.selector_value));
        rr.append(el('td', '', rule.action));
        rr.append(el('td', '', rule.category));
        rr.append(el('td', '', String(rule.priority)));
      }
      rulesCell.append(inner);
      details.addEventListener('click', () => { rulesRow.hidden = !rulesRow.hidden; });
    }
    const active = policies.find(p => p.status === 'active');
    $('#polNew').disabled = !active;
    $('#polNew').title = active ? '' : 'Нет действующей версии — нечего копировать';
  };
  $('#polNew').addEventListener('click', async () => {
    const active = policies.find(p => p.status === 'active');
    if (!active || !dbs.current) return;
    try {
      await api(`/api/v1/admin/databases/${encodeURIComponent(dbs.current.id)}/policies`, {
        method: 'POST',
        body: JSON.stringify({ rules: active.rules }),
      });
      await loadPolicies(dbs.current);
    } catch (error) {
      showError($('#polErr'), error);
    }
  });

  await loadUsers();
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
