'use strict';

const statusNode = document.querySelector('#status');
const csrfKey = 'masking-csrf';

function status(message) {
  if (statusNode) statusNode.textContent = message;
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set('Content-Type', 'application/json');
  if (options.method && options.method !== 'GET') {
    const csrf = sessionStorage.getItem(csrfKey);
    if (csrf) headers.set('X-CSRF-Token', csrf);
  }
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store' });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.error?.message || 'Операция не выполнена');
  }
  if (response.status === 204 || response.status === 202) return null;
  return response.json();
}

function button(label, action) {
  const node = document.createElement('button');
  node.type = 'button';
  node.textContent = label;
  node.addEventListener('click', action);
  return node;
}

function renderTable(target, columns, rows) {
  target.replaceChildren();
  const table = document.createElement('table');
  const head = table.createTHead().insertRow();
  for (const column of columns) {
    const cell = document.createElement('th');
    cell.scope = 'col';
    cell.textContent = column.label;
    head.append(cell);
  }
  const body = table.createTBody();
  for (const row of rows) {
    const tr = body.insertRow();
    for (const value of row) {
      const td = tr.insertCell();
      td.textContent = value === null ? '' : String(value);
    }
  }
  target.append(table);
}

function renderReport(target, report) {
  target.replaceChildren();
  if (!report || report.version !== 1 || !Array.isArray(report.blocks)) return;
  for (const block of report.blocks) {
    if (block.kind === 'text' && typeof block.text === 'string') {
      const text = document.createElement('pre');
      text.textContent = block.text;
      target.append(text);
    } else if (block.kind === 'table' && Array.isArray(block.columns) && Array.isArray(block.rows)) {
      const holder = document.createElement('div');
      renderTable(holder, block.columns, block.rows);
      target.append(holder);
    }
  }
}

async function loginPage() {
  document.querySelector('#login-form').addEventListener('submit', async event => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const session = await request('/auth/login', { method: 'POST', body: JSON.stringify({ login: form.get('login'), password: form.get('password') }) });
      sessionStorage.setItem(csrfKey, session.csrf_token);
      location.assign(session.role === 'Viewer' ? '/viewer' : '/admin');
    } catch (error) { status(error.message); }
  });
}

function wireLogout() {
  document.querySelector('#logout')?.addEventListener('click', async () => {
    try { await request('/auth/logout', { method: 'POST' }); } catch (_) { /* local cleanup still applies */ }
    sessionStorage.removeItem(csrfKey);
    location.assign('/');
  });
}

function wirePasswordChange() {
  document.querySelector('#change-password')?.addEventListener('submit', async event => {
    event.preventDefault();
    const formNode = event.currentTarget;
    const form = new FormData(formNode);
    if (form.get('new_password') !== form.get('confirmation')) {
      status('Новые пароли не совпадают');
      return;
    }
    try {
      const session = await request('/api/v1/session/password', {
        method: 'POST',
        body: JSON.stringify({
          current_password: form.get('current_password'),
          new_password: form.get('new_password')
        })
      });
      sessionStorage.setItem(csrfKey, session.csrf_token);
      formNode.reset();
      status('Пароль изменён; остальные сеансы завершены');
    } catch (error) {
      formNode.reset();
      status(error.message);
    }
  });
}

async function viewerPage() {
  wireLogout();
  wirePasswordChange();
  const dbTarget = document.querySelector('#databases');
  const chatTarget = document.querySelector('#chats');
  const historyTarget = document.querySelector('#history');
  const reportTarget = document.querySelector('#report');
  try {
    const databases = await request('/api/v1/databases');
    for (const database of databases) {
      dbTarget.append(button(`${database.label} (${database.mode})`, async () => {
        chatTarget.replaceChildren(); historyTarget.replaceChildren(); reportTarget.replaceChildren();
        const chats = await request(`/api/v1/chats?database_id=${encodeURIComponent(database.id)}`);
        for (const chat of chats) {
          chatTarget.append(button(`${chat.chat_id} — ${chat.message_count}`, async () => {
            historyTarget.replaceChildren(); reportTarget.replaceChildren();
            const items = await request(`/api/v1/history?database_id=${encodeURIComponent(database.id)}&chat_id=${encodeURIComponent(chat.chat_id)}&limit=50`);
            for (const item of items) {
              historyTarget.append(button(`${item.created_at} — ${item.tool_name}`, () => {
                renderReport(reportTarget, item.report);
                reportTarget.append(button('Раскрыть доступные значения', async () => {
                  try { renderReport(reportTarget, await request(`/api/v1/history/${encodeURIComponent(item.id)}/reveal`, { method: 'POST' })); }
                  catch (error) { status(error.message); }
                }));
              }));
            }
          }));
        }
      }));
    }
  } catch (error) { status(error.message); }
}

async function adminPage() {
  wireLogout();
  wirePasswordChange();
  const usersTarget = document.querySelector('#users');
  const dbTarget = document.querySelector('#admin-databases');

  async function loadUsers() {
    const users = await request('/api/v1/admin/users');
    usersTarget.replaceChildren();
    for (const user of users) {
      const form = document.createElement('form');
      form.className = 'inline-card';
      const title = document.createElement('strong');
      title.textContent = `${user.login} — ${user.activated ? 'активирован' : 'ожидает активации'}`;
      const role = selectInput('role', ['Admin', 'Viewer'], user.role);
      const userStatus = selectInput('status', ['active', 'disabled'], user.status);
      form.append(title, labeled('Роль', role), labeled('Статус', userStatus));
      const save = document.createElement('button');
      save.type = 'submit'; save.textContent = 'Сохранить пользователя'; form.append(save);
      form.addEventListener('submit', async event => {
        event.preventDefault();
        try {
          await request(`/api/v1/admin/users/${encodeURIComponent(user.user_id)}`, {
            method: 'PATCH', body: JSON.stringify({ role: role.value, status: userStatus.value })
          });
          status('Пользователь обновлён'); await loadUsers();
        } catch (error) { status(error.message); }
      });
      usersTarget.append(form);
    }
  }

  document.querySelector('#create-user').addEventListener('submit', async event => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const created = await request('/api/v1/admin/users', { method: 'POST', body: JSON.stringify({ login: form.get('login'), role: form.get('role') }) });
      document.querySelector('#activation').textContent = `Одноразовый activation token (показывается только сейчас): ${created.activation_token}`;
      event.currentTarget.reset();
      await loadUsers();
    } catch (error) { status(error.message); }
  });

  try {
    await loadUsers();
    const databases = await request('/api/v1/admin/databases');
    dbTarget.replaceChildren();
    for (const database of databases) {
      const card = document.createElement('section');
      card.className = 'admin-db';
      const heading = document.createElement('h3');
      heading.textContent = `${database.label} (${database.id})`;
      card.append(heading);

      const settings = document.createElement('form');
      settings.className = 'settings-grid';
      const mode = selectInput('mode', ['enabled', 'disabled'], database.mode);
      settings.append(labeled('Режим', mode));
      for (const [name, label, current] of [
        ['mapping_ttl_seconds', 'Mapping TTL, сек.', database.mapping_ttl_seconds],
        ['history_ttl_seconds', 'History retention, сек.', database.history_ttl_seconds]
      ]) {
        const input = document.createElement('input'); input.name = name; input.type = 'number'; input.min = '1'; input.required = true; input.value = String(current);
        settings.append(labeled(label, input));
      }
      const save = document.createElement('button'); save.type = 'submit'; save.textContent = 'Сохранить режим и TTL'; settings.append(save);
      settings.append(button('Запустить refresh', async () => {
        try { await request(`/api/v1/admin/databases/${encodeURIComponent(database.id)}/refresh`, { method: 'POST' }); status('Обновление принято'); }
        catch (error) { status(error.message); }
      }));
      settings.addEventListener('submit', async event => {
        event.preventDefault(); const values = new FormData(settings);
        try {
          await request(`/api/v1/admin/databases/${encodeURIComponent(database.id)}`, { method: 'PATCH', body: JSON.stringify({
            mode: values.get('mode'), mapping_ttl_seconds: Number(values.get('mapping_ttl_seconds')), history_ttl_seconds: Number(values.get('history_ttl_seconds'))
          }) });
          status('Настройки сохранены');
        } catch (error) { status(error.message); }
      });
      card.append(settings);

      card.append(sectionHeading('Классификация tools'));
      const toolsTarget = document.createElement('div'); card.append(toolsTarget);
      await loadTools(database.id, toolsTarget);

      card.append(sectionHeading('Dictionary configuration'));
      const dictionariesTarget = document.createElement('div'); card.append(dictionariesTarget);
      await loadDictionary(database.id, dictionariesTarget);

      card.append(sectionHeading('Policy versions и rules'));
      const policiesTarget = document.createElement('div'); card.append(policiesTarget);
      await loadPolicies(database.id, policiesTarget);
      dbTarget.append(card);
    }
  } catch (error) { status(error.message); }
}

function sectionHeading(text) {
  const heading = document.createElement('h4'); heading.textContent = text; return heading;
}

function labeled(text, control) {
  const holder = document.createElement('label'); holder.append(document.createTextNode(`${text} `), control); return holder;
}

function selectInput(name, values, selected) {
  const node = document.createElement('select'); node.name = name;
  for (const value of values) {
    const option = document.createElement('option'); option.value = value; option.textContent = value; option.selected = value === selected; node.append(option);
  }
  return node;
}

async function loadTools(databaseId, target) {
  const tools = await request(`/api/v1/admin/databases/${encodeURIComponent(databaseId)}/tools`);
  target.replaceChildren();
  for (const tool of tools) {
    const form = document.createElement('form'); form.className = 'inline-card';
    const classification = selectInput('class', ['data-mask', 'metadata-bypass', 'deny-pending-review'], tool.class);
    const save = document.createElement('button'); save.type = 'submit'; save.textContent = 'Сохранить';
    form.append(labeled(tool.tool_name, classification), save);
    form.addEventListener('submit', async event => {
      event.preventDefault();
      try {
        await request(`/api/v1/admin/databases/${encodeURIComponent(databaseId)}/tools/${encodeURIComponent(tool.tool_name)}`, {
          method: 'PUT', body: JSON.stringify({ class: classification.value })
        });
        status(`Класс tool ${tool.tool_name} сохранён`);
      } catch (error) { status(error.message); }
    });
    target.append(form);
  }
}

function dictionarySelectorRow(selector = {}) {
  const row = document.createElement('div'); row.className = 'selector-row';
  const source = document.createElement('input'); source.name = 'source_path'; source.required = true; source.maxLength = 512; source.value = selector.source_path || '';
  const category = document.createElement('input'); category.name = 'category'; category.required = true; category.maxLength = 32; category.value = selector.category || '';
  const filter = document.createElement('textarea'); filter.name = 'filter_ast'; filter.rows = 2; filter.placeholder = 'null или JSON AST'; filter.value = selector.filter_ast == null ? '' : JSON.stringify(selector.filter_ast);
  row.append(labeled('Source path', source), labeled('Категория', category), labeled('Filter AST', filter));
  row.append(button('Удалить selector', () => row.remove()));
  return row;
}

async function loadDictionary(databaseId, target) {
  const configs = await request(`/api/v1/admin/databases/${encodeURIComponent(databaseId)}/dictionaries`);
  const config = configs[0] || { id: crypto.randomUUID(), mode: 'part', selectors: [] };
  const form = document.createElement('form'); form.className = 'stack-card';
  const mode = selectInput('dictionary_mode', ['part', 'all'], config.mode);
  const rows = document.createElement('div'); rows.className = 'selector-list';
  for (const selector of config.selectors) rows.append(dictionarySelectorRow(selector));
  if (!config.selectors.length) rows.append(dictionarySelectorRow());
  form.append(labeled('Режим dictionary', mode), rows, button('Добавить selector', () => rows.append(dictionarySelectorRow())));
  const save = document.createElement('button'); save.type = 'submit'; save.textContent = 'Сохранить dictionary'; form.append(save);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const selectors = [...rows.querySelectorAll('.selector-row')].map(row => {
        const rawFilter = row.querySelector('[name="filter_ast"]').value.trim();
        return {
          source_path: row.querySelector('[name="source_path"]').value.trim(),
          category: row.querySelector('[name="category"]').value.trim(),
          filter_ast: rawFilter ? JSON.parse(rawFilter) : null
        };
      });
      if (mode.value === 'all') {
        selectors.splice(0, selectors.length, { source_path: '*', category: selectors[0]?.category || 'DEFAULT', filter_ast: selectors[0]?.filter_ast ?? null });
      }
      await request(`/api/v1/admin/databases/${encodeURIComponent(databaseId)}/dictionaries/${encodeURIComponent(config.id)}`, {
        method: 'PUT', body: JSON.stringify({ id: config.id, mode: mode.value, selectors })
      });
      status('Dictionary configuration сохранена'); await loadDictionary(databaseId, target);
    } catch (error) { status(error instanceof SyntaxError ? 'Filter AST должен быть корректным JSON' : error.message); }
  });
  target.replaceChildren(form);
}

function policyRuleRow(rule = {}) {
  const row = document.createElement('div'); row.className = 'rule-row';
  const kind = selectInput('selector_kind', ['source_path', 'name', 'type', 'dictionary', 'regex'], rule.selector_kind || 'name');
  const value = document.createElement('input'); value.name = 'selector_value'; value.required = true; value.maxLength = 1024; value.value = rule.selector_value || '';
  const action = selectInput('action', ['keep', 'mask', 'secret'], rule.action || 'mask');
  const category = document.createElement('input'); category.name = 'category'; category.required = true; category.maxLength = 32; category.value = rule.category || '';
  const priority = document.createElement('input'); priority.name = 'priority'; priority.type = 'number'; priority.value = String(rule.priority || 0);
  row.append(labeled('Selector', kind), labeled('Значение', value), labeled('Action', action), labeled('Категория', category), labeled('Priority', priority));
  row.append(button('Удалить rule', () => row.remove()));
  return row;
}

async function loadPolicies(databaseId, target) {
  const policies = await request(`/api/v1/admin/databases/${encodeURIComponent(databaseId)}/policies`);
  target.replaceChildren();
  for (const policy of policies) {
    const article = document.createElement('article'); article.className = 'inline-card';
    const title = document.createElement('strong'); title.textContent = `Версия ${policy.version} — ${policy.status}`; article.append(title);
    const list = document.createElement('ul');
    for (const rule of policy.rules) {
      const item = document.createElement('li'); item.textContent = `${rule.selector_kind}: ${rule.selector_value} → ${rule.action} (${rule.category}, priority ${rule.priority})`; list.append(item);
    }
    article.append(list);
    if (policy.status !== 'active') article.append(button('Активировать версию', async () => {
      try {
        await request(`/api/v1/admin/databases/${encodeURIComponent(databaseId)}/policies/${encodeURIComponent(policy.id)}/activate`, { method: 'POST' });
        status('Policy активирована'); await loadPolicies(databaseId, target);
      } catch (error) { status(error.message); }
    }));
    target.append(article);
  }
  const form = document.createElement('form'); form.className = 'stack-card';
  const rows = document.createElement('div'); rows.className = 'rule-list'; rows.append(policyRuleRow());
  form.append(rows, button('Добавить rule', () => rows.append(policyRuleRow())));
  const create = document.createElement('button'); create.type = 'submit'; create.textContent = 'Создать новую policy version'; form.append(create);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const rules = [...rows.querySelectorAll('.rule-row')].map(row => ({
      selector_kind: row.querySelector('[name="selector_kind"]').value,
      selector_value: row.querySelector('[name="selector_value"]').value.trim(),
      action: row.querySelector('[name="action"]').value,
      category: row.querySelector('[name="category"]').value.trim(),
      priority: Number(row.querySelector('[name="priority"]').value)
    }));
    try {
      await request(`/api/v1/admin/databases/${encodeURIComponent(databaseId)}/policies`, { method: 'POST', body: JSON.stringify({ rules }) });
      status('Новая policy version создана'); await loadPolicies(databaseId, target);
    } catch (error) { status(error.message); }
  });
  target.append(form);
}

async function activationPage() {
  const token = decodeURIComponent(location.pathname.split('/').pop() || '');
  document.querySelector('#activate-form').addEventListener('submit', async event => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (form.get('password') !== form.get('confirmation')) {
      status('Пароли не совпадают');
      return;
    }
    try {
      await request(`/auth/activate/${encodeURIComponent(token)}`, {
        method: 'POST',
        headers: { 'X-CSRF-Token': token },
        body: JSON.stringify({ password: form.get('password') })
      });
      history.replaceState(null, '', '/');
      location.replace('/');
    } catch (error) { status(error.message); }
  });
}

const page = document.body.dataset.page;
if (page === 'login') loginPage();
if (page === 'viewer') viewerPage();
if (page === 'admin') adminPage();
if (page === 'activate') activationPage();
