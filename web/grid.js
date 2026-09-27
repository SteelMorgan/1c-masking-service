'use strict';
/*++agent TASK-224 [24.09.2026] итерация 3 — изолированный табличный grid.
   Итерация 4 [08.10.2026]: сброс фильтров/поиска/сортировки, «Копировать
   всё», A−/A+ (классы dg-f-*, без inline-стилей — CSP), замок и подсветка
   маскируемых колонок (columns[].masked).

   Модуль ничего не знает о backend: вход — {columns, rows}, выход — DOM в
   переданном контейнере. Заменяется целиком: единственная точка контакта —
   глобальный MaskingGrid.create(host, options).

   options:
     columns        [{id,label,type,masked?}] — type подсказка
                    ('number','boolean','string','mixed','null'); masked —
                    колонка содержит маскированные значения (замок+подсветка);
                    фактический тип выводится по данным
     rows           массив массивов скаляров (null|boolean|number|string),
                    позиционно соответствующий columns
     renderCell?    (td, value, rowIndex, colIndex) — наполнение ячейки;
                    rowIndex/colIndex — индексы в ИСХОДНЫХ rows/columns, чтобы
                    внешний код мог сверять версии данных независимо от
                    сортировки/фильтра. По умолчанию текст «—» для null.
     exportFileName?  имя файла CSV (по умолчанию 'table.csv')
     exportRows?()  → {columns, rows} — данные для экспорта и «Копировать
                    всё»; без него выгружаются загруженные в grid строки.
                    Вызывающий отвечает за то, ЧТО экспортируется (модуль
                    сам не фильтрует реальные/маскированные версии).
     realValues?    true — на экране реальные значения (TASK-225): подписи
                    кнопок говорят «реальные», выгрузка идёт через confirmReal.
     confirmReal?(proceed)  подтверждение выгрузки реальных значений;
                    вызывающий вызывает proceed() после согласия человека.
     onRealCopied?()  уведомление: скопирована одна ячейка с реальным значением.

   instance:
     setData({columns?, rows})   — замена данных; сортировка, фильтры, поиск,
                                   видимость колонок и размер страницы живут
     setExportEnabled(on, hint)  — выкл. + видимая причина (hint) либо вкл.
     destroy()                   — снять слушатели и удалить DOM
*/
window.MaskingGrid = (() => {
  const PAGE_SIZES = [100, 200, 500, 1000];
  const DEFAULT_PAGE_SIZE = 200;
  // Размер шрифта — фиксированные классы: inline-style запрещён CSP
  // (style-src 'self'), поэтому A−/A+ переключают dg-f-* на корне.
  const FONT_CLASSES = ['dg-f-xs', 'dg-f-s', 'dg-f-m', 'dg-f-l', 'dg-f-xl'];
  const DEFAULT_FONT = 2; // dg-f-m = 14px, как раньше
  const ISO_DATE = /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?([.,]\d+)?(Z|[+-]\d{2}:?\d{2})?)?$/;

  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  //++agent TASK-224 [25.09.2026 12:10:00] итерация 5: иконки — inline SVG
  // через createElementNS (emoji-шрифта в окружении нет, внешние ресурсы
  // запрещены CSP). Пути — штрих 24x24, цвет — currentColor.
  const ICONS = {
    lock: ['M7 11V8a5 5 0 0 1 10 0v3', 'M5 11h14v10H5z'],
    search: ['M11 4a7 7 0 1 0 0 14a7 7 0 0 0 0-14z', 'M20 20l-4-4'],
    up: ['M12 19V5', 'M6 11l6-6 6 6'],
    down: ['M12 5v14', 'M6 13l6 6 6-6'],
    filter: ['M4 5h16', 'M7 12h10', 'M10 19h4'],
    cols: ['M4 5h16v14H4z', 'M10 5v14', 'M16 5v14'],
    copy: ['M9 9h11v11H9z', 'M5 15V4h11'],
    download: ['M12 4v11', 'M7 10l5 5 5-5', 'M5 20h14'],
    reset: ['M4 12a8 8 0 1 0 2.5-5.8', 'M4 4v5h5'],
    left: ['M15 6l-6 6 6 6'],
    right: ['M9 6l6 6-6 6'],
  };
  const icon = name => {
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('class', 'ico');
    svg.setAttribute('aria-hidden', 'true');
    for (const d of ICONS[name] || []) {
      const path = document.createElementNS(NS, 'path');
      path.setAttribute('d', d);
      svg.append(path);
    }
    return svg;
  };
  const iconBtn = (name, text, cls) => {
    const btn = el('button', cls || 'btn sm ghost');
    btn.type = 'button';
    btn.append(icon(name));
    if (text) btn.append(el('span', '', text));
    return btn;
  };
  // Отображение значения по типу колонки: числа — ru-разряды, булевы —
  // Да/Нет, ISO-даты — ru-формат. Сортировка/фильтр/экспорт работают по
  // исходным значениям, это только представление.
  const NUM_FMT = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 10 });
  function formatValue(value, type) {
    if (value === null || value === undefined) return '—';
    if (typeof value === 'number') return NUM_FMT.format(value);
    if (typeof value === 'boolean') return value ? 'Да' : 'Нет';
    if (type === 'date' && ISO_DATE.test(String(value))) {
      const s = String(value);
      const d = new Date(s.length > 10 ? s : `${s}T00:00:00`);
      if (!Number.isNaN(d.getTime())) {
        // Полночь без смещения — это «дата без времени» (типично для 1С).
        if (s.length <= 10 || /[T ]00:00(:00)?([.,]0+)?$/.test(s)) return d.toLocaleDateString('ru-RU');
        return d.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'medium' });
      }
    }
    return String(value);
  }
  const plural = (n, one, few, many) => {
    const m10 = n % 10;
    const m100 = n % 100;
    if (m10 === 1 && m100 !== 11) return one;
    if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
    return many;
  };
  //++agent TASK-224

  // Фактический тип колонки — по первым ~100 непустым значениям.
  function detectType(rows, col, hint) {
    if (hint === 'number' || hint === 'boolean') return hint;
    let kind = null;
    let seen = 0;
    for (const row of rows) {
      const value = row[col];
      if (value === null || value === undefined) continue;
      const t = typeof value;
      const mapped = t === 'number'
        ? 'number'
        : t === 'boolean'
          ? 'boolean'
          : ISO_DATE.test(String(value)) ? 'date' : 'string';
      if (kind === null) kind = mapped;
      else if (kind !== mapped) return 'string';
      if (++seen >= 100) break;
    }
    return kind || 'string';
  }

  function compareValues(a, b, type) {
    const aEmpty = a === null || a === undefined;
    const bEmpty = b === null || b === undefined;
    if (aEmpty || bEmpty) return aEmpty === bEmpty ? 0 : aEmpty ? 1 : -1;
    if (type === 'number') return Number(a) - Number(b);
    if (type === 'boolean') return Number(a) - Number(b);
    if (type === 'date') return Date.parse(String(a)) - Date.parse(String(b));
    return String(a).localeCompare(String(b), 'ru', { numeric: true });
  }

  // Фильтр колонки: для чисел — «a..b» (любая граница опциональна, запятая =
  // десятичный разделитель); иначе — подстрока без учёта регистра.
  function makeColumnFilter(raw, type) {
    const text = raw.trim().toLowerCase();
    if (!text) return null;
    if (type === 'number') {
      const range = text.match(/^(-?[\d\s]+[.,]?\d*)\.\.(-?[\d\s]+[.,]?\d*)$/)
        || text.match(/^\.\.(-?[\d\s]+[.,]?\d*)$/)
        || text.match(/^(-?[\d\s]+[.,]?\d*)\.\.$/);
      if (range) {
        const parse = v => (v === undefined || v === ''
          ? null
          : Number(v.replace(/\s+/g, '').replace(',', '.')));
        const lo = parse(range[1]);
        const hi = parse(range[2]);
        if (lo !== null || hi !== null) {
          return value => {
            if (typeof value !== 'number') return false;
            return (lo === null || value >= lo) && (hi === null || value <= hi);
          };
        }
      }
    }
    return value => String(value ?? '').toLowerCase().includes(text);
  }

  function toCsv(columns, rows, visible) {
    const escape = value => {
      const s = value === null || value === undefined ? '' : String(value);
      return /[";\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const lines = [columns.filter((_, i) => visible(i)).map(c => escape(c.label || c.id)).join(';')];
    for (const row of rows) {
      lines.push(row.filter((_, i) => visible(i)).map(escape).join(';'));
    }
    // BOM — чтобы Excel открыл UTF-8 корректно.
    return `\uFEFF${lines.join('\r\n')}`;
  }

  function create(host, options) {
    const state = {
      columns: options.columns || [],
      rows: options.rows || [],
      types: [],
      hidden: new Set(),
      sort: null, // {col, dir}
      filters: new Map(),
      query: '',
      page: 0,
      pageSize: DEFAULT_PAGE_SIZE,
      exportEnabled: true,
      fontIndex: DEFAULT_FONT,
    };
    const renderCell = options.renderCell
      //**agent TASK-224 [25.09.2026 12:10:00] итерация 5: форматирование по типу
      // || ((td, value) => { td.textContent = value === null || value === undefined ? '—' : String(value); });
      || ((td, value, rowIndex, colIndex, type) => { td.textContent = formatValue(value, type); });
      //**agent TASK-224

    const root = el('div', 'dg');
    const tools = el('div', 'dg-tools');
    //**agent TASK-224 [25.09.2026 12:10:00] итерация 5: панель одной строкой —
    // поиск слева; справа счётчик и вторичные ghost-кнопки с иконками;
    // причина выключенного экспорта — в title кнопок, а не абзацем.
    // (прежняя сборка панели итерации 4 заменена целиком)
    const searchBox = el('span', 'dg-searchbox');
    const search = el('input', 'input dg-search');
    search.type = 'search';
    search.placeholder = 'Поиск по таблице';
    search.maxLength = 200;
    searchBox.append(icon('search'), search);
    const count = el('span', 'dg-count');
    const resetBtn = iconBtn('reset', '', 'btn sm ghost icon');
    resetBtn.title = 'Сбросить поиск, фильтры и сортировку';
    resetBtn.setAttribute('aria-label', resetBtn.title);
    const filterBtn = iconBtn('filter', 'Фильтры');
    filterBtn.title = 'Показать строку фильтров по колонкам';
    const copyAllBtn = iconBtn('copy', 'Копировать');
    copyAllBtn.title = options.realValues // TASK-225
      ? 'Скопировать таблицу (реальные значения) в буфер'
      : 'Скопировать таблицу (маскированные значения) в буфер';
    const colWrap = el('span', 'dg-colwrap');
    const colsBtn = iconBtn('cols', 'Колонки');
    const exportBtn = iconBtn('download', 'CSV');
    exportBtn.title = options.realValues // TASK-225
      ? 'Скачать CSV (реальные значения)'
      : 'Скачать CSV (маскированные значения)';
    const fontMinus = el('button', 'btn sm ghost', 'A−');
    fontMinus.type = 'button';
    fontMinus.title = 'Уменьшить шрифт';
    const fontPlus = el('button', 'btn sm ghost', 'A+');
    fontPlus.type = 'button';
    fontPlus.title = 'Увеличить шрифт';
    const exportHint = el('span', 'dg-exphint small muted');
    exportHint.hidden = true;
    const colMenu = el('div', 'dg-drop');
    colMenu.hidden = true;
    colWrap.append(colsBtn, colMenu);
    //**agent TASK-224
    const scroll = el('div', 'dg-scroll');
    const table = el('table', 'dg-table');
    const thead = table.createTHead();
    const tbody = table.createTBody();
    const foot = el('div', 'dg-foot');
    const pageInfo = el('span', 'small muted');
    const sizeSel = el('select', 'input dg-size');
    for (const size of PAGE_SIZES) {
      const opt = el('option', '', String(size));
      opt.value = String(size);
      if (size === DEFAULT_PAGE_SIZE) opt.selected = true;
      sizeSel.append(opt);
    }
    //**agent TASK-224 [25.09.2026 12:10:00] итерация 5: стрелки пейджера — SVG
    // const prevBtn = el('button', 'btn sm', '‹');
    // const nextBtn = el('button', 'btn sm', '›');
    const prevBtn = iconBtn('left', '', 'btn sm ghost icon');
    const nextBtn = iconBtn('right', '', 'btn sm ghost icon');
    prevBtn.setAttribute('aria-label', 'Предыдущая страница');
    nextBtn.setAttribute('aria-label', 'Следующая страница');
    //**agent TASK-224
    prevBtn.type = nextBtn.type = 'button';

    //**agent TASK-224 [25.09.2026 12:10:00] итерация 5
    // tools.append(search, resetBtn, count, copyAllBtn, colWrap, exportBtn, exportHint, fontMinus, fontPlus);
    // foot.append(prevBtn, pageInfo, nextBtn, el('span', 'small muted', 'на странице:'), sizeSel);
    tools.append(searchBox, resetBtn, el('span', 'dg-sp'), count, filterBtn, colWrap,
      fontMinus, fontPlus, el('span', 'dg-sep'), copyAllBtn, exportBtn);
    foot.append(el('span', '', 'Строк на странице'), sizeSel, prevBtn, pageInfo, nextBtn);
    filterBtn.addEventListener('click', () => {
      const on = !table.classList.contains('dg-showf');
      table.classList.toggle('dg-showf', on);
      filterBtn.classList.toggle('on', on);
      filterBtn.setAttribute('aria-pressed', String(on));
    });
    //**agent TASK-224
    scroll.append(table);
    root.append(tools, scroll, foot);
    host.append(root);

    let debounce = null;
    const schedule = () => {
      clearTimeout(debounce);
      debounce = setTimeout(renderRows, 150);
    };

    const closeMenu = event => {
      if (!root.contains(event.target)) colMenu.hidden = true;
    };
    document.addEventListener('click', closeMenu);

    function visibleColumns() {
      return state.columns.map((c, i) => ({ c, i })).filter(({ c }) => !state.hidden.has(c.id ?? c.label));
    }

    function view() {
      const active = [];
      for (const { i } of visibleColumns()) {
        const fn = makeColumnFilter(state.filters.get(i) || '', state.types[i]);
        if (fn) active.push({ i, fn });
      }
      const query = state.query.trim().toLowerCase();
      const visibleIdx = visibleColumns().map(({ i }) => i);
      let out = state.rows
        .map((cells, i) => ({ i, cells }))
        .filter(({ cells }) =>
          active.every(({ i, fn }) => fn(cells[i]))
          && (!query || visibleIdx.some(i => String(cells[i] ?? '').toLowerCase().includes(query))));
      if (state.sort) {
        const { col, dir } = state.sort;
        const type = state.types[col];
        out = out.slice().sort((a, b) => dir * compareValues(a.cells[col], b.cells[col], type));
      }
      return out;
    }

    // Шапка собирается только при смене колонок — иначе ввод в фильтре
    // терял бы фокус на каждом дебаунсе. Стрелки сортировки живут в
    // sortMarks и обновляются отдельно.
    const sortMarks = new Map();
    //**agent TASK-224 [25.09.2026 12:10:00] итерация 5: стрелка — SVG-иконка
    // function markFor(i) {
    //   if (!state.sort || state.sort.col !== i) return ' ';
    //   return state.sort.dir === 1 ? '▲' : '▼';
    // }
    function markFor(i, node) {
      node.replaceChildren();
      const on = state.sort && state.sort.col === i;
      if (node.parentNode) node.parentNode.classList.toggle('sorted', !!on);
      if (on) node.append(icon(state.sort.dir === 1 ? 'up' : 'down'));
    }
    //**agent TASK-224

    //**agent TASK-224 [25.09.2026 12:10:00] итерация 5: шапка — две строки:
    // заголовки (замок SVG + акцентная полоса у маскируемых) и строка
    // фильтров, скрытая по умолчанию (кнопка «Фильтры»). Прежняя
    // однострочная шапка итераций 3-4 заменена целиком.
    function renderHead() {
      thead.replaceChildren();
      sortMarks.clear();
      const tr = thead.insertRow();
      const fr = thead.insertRow();
      fr.className = 'dg-frow';
      for (const { c, i } of visibleColumns()) {
        const th = el('th');
        const isNum = state.types[i] === 'number';
        if (isNum) th.classList.add('dg-num');
        const sortBtn = el('button', 'dg-sort');
        sortBtn.type = 'button';
        const arrow = el('span', 'dg-arrow');
        sortMarks.set(i, arrow);
        if (c.masked) {
          th.classList.add('dg-th-masked');
          const lock = el('span', 'dg-lock');
          lock.append(icon('lock'));
          lock.title = 'Колонка содержит маскированные значения';
          sortBtn.append(lock);
        }
        sortBtn.append(el('span', '', c.label || c.id), arrow);
        markFor(i, arrow);
        sortBtn.title = 'Сортировать';
        sortBtn.addEventListener('click', () => {
          if (state.sort && state.sort.col === i) {
            state.sort = state.sort.dir === 1 ? { col: i, dir: -1 } : null;
          } else {
            state.sort = { col: i, dir: 1 };
          }
          sortMarks.forEach((node, col) => markFor(col, node));
          renderRows();
        });
        th.append(sortBtn);
        tr.append(th);
        const fth = el('th');
        const filter = el('input', 'dg-filter');
        filter.type = 'search';
        filter.placeholder = isNum ? 'от..до' : 'фильтр…';
        filter.maxLength = 200;
        filter.value = state.filters.get(i) || '';
        filter.setAttribute('aria-label', `Фильтр: ${c.label || c.id}`);
        filter.addEventListener('input', () => {
          if (filter.value) state.filters.set(i, filter.value);
          else state.filters.delete(i);
          state.page = 0;
          schedule();
        });
        fth.append(filter);
        fr.append(fth);
      }
    }
    //**agent TASK-224

    function renderMenu() {
      colMenu.replaceChildren();
      for (const c of state.columns) {
        const key = c.id ?? c.label;
        const label = el('label', 'dg-col');
        const cb = el('input');
        cb.type = 'checkbox';
        cb.checked = !state.hidden.has(key);
        cb.addEventListener('change', () => {
          if (cb.checked) state.hidden.delete(key);
          else state.hidden.add(key);
          state.page = 0;
          renderAll();
        });
        label.append(cb, document.createTextNode(` ${c.label || c.id}`));
        colMenu.append(label);
      }
    }

    function renderBody(slice) {
      tbody.replaceChildren();
      if (!slice.length) {
        const td = tbody.insertRow().insertCell();
        td.colSpan = Math.max(1, visibleColumns().length);
        td.className = 'empty';
        td.textContent = state.rows.length ? 'Ничего не найдено' : 'Нет данных';
        return;
      }
      for (const { i: rowIndex, cells } of slice) {
        const tr = tbody.insertRow();
        for (const { i: colIndex } of visibleColumns()) {
          const td = tr.insertCell();
          const value = cells[colIndex];
          //++agent TASK-224 [08.10.2026] итерация 4: подсветка колонки
          // с маскированными значениями (эт. reference-grid).
          //**agent TASK-224 [25.09.2026 12:10:00] итерация 5: без заливки
          // маскируемых колонок — признак только в шапке; класс по типу.
          // if (state.columns[colIndex] && state.columns[colIndex].masked) {
          //   td.classList.add('dg-masked');
          // }
          const type = state.types[colIndex];
          if (value === null || value === undefined) td.classList.add('dg-null');
          else if (type === 'number' && typeof value === 'number') td.classList.add('dg-num');
          else if (value === false) td.classList.add('dg-bool-no');
          //**agent TASK-224
          //--agent TASK-224
          td.addEventListener('click', () => {
            const raw = value === null || value === undefined ? '' : String(value);
            if (navigator.clipboard && window.isSecureContext) {
              navigator.clipboard.writeText(raw).then(() => flash(td), () => flash(td));
            }
            //++agent TASK-225 [27.09.2026 09:16:39] одна ячейка — без модалки,
            // но человек должен видеть, что взял реальное значение.
            if (options.realValues && options.onRealCopied) options.onRealCopied();
            //++agent TASK-225
            function flash(node) {
              node.classList.add('dg-copied');
              setTimeout(() => node.classList.remove('dg-copied'), 600);
            }
          });
          td.title = 'Клик — скопировать значение';
          renderCell(td, value, rowIndex, colIndex, state.types[colIndex]);
        }
      }
    }

    // Тело/счётчик/пейджер — без трогания шапки (фокус фильтров живёт).
    function renderRows() {
      const rows = view();
      const totalPages = Math.max(1, Math.ceil(rows.length / state.pageSize));
      state.page = Math.min(state.page, totalPages - 1);
      const start = state.page * state.pageSize;
      renderBody(rows.slice(start, start + state.pageSize));
      //**agent TASK-224 [25.09.2026 12:10:00] итерация 5: компактный счётчик
      // count.textContent = `Показано ${rows.length.toLocaleString('ru-RU')} из ${state.rows.length.toLocaleString('ru-RU')}`;
      count.textContent = rows.length === state.rows.length
        ? `${rows.length.toLocaleString('ru-RU')} ${plural(rows.length, 'строка', 'строки', 'строк')}`
        : `${rows.length.toLocaleString('ru-RU')} из ${state.rows.length.toLocaleString('ru-RU')}`;
      //**agent TASK-224
      const many = rows.length > PAGE_SIZES[0];
      foot.hidden = !many;
      pageInfo.textContent = `${state.page + 1}/${totalPages}`;
      prevBtn.disabled = state.page === 0;
      nextBtn.disabled = state.page >= totalPages - 1;
    }

    function renderAll() {
      renderHead();
      renderRows();
    }

    search.addEventListener('input', () => {
      state.query = search.value;
      state.page = 0;
      schedule();
    });
    //++agent TASK-224 [08.10.2026] итерация 4
    root.classList.add(FONT_CLASSES[state.fontIndex]);
    const setFont = index => {
      root.classList.remove(FONT_CLASSES[state.fontIndex]);
      state.fontIndex = Math.min(FONT_CLASSES.length - 1, Math.max(0, index));
      root.classList.add(FONT_CLASSES[state.fontIndex]);
      fontMinus.disabled = state.fontIndex === 0;
      fontPlus.disabled = state.fontIndex === FONT_CLASSES.length - 1;
    };
    fontMinus.disabled = false;
    fontPlus.disabled = false;
    fontMinus.addEventListener('click', () => setFont(state.fontIndex - 1));
    fontPlus.addEventListener('click', () => setFont(state.fontIndex + 1));
    resetBtn.addEventListener('click', () => {
      state.query = '';
      search.value = '';
      state.filters.clear();
      state.sort = null;
      state.page = 0;
      renderAll(); // шапка нужна: поля фильтров и стрелки сортировки чистятся
    });
    //++agent TASK-225 [27.09.2026 09:16:39] выгрузка реальных значений —
    // осознанное действие человека: подтверждение решает вызывающий
    // (options.confirmReal), модуль лишь не обходит его.
    const guardReal = action => {
      if (options.realValues && options.confirmReal) options.confirmReal(action);
      else action();
    };
    //++agent TASK-225
    copyAllBtn.addEventListener('click', () => guardReal(() => {
      //**agent TASK-225 [27.09.2026 09:16:39]
      // // То же правило, что у CSV: данные просит вызывающий — при раскрытом
      // // виде сюда подаются маскированные строки, не реальные.
      // Данные просит вызывающий: выгружается то, что на экране.
      //**agent TASK-225
      const data = options.exportRows ? options.exportRows() : { columns: state.columns, rows: state.rows };
      const visibleIdx = new Set(visibleColumns().map(({ i }) => i));
      const text = data.columns
        .map((c, i) => ({ c, i }))
        .filter(({ i }) => visibleIdx.has(i))
        .map(({ c }) => c.label || c.id)
        .join('\t')
        + '\n'
        + data.rows
          .map(row => row.filter((_, i) => visibleIdx.has(i))
            .map(value => (value === null || value === undefined ? '' : String(value)).replace(/[\t\r\n]+/g, ' '))
            .join('\t'))
          .join('\n');
      //**agent TASK-224 [25.09.2026 12:10:00] итерация 5: подпись внутри span
      const label = copyAllBtn.querySelector('span');
      const done = () => {
        label.textContent = 'Скопировано';
        setTimeout(() => { label.textContent = 'Копировать'; }, 1200);
      };
      //**agent TASK-224
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
    })); // TASK-225: guardReal
    //--agent TASK-224
    colsBtn.addEventListener('click', event => {
      event.stopPropagation();
      colMenu.hidden = !colMenu.hidden;
      if (!colMenu.hidden) renderMenu();
    });
    prevBtn.addEventListener('click', () => { state.page -= 1; renderRows(); });
    nextBtn.addEventListener('click', () => { state.page += 1; renderRows(); });
    sizeSel.addEventListener('change', () => {
      state.pageSize = Number(sizeSel.value);
      state.page = 0;
      renderRows();
    });
    exportBtn.addEventListener('click', () => guardReal(() => {
      if (!state.exportEnabled) return;
      const data = options.exportRows ? options.exportRows() : { columns: state.columns, rows: state.rows };
      const visibleIdx = new Set(visibleColumns().map(({ i }) => i));
      const csv = toCsv(data.columns, data.rows, i => visibleIdx.has(i));
      const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
      const a = el('a');
      a.href = url;
      a.download = options.exportFileName || 'table.csv';
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    })); // TASK-225: guardReal

    state.types = state.columns.map((c, i) => detectType(state.rows, i, c.type));
    renderAll();

    return {
      element: root,
      setData(next) {
        if (next.columns) state.columns = next.columns;
        if (next.rows) state.rows = next.rows;
        state.types = state.columns.map((c, i) => detectType(state.rows, i, c.type));
        state.page = 0;
        renderAll();
      },
      setExportEnabled(enabled, hint) {
        state.exportEnabled = enabled;
        exportBtn.disabled = !enabled;
        //++agent TASK-224 [08.10.2026] «Копировать всё» — тот же контракт,
        // что у CSV: при показе реальных значений выключено.
        copyAllBtn.disabled = !enabled;
        //--agent TASK-224
        //**agent TASK-224 [25.09.2026 12:10:00] итерация 5: причина — tooltip
        // exportHint.hidden = enabled || !hint;
        // exportHint.textContent = hint || '';
        exportHint.hidden = true;
        //**agent TASK-225 [27.09.2026 09:16:39] подпись по тому, что на экране
        // exportBtn.title = enabled ? 'Скачать CSV (маскированные значения)' : (hint || 'Экспорт недоступен');
        // copyAllBtn.title = enabled ? 'Скопировать таблицу (маскированные значения) в буфер' : (hint || 'Копирование недоступно');
        const kind = options.realValues ? 'реальные значения' : 'маскированные значения';
        exportBtn.title = enabled ? `Скачать CSV (${kind})` : (hint || 'Экспорт недоступен');
        copyAllBtn.title = enabled ? `Скопировать таблицу (${kind}) в буфер` : (hint || 'Копирование недоступно');
        //**agent TASK-225
        //**agent TASK-224
      },
      destroy() {
        clearTimeout(debounce);
        document.removeEventListener('click', closeMenu);
        root.remove();
      },
    };
  }

  return { create, formatValue, icon };
})();
/*--agent TASK-224*/
