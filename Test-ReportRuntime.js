'use strict';

const fs = require('fs');
const vm = require('vm');

const htmlPath = process.argv[2];
if (!htmlPath) throw new Error('Uso: node Test-ReportRuntime.js REPORT.html');

class ClassList {
  constructor(owner) {
    this.owner = owner;
    this.values = new Set();
  }
  add(...names) {
    names.filter(Boolean).forEach(name => this.values.add(name));
    this.owner._className = [...this.values].join(' ');
  }
  contains(name) {
    return this.values.has(name);
  }
  toggle(name, force) {
    const enabled = force === undefined ? !this.values.has(name) : Boolean(force);
    if (enabled) this.values.add(name); else this.values.delete(name);
    this.owner._className = [...this.values].join(' ');
    return enabled;
  }
  reset(value) {
    this.values = new Set(String(value || '').split(/\s+/).filter(Boolean));
  }
}

class Element {
  constructor(tagName, id = '') {
    this.tagName = String(tagName).toUpperCase();
    this.id = id;
    this.children = [];
    this.dataset = {};
    this.style = {};
    this.listeners = {};
    this.value = '';
    this.textContent = '';
    this.classList = new ClassList(this);
    this._className = '';
    this.selectedOptions = [];
  }
  set className(value) {
    this._className = String(value || '');
    this.classList.reset(this._className);
  }
  get className() {
    return this._className;
  }
  appendChild(child) {
    this.children.push(child);
    return child;
  }
  replaceChildren(...children) {
    this.children = children;
  }
  addEventListener(name, handler) {
    this.listeners[name] = handler;
  }
  click() {}
}

const ids = new Map();
const element = (tag, id) => {
  const item = new Element(tag, id);
  if (id) ids.set(id, item);
  return item;
};

[
  'headerMeta', 'themeBtn', 'printBtn', 'nav', 'summaryBody', 'postureBody',
  'licensingBody', 'recommendationsBody', 'planBody', 'operationsBody',
  'recSearch', 'recStatus', 'recPriority', 'recSort', 'recCsv'
].forEach(id => element(id.startsWith('rec') ? 'input' : 'div', id));

ids.get('recSort').value = 'priority';
ids.get('recSort').selectedOptions = [{ textContent: 'Prioridad del assessment' }];

const panelIds = ['summary', 'posture', 'licensing', 'recommendations', 'plan', 'operations'];
const panels = panelIds.map(id => {
  const item = element('section', id);
  item.classList.add('panel');
  if (id === 'summary') item.classList.add('active');
  return item;
});
const navButtons = panelIds.map(id => {
  const item = element('button');
  item.dataset.tab = id;
  if (id === 'summary') item.classList.add('active');
  return item;
});

const document = {
  documentElement: new Element('html'),
  createElement: tag => new Element(tag),
  getElementById: id => ids.get(id) || null,
  querySelectorAll: selector => {
    if (selector === '#nav button') return navButtons;
    if (selector === '.panel') return panels;
    return [];
  }
};

const storage = new Map();
const context = vm.createContext({
  document,
  window: { print() {} },
  location: { hash: '' },
  history: { replaceState() {} },
  localStorage: {
    getItem: key => storage.get(key) || null,
    setItem: (key, value) => storage.set(key, value)
  },
  URL,
  Blob,
  setTimeout,
  clearTimeout,
  console
});

const html = fs.readFileSync(htmlPath, 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match => match[1]);
if (scripts.length < 2) throw new Error('El reporte no contiene los scripts esperados.');
scripts.forEach((script, index) => vm.runInContext(script, context, { filename: `${htmlPath}:script-${index + 1}` }));

function walk(root, predicate, output = []) {
  if (predicate(root)) output.push(root);
  root.children.forEach(child => walk(child, predicate, output));
  return output;
}

const recommendationRows = walk(ids.get('recommendationsBody'), node => node.tagName === 'TBODY')
  .reduce((count, body) => count + body.children.length, 0);
const unknownEffortLabels = walk(ids.get('recommendationsBody'), node => node.textContent === 'Unknown / Unknown').length;
const normalizedMicrosoftLabels = walk(ids.get('recommendationsBody'), node => /^Esfuerzo:|^Impacto:/.test(node.textContent)).length;
const planItems = walk(ids.get('planBody'), node => node.classList.contains('plan-item')).length;
const planColumns = walk(ids.get('planBody'), node => node.classList.contains('plan-col')).length;

if (recommendationRows < 1) throw new Error('Recomendaciones no renderizó filas.');
if (unknownEffortLabels > 0) throw new Error('Recomendaciones expone Unknown / Unknown al usuario.');
if (planColumns !== 3) throw new Error(`Plan esperaba 3 columnas y renderizó ${planColumns}.`);
if (planItems < 1) throw new Error('Plan 30/60/90 no renderizó acciones.');

process.stdout.write(JSON.stringify({ recommendationRows, unknownEffortLabels, normalizedMicrosoftLabels, planColumns, planItems }));
