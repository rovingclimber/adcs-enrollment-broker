'use strict';
const $ = id => document.getElementById(id);
let session, scenarioIndex = 0, revealed = 0, timer, snapshotHash = '', selectedEventId;

const components = [
  { id: 'ad', label: 'Active Directory', matches: event => /active directory/i.test(event.source) },
  { id: 'adcs', label: 'AD CS', matches: event => /ad cs|certificate authority/i.test(event.source) },
  { id: 'broker', label: 'Broker', matches: event => /broker|signer/i.test(event.source) },
  { id: 'facts', label: 'Facts service', matches: event => /facts/i.test(event.source) },
  { id: 'radius', label: 'FreeRADIUS', matches: event => /radius/i.test(event.source) },
  { id: 'unifi', label: 'UniFi', matches: event => /unifi|controller/i.test(event.source) }
];

function statusClass(element, status) {
  element.className = element.className.split(' ').filter(value =>
    !['pending','active','success','warning','denied','recorded','connected','waiting','stale','offline'].includes(value)).join(' ');
  element.classList.add(status);
}
function isLive() { return session?.mode === 'live'; }
function currentScenario() { return session.scenarios[scenarioIndex]; }
function allEvents() {
  if (!session) return [];
  return session.scenarios.flatMap(scenario => scenario.events.map(event => ({ event, scenario })))
    .sort((left, right) => new Date(right.event.atUtc) - new Date(left.event.atUtc));
}
function appendFields(target, fields, limit) {
  target.replaceChildren();
  Object.entries(fields || {}).slice(0, limit || 99).forEach(([name, value]) => {
    const row = document.createElement('div'), term = document.createElement('dt'), definition = document.createElement('dd');
    term.textContent = name; definition.textContent = value ?? '—'; row.append(term, definition); target.append(row);
  });
}

function renderMode() {
  const live = isLive();
  $('provenance').classList.toggle('live', live);
  $('provenance-title').textContent = live ? 'Live sanitized evidence feed' : 'Recorded evidence replay';
  $('provenance-text').textContent = live
    ? 'Collectors are reading the real lab components. Each line below is fresh bounded evidence from this session; raw secrets and key material remain at source.'
    : 'This page replays a sanitized evidence bundle. Timestamps describe the original capture, not current component activity.';
  $('mode-tag').textContent = live ? 'LIVE COLLECTORS' : 'SANITIZED REPLAY';
  $('live-dashboard').hidden = !live;
  $('story-view').hidden = live;
  $('controls').hidden = live;
  $('updated').textContent = (live ? 'Feed updated ' : 'Captured ') + new Date(session.updatedUtc).toLocaleString();
}

function renderSources() {
  $('sources').replaceChildren();
  const sources = session?.sources || [];
  sources.forEach(source => {
    const card = document.createElement('article'); card.className = 'source-card ' + source.status;
    const head = document.createElement('div'), name = document.createElement('strong'), state = document.createElement('span');
    name.textContent = source.label; state.textContent = source.status; state.className = 'pill ' + source.status; head.append(name, state);
    const detail = document.createElement('p'); detail.textContent = source.detail || 'Collector reported no detail.';
    const time = document.createElement('time'); time.dateTime = source.observedUtc;
    const age = Math.max(0, Math.round((Date.now() - new Date(source.observedUtc).getTime()) / 1000));
    time.textContent = age < 2 ? 'observed now' : `observed ${age}s ago`;
    card.append(head, detail, time); $('sources').append(card);
  });
  $('source-title').textContent = sources.length ? 'Evidence collectors' : (isLive() ? 'Waiting for collector state' : 'Replay source inventory');
}

function latestFor(predicate) { return allEvents().find(item => predicate(item.event)); }
function renderDecisionCard(cardId, titleId, detailId, fieldsId, item, emptyTitle, emptyDetail) {
  const card = $(cardId);
  if (!item) {
    statusClass(card, 'waiting'); $(titleId).textContent = emptyTitle; $(detailId).textContent = emptyDetail; $(fieldsId).replaceChildren(); return;
  }
  statusClass(card, item.event.status);
  $(titleId).textContent = item.event.title; $(detailId).textContent = item.event.detail;
  appendFields($(fieldsId), item.event.fields);
}
function renderDecisions() {
  const authorization = latestFor(event => /radius/i.test(event.source) && event.stage === 'network') ??
    latestFor(event => /radius/i.test(event.source) && (event.fields?.VLAN || event.fields?.decision));
  renderDecisionCard('authorization-card', 'authorization-title', 'authorization-detail', 'authorization-fields', authorization,
    'Waiting for EAP-TLS', 'No fresh RADIUS policy or Access-Accept/Reject has arrived in this live session.');
  const attachment = latestFor(event => /unifi|controller/i.test(event.source));
  renderDecisionCard('attachment-card', 'attachment-title', 'attachment-detail', 'attachment-fields', attachment,
    'Waiting for station', 'The controller source is connected but has not reported this station in the live session.');
}

function livePathBadge(event, scenario) {
  const badge = document.createElement('span');
  const unclassified = event.fields?.['policy correlation'] === 'unclassified';
  const enrollmentLabel = scenario.id === 'native' ? 'DIRECT' : 'BROKER';
  badge.className = unclassified ? 'path-tag' : `path-tag ${scenario.id}`;
  badge.textContent = unclassified ? 'UNCLASSIFIED' : enrollmentLabel;
  return badge;
}

function renderComponentGrid() {
  const events = allEvents(), sources = session.sources || [];
  $('component-grid').replaceChildren();
  components.forEach(component => {
    const source = sources.find(value => value.id === component.id);
    const matches = events.filter(item => component.matches(item.event));
    const card = document.createElement('article'); card.className = `component-card ${source?.status || 'waiting'}`;
    const head = document.createElement('div'), title = document.createElement('h3'), state = document.createElement('span');
    title.textContent = component.label; state.textContent = source?.status || 'waiting'; state.className = `pill ${source?.status || 'waiting'}`; head.append(title, state);
    const meta = document.createElement('p'); meta.className = 'component-meta'; meta.textContent = source?.detail || 'Waiting for the first collector poll.';
    const list = document.createElement('ol'); list.className = 'component-events';
    matches.slice(0, 5).forEach(({event, scenario}) => {
      const row = document.createElement('li'), time = document.createElement('time'), strong = document.createElement('strong'), detail = document.createElement('small');
      time.dateTime = event.atUtc; time.textContent = new Date(event.atUtc).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
      strong.textContent = event.title; detail.textContent = event.detail; row.append(time, livePathBadge(event, scenario), strong, detail); list.append(row);
    });
    if (!matches.length) { const empty = document.createElement('li'); empty.className = 'empty'; empty.textContent = 'Waiting for new activity in this session…'; list.append(empty); }
    card.append(head, meta, list); $('component-grid').append(card);
  });
}

function renderLiveLog() {
  const events = allEvents(); $('live-log').replaceChildren();
  events.slice(0, 100).forEach(({event, scenario}) => {
    const row = document.createElement('li'); row.className = event.status;
    const head = document.createElement('div'), time = document.createElement('time'), source = document.createElement('span');
    time.dateTime = event.atUtc; time.textContent = new Date(event.atUtc).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
    source.className = 'live-source'; source.textContent = event.source; head.append(time, source, livePathBadge(event, scenario));
    const title = document.createElement('strong'), detail = document.createElement('p'), fields = document.createElement('dl');
    title.textContent = event.title; detail.textContent = event.detail; fields.className = 'live-fields'; appendFields(fields, event.fields, 12);
    row.append(head, title, detail, fields); $('live-log').append(row);
  });
  if (!events.length) { const empty = document.createElement('li'); empty.className = 'empty'; empty.textContent = 'Listening for AD, AD CS, broker, facts, FreeRADIUS and UniFi events…'; $('live-log').append(empty); }
  $('live-count').textContent = `${events.length} live event${events.length === 1 ? '' : 's'}`;
}
function renderLiveBoard() {
  $('live-hostname').textContent = session.device.hostname; $('live-mac').textContent = session.device.macAddress;
  renderDecisions(); renderComponentGrid(); renderLiveLog();
}

function renderTabs() {
  $('scenarios').replaceChildren();
  session.scenarios.forEach((scenario, index) => {
    const button = document.createElement('button'); button.type = 'button'; button.className = index === scenarioIndex ? 'active' : '';
    const title = document.createElement('strong'); title.textContent = scenario.label;
    const detail = document.createElement('span'); detail.textContent = scenario.summary;
    button.append(title, detail); button.setAttribute('aria-pressed', String(index === scenarioIndex));
    button.addEventListener('click', () => selectScenario(index)); $('scenarios').append(button);
  });
}
function derivedStageStatus(stage) {
  const visible = currentScenario().events.slice(0, revealed).filter(event => event.stage === stage.id);
  return visible.length ? visible.at(-1).status : 'pending';
}
function renderFlow() {
  const scenario = currentScenario(); $('flow').replaceChildren(); $('flow').style.setProperty('--stage-count', scenario.stages.length);
  scenario.stages.forEach((stage, index) => {
    const item = document.createElement('li'), status = derivedStageStatus(stage);
    item.className = status; if (revealed && scenario.events[revealed - 1].stage === stage.id) item.classList.add('active');
    const number = document.createElement('span'); number.textContent = 'Stage ' + (index + 1) + ' · ' + status;
    const label = document.createElement('strong'); label.textContent = stage.label; item.append(number, label); $('flow').append(item);
  });
  const latest = scenario.events.slice(0, revealed).at(-1);
  const overall = latest?.status === 'denied' ? 'denied' : (revealed ? (revealed === scenario.events.length ? 'success' : 'active') : 'pending');
  $('scenario-status').textContent = overall; statusClass($('scenario-status'), overall);
}
function selectEvent(index) {
  const event = currentScenario().events[index]; if (!event || index >= revealed) return;
  selectedEventId = event.id; $('detail-title').textContent = event.title; $('detail-text').textContent = event.detail; appendFields($('detail-fields'), event.fields);
  document.querySelectorAll('.timeline li').forEach((item, itemIndex) => item.classList.toggle('current', itemIndex === index));
}
function renderTimeline() {
  const events = currentScenario().events; $('timeline').replaceChildren();
  events.forEach((event, index) => {
    const item = document.createElement('li'); if (index < revealed) item.classList.add('revealed');
    const time = document.createElement('time'); time.dateTime = event.atUtc; time.textContent = new Date(event.atUtc).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
    const source = document.createElement('span'); source.className = 'source'; source.textContent = event.source;
    const button = document.createElement('button'); button.type = 'button'; button.disabled = index >= revealed;
    const title = document.createElement('strong'); title.textContent = event.title; const detail = document.createElement('small'); detail.textContent = event.detail; button.append(title, detail);
    button.addEventListener('click', () => selectEvent(index)); const dot = document.createElement('span'); dot.className = 'status-dot ' + event.status;
    item.append(time, source, button, dot); $('timeline').append(item);
  });
  if (!events.length) {
    const empty = document.createElement('li'); empty.className = 'revealed empty'; empty.textContent = 'No recorded evidence.'; $('timeline').append(empty);
    $('detail-title').textContent = 'Waiting for evidence'; $('detail-text').textContent = 'This replay path contains no evidence.'; $('detail-fields').replaceChildren();
  } else { const selected = events.findIndex(event => event.id === selectedEventId); selectEvent(selected >= 0 ? selected : revealed - 1); }
}
function renderStory() {
  const scenario = currentScenario(); $('title').textContent = scenario.label; $('summary').textContent = scenario.summary;
  $('hostname').textContent = session.device.hostname; $('asset').textContent = session.device.assetId; $('mac').textContent = session.device.macAddress;
  $('progress').textContent = revealed + ' / ' + scenario.events.length + ' events'; $('previous').disabled = revealed === 0; $('next').disabled = revealed === scenario.events.length;
  renderTabs(); renderFlow(); renderTimeline();
}
function render() {
  $('session-id').textContent = session.sessionId; $('snapshot').textContent = (isLive() ? 'Live snapshot ' : 'Replay snapshot ') + snapshotHash.slice(0, 16) + '…';
  renderMode(); renderSources(); if (isLive()) renderLiveBoard(); else renderStory();
}
function applyEnvelope(result) {
  if (!result?.session || result.sha256 === snapshotHash) return;
  const oldScenarioId = session?.scenarios?.[scenarioIndex]?.id;
  session = result.session; snapshotHash = result.sha256;
  const retained = session.scenarios.findIndex(value => value.id === oldScenarioId); scenarioIndex = retained >= 0 ? retained : 0;
  revealed = isLive() ? currentScenario().events.length : Math.min(revealed, currentScenario().events.length);
  render();
}
function stop() { if (timer) clearInterval(timer); timer = null; $('play').textContent = 'Auto play'; }
function advance() { if (revealed < currentScenario().events.length) { revealed += 1; render(); } else stop(); }
function selectScenario(index) { stop(); scenarioIndex = index; revealed = 0; selectedEventId = undefined; render(); }
$('restart').addEventListener('click', () => { stop(); revealed = 0; render(); });
$('previous').addEventListener('click', () => { stop(); if (revealed) revealed -= 1; render(); });
$('next').addEventListener('click', () => { stop(); advance(); });
$('play').addEventListener('click', () => { if (timer) { stop(); return; } $('play').textContent = 'Pause'; advance(); timer = setInterval(advance, Number($('speed').value)); });
$('speed').addEventListener('change', () => { if (timer) { stop(); $('play').click(); } });
async function refresh() {
  try {
    const response = await fetch('/api/session');
    if (!response.ok) throw new Error('Session request failed.');
    applyEnvelope(await response.json());
    if (feed.readyState === EventSource.CLOSED) {
      $('connection').textContent = isLive() ? 'Live snapshot polling' : 'Replay loaded';
      statusClass($('connection'), isLive() ? 'connected' : 'recorded');
    }
  }
  catch { $('connection').textContent = 'Feed unavailable'; statusClass($('connection'), 'warning'); }
}
const feed = new EventSource('/api/events');
feed.addEventListener('session', event => {
  applyEnvelope(JSON.parse(event.data)); $('connection').textContent = isLive() ? 'Live feed connected' : 'Replay loaded'; statusClass($('connection'), isLive() ? 'connected' : 'recorded');
});
feed.onerror = () => { $('connection').textContent = 'Reconnecting'; statusClass($('connection'), 'warning'); };
setInterval(refresh, 5000);
setInterval(() => {
  if (!session) return;
  const age = Math.max(0, Math.round((Date.now() - new Date(session.updatedUtc).getTime()) / 1000));
  $('feed-age').textContent = isLive() ? `feed ${age}s old` : `captured ${new Date(session.updatedUtc).toLocaleString()}`;
  renderSources();
}, 1000);
