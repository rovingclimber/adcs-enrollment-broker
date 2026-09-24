'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="workbench-token"]').content;
let original, draft, sourceHash, selected = -1;
let publishEnabled = false, publicationBusy = false, reviewed;
const fields = ['hostname', 'assetId', 'deviceClass', 'useCase', 'location', 'managementDomain'];
function notice(message, error = false) { $('notice').textContent = message; $('notice').classList.toggle('error', error); }
function changed() { return JSON.stringify(original) !== JSON.stringify(draft); }
function updateState() { $('dirty').hidden = !changed(); $('export').disabled = !changed(); $('review-publish').disabled = !changed() || !publishEnabled || publicationBusy; }
function list() {
  const search = $('search').value.toLowerCase();
  $('devices').replaceChildren(); $('count').textContent = draft.devices.length;
  draft.devices.forEach((device, index) => {
    if (!(device.hostname + ' ' + device.assetId).toLowerCase().includes(search)) return;
    const button = document.createElement('button'); button.type = 'button'; button.className = 'device' + (index === selected ? ' selected' : '');
    button.setAttribute('aria-pressed', index === selected ? 'true' : 'false');
    const name = document.createElement('strong'); name.textContent = device.hostname || 'New device';
    const detail = document.createElement('small'); detail.textContent = device.assetId || 'Add an asset ID';
    button.append(name, detail); button.addEventListener('click', () => select(index)); $('devices').append(button);
  });
  if (!$('devices').childElementCount) { const empty = document.createElement('p'); empty.textContent = 'No matching devices.'; $('devices').append(empty); }
}
const encode = value => encodeURIComponent(value).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
function claims() {
  $('claims').replaceChildren();
  if (selected < 0) return;
  const d = draft.devices[selected];
  const values = [['Profile', 'urn:example:pki-broker:lab:fact:v1:profile:broker-pilot'], ...[['Asset', 'asset', d.assetId], ['Class', 'class', d.deviceClass], ['Use case', 'use-case', d.useCase], ['Location', 'location', d.location], ['Management domain', 'management-domain', d.managementDomain]].map(([label, key, value]) => [label, 'urn:example:pki-broker:lab:fact:v1:' + key + ':' + encode(value)])];
  for (const [label, value] of values) { const item = document.createElement('li'), heading = document.createElement('span'), code = document.createElement('code'); heading.textContent = label; code.textContent = value; item.append(heading, code); $('claims').append(item); }
}
function select(index) {
  selected = index; $('device-form').hidden = index < 0;
  $('editor-title').textContent = index < 0 ? 'Add a device to begin' : (draft.devices[index].hostname || 'New device');
  if (index >= 0) for (const field of fields) $('device-form').elements.namedItem(field).value = draft.devices[index][field];
  list(); claims(); updateState();
}
$('search').addEventListener('input', () => { if (draft) list(); });
$('device-form').addEventListener('submit', event => event.preventDefault());
$('device-form').addEventListener('input', event => {
  if (selected < 0 || !fields.includes(event.target.name)) return;
  draft.devices[selected][event.target.name] = event.target.value;
  $('editor-title').textContent = draft.devices[selected].hostname || 'New device'; list(); claims(); updateState();
});
$('add').addEventListener('click', () => { draft.devices.push({ hostname: '', assetId: '', deviceClass: 'workstation', useCase: draft.useCases[0].id, location: '', managementDomain: '' }); $('search').value = ''; select(draft.devices.length - 1); $('device-form').elements.namedItem('hostname').focus(); notice('New draft record. This does not create an AD computer account or grant enrollment.'); });
$('remove').addEventListener('click', () => $('confirm-remove').showModal());
$('confirm-remove').addEventListener('close', () => { if ($('confirm-remove').returnValue !== 'remove') return; draft.devices.splice(selected, 1); select(Math.min(selected, draft.devices.length - 1)); notice('Device removed from this draft only. Existing certificates are unchanged.'); });
$('reset').addEventListener('click', () => { draft = structuredClone(original); select(draft.devices.length ? 0 : -1); notice('Draft reset to the loaded snapshot.'); });
$('export').addEventListener('click', async () => {
  if (!$('device-form').hidden && !$('device-form').reportValidity()) return;
  $('export').disabled = true;
  try {
    const response = await fetch('/api/draft', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Workbench-Token': token, 'If-Match': sourceHash }, body: JSON.stringify(draft) });
    if (!response.ok) { const error = await response.json(); throw new Error(error.error || 'Draft validation failed.'); }
    const blob = await response.blob(), url = URL.createObjectURL(blob), link = document.createElement('a');
    link.href = url; link.download = 'device-facts.draft.json'; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    notice('Validated draft downloaded. Live facts are unchanged. Review and publish it before renewing the device certificate.');
  } catch (error) { notice(error.message, true); } finally { updateState(); }
});
window.addEventListener('beforeunload', event => { if (draft && changed()) { event.preventDefault(); event.returnValue = ''; } });
$('review-publish').addEventListener('click', async () => {
  if (!$('device-form').hidden && !$('device-form').reportValidity()) return;
  publicationBusy = true; updateState();
  try {
    const snapshotHash = sourceHash, before = structuredClone(original), proposal = structuredClone(draft);
    const response = await fetch('/api/draft', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Workbench-Token': token, 'If-Match': snapshotHash }, body: JSON.stringify(proposal) });
    if (!response.ok) throw new Error((await response.json()).error || 'Draft validation failed.');
    const bytes = await response.arrayBuffer();
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
    const after = JSON.parse(new TextDecoder().decode(bytes));
    const lines = [];
    const oldByHost = new Map(before.devices.map(d => [d.hostname.toLowerCase(), d]));
    const newByHost = new Map(after.devices.map(d => [d.hostname.toLowerCase(), d]));
    for (const [key, device] of oldByHost) if (!newByHost.has(key)) lines.push('REMOVE ' + device.hostname + ' (' + device.assetId + ')');
    for (const [key, device] of newByHost) {
      const old = oldByHost.get(key);
      if (!old) lines.push('ADD ' + device.hostname);
      for (const field of fields) if (!old || old[field] !== device[field]) lines.push(device.hostname + ' · ' + field + ': ' + (old ? old[field] : '—') + ' → ' + device[field]);
    }
    reviewed = { bytes, hash, sourceHash: snapshotHash };
    $('publish-diff').textContent = lines.join('\n');
    $('publish-revision').textContent = 'Revision ' + before.revision + ' → ' + after.revision;
    $('confirm-publish').showModal();
  } catch (error) { notice(error.message, true); }
  finally { publicationBusy = false; updateState(); }
});
$('cancel-publish').addEventListener('click', () => { reviewed = null; $('confirm-publish').close(); });
$('apply-publish').addEventListener('click', async () => {
  if (!reviewed || publicationBusy) return;
  const publication = reviewed; reviewed = null; publicationBusy = true;
  $('confirm-publish').close(); updateState();
  try {
    const response = await fetch('/api/publish', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Workbench-Token': token, 'If-Match': publication.sourceHash, 'X-Draft-SHA256': publication.hash }, body: publication.bytes });
    if (!response.ok) throw new Error((await response.json()).error || 'Publication result uncertain. Operator reconciliation required.');
    const receipt = await response.json();
    if (!await load()) { publishEnabled = false; notice('Published revision ' + receipt.revision + ', but the refreshed snapshot could not be loaded. Reload before editing again. Receipt: ' + receipt.transaction, true); return; }
    notice('Published revision ' + receipt.revision + '. Renew the device certificate to apply its new facts. Receipt: ' + receipt.transaction);
  } catch (error) { publishEnabled = false; notice(error.message + ' Publishing is paused; do not blindly retry.', true); }
  finally { publicationBusy = false; updateState(); }
});
async function load() {
  try {
    const response = await fetch('/api/snapshot', { headers: { 'X-Workbench-Token': token } });
    if (!response.ok) throw new Error('Unable to load the selected facts file. Check the workbench server.');
    const snapshot = await response.json(); original = snapshot.document; draft = structuredClone(original); sourceHash = snapshot.sha256;
    publishEnabled = snapshot.publishEnabled && !snapshot.publicationBlocked;
    $('review-publish').hidden = !snapshot.publishEnabled;
    $('mode').textContent = snapshot.publishEnabled ? (snapshot.publicationBlocked ? 'Publication paused' : 'Operator publication') : 'Draft workspace';
    $('revision').textContent = String(original.revision); $('source-hash').textContent = 'Snapshot SHA-256 ' + sourceHash.slice(0, 16) + '…';
    const selectElement = $('device-form').elements.namedItem('useCase');
    selectElement.replaceChildren();
    for (const useCase of draft.useCases) { const option = document.createElement('option'); option.value = useCase.id; option.textContent = useCase.label; selectElement.append(option); }
    $('add').disabled = false; select(draft.devices.length ? 0 : -1);
    notice('Editing an operator-selected snapshot. Downloads are validated drafts, not live changes.');
    return true;
  } catch (error) { notice(error.message, true); return false; }
}
load();
