'use strict';
/* Zyntra Certificate Manager — 100% client-side. Nenhum arquivo sai do navegador. */
pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
const { PDFDocument, PDFName, PDFString, PDFArray, PDFDict, PDFSignature } = PDFLib;
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? '—').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const td = new TextDecoder('utf-8');
const MAX_MB = 150;

/* ───────── ASN.1 / PKCS#7 (somente leitura de dados públicos) ───────── */
function tlv(b, p) {
  const tag = b[p++]; let l = b[p++], ind = false;
  if (l === 0x80) ind = true; else if (l & 0x80) { const n = l & 0x7f; l = 0; for (let i = 0; i < n; i++) l = l * 256 + b[p++]; }
  const o = { tag, v: p };
  if (tag & 0x20) {
    o.c = []; let q = p; const end = ind ? b.length : p + l;
    while (q < end && !(ind && b[q] === 0 && b[q + 1] === 0)) { const x = tlv(b, q); o.c.push(x); q = x.e; }
    o.e = ind ? q + 2 : p + l;
  } else o.e = p + l;
  return o;
}
const raw = (b, n) => b.subarray(n.v, n.e);
const hx = a => Array.from(a, x => x.toString(16).padStart(2, '0')).join('');
const oid = (b, n) => { const r = raw(b, n), a = [Math.floor(r[0] / 40), r[0] % 40]; let x = 0; for (let i = 1; i < r.length; i++) { x = x * 128 + (r[i] & 127); if (!(r[i] & 128)) { a.push(x); x = 0; } } return a.join('.'); };
const NAMES = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.5': 'serial' };
const dn = (b, n) => { const o = {}; n.c.forEach(set => set.c.forEach(a => { const k = NAMES[oid(b, a.c[0])]; if (k && !o[k]) o[k] = td.decode(raw(b, a.c[1])); })); return o; };
const fmtDN = o => [o.CN, o.O, o.C].filter(Boolean).join(', ') || '—';
const asnTime = (b, n) => {
  const s = td.decode(raw(b, n)), u = n.tag === 0x17;
  const m = s.match(u ? /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z/ : /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z/);
  if (!m) return null; let y = +m[1]; if (u) y += y >= 50 ? 1900 : 2000;
  return new Date(Date.UTC(y, m[2] - 1, m[3], m[4], m[5], m[6] || 0));
};
const ALGS = {
  '1.2.840.113549.1.1.1': 'RSA', '1.2.840.113549.1.1.5': 'SHA-1 com RSA', '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.113549.1.1.11': 'SHA-256 com RSA', '1.2.840.113549.1.1.12': 'SHA-384 com RSA', '1.2.840.113549.1.1.13': 'SHA-512 com RSA',
  '1.2.840.10045.4.3.2': 'ECDSA com SHA-256', '1.2.840.10045.4.3.3': 'ECDSA com SHA-384', '1.2.840.10045.4.3.4': 'ECDSA com SHA-512'
};
const DIGESTS = { '2.16.840.1.101.3.4.2.1': 'SHA-256', '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512', '1.3.14.3.2.26': 'SHA-1' };

function parseCert(b, n) {
  const t = n.c[0], i = t.c[0].tag === 0xA0 ? 1 : 0;
  return { serial: hx(raw(b, t.c[i])).replace(/^0+/, ''), sigAlg: oid(b, t.c[i + 1].c[0]), issuer: dn(b, t.c[i + 2]),
    nb: asnTime(b, t.c[i + 3].c[0]), na: asnTime(b, t.c[i + 3].c[1]), subject: dn(b, t.c[i + 4]) };
}
function parseP7(b) {
  const sd = tlv(b, 0).c[1].c[0];
  const cn = sd.c.find(n => n.tag === 0xA0);
  const certs = (cn ? cn.c : []).filter(n => n.tag === 0x30).map(n => { try { return parseCert(b, n); } catch { return null; } }).filter(Boolean);
  const si = sd.c[sd.c.length - 1].c[0], attrs = si.c.find(n => n.tag === 0xA0);
  let sid = null; try { sid = { issuer: fmtDN(dn(b, si.c[1].c[0])), serial: hx(raw(b, si.c[1].c[1])).replace(/^0+/, '') }; } catch {}
  let md = null, st = null;
  (attrs ? attrs.c : []).forEach(a => {
    const o = oid(b, a.c[0]), v = a.c[1].c[0];
    if (o === '1.2.840.113549.1.9.4') md = hx(raw(b, v)); else if (o === '1.2.840.113549.1.9.5') st = asnTime(b, v);
  });
  const signer = certs.find(c => sid && c.serial === sid.serial && fmtDN(c.issuer) === sid.issuer) || certs[0] || null;
  return { certs, signer, md, st, digestOid: oid(b, si.c[2].c[0]), sigAlg: oid(b, si.c[attrs ? 4 : 3].c[0]) };
}

/* ───────── Varredura de assinaturas no PDF ───────── */
async function checkDigest(bytes, [a, b, c, d], p7) {
  const alg = DIGESTS[p7.digestOid]; if (!alg || !p7.md) return null;
  const data = new Uint8Array(b + d); data.set(bytes.subarray(a, a + b)); data.set(bytes.subarray(c, c + d), b);
  return { alg, match: hx(new Uint8Array(await crypto.subtle.digest(alg, data))) === p7.md };
}
async function scanSigs(bytes) {
  const txt = new TextDecoder('latin1').decode(bytes);
  const clean = txt.replace(/<[0-9A-Fa-f\s]{200,}>/g, '<>');
  const re = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;
  const cidx = []; let m; const cre = new RegExp(re.source, 'g');
  while ((m = cre.exec(clean))) cidx.push(m.index);
  const out = []; let i = 0;
  while ((m = re.exec(txt))) {
    const br = m.slice(1).map(Number), [a, b, c, d] = br, ci = cidx[i++] ?? 0;
    if (a + b > c || c + d > bytes.length || c === 0) continue;
    const win = clean.slice(Math.max(0, ci - 700), ci + 700);
    const g = k => (win.match(new RegExp('/' + k + '\\s*\\(([^)]*)\\)')) || [])[1];
    const pd = (g('M') || '').match(/D:(\d{4})(\d\d)(\d\d)(\d\d)?(\d\d)?(\d\d)?/);
    const hex = txt.slice(a + b, c).replace(/[<>\s]/g, '').replace(/(00)+$/, '');
    const sig = { byteRange: br, subFilter: (win.match(/\/SubFilter\s*\/([\w.]+)/) || [])[1], name: g('Name'), reason: g('Reason'),
      location: g('Location'), when: pd ? `${pd[3]}/${pd[2]}/${pd[1]} ${pd[4] || '00'}:${pd[5] || '00'}` : null,
      covers: c + d === bytes.length, timestamp: /DocTimeStamp/.test(win) };
    try { sig.p7 = parseP7(Uint8Array.from(hex.match(/../g) || [], h => parseInt(h, 16))); sig.integrity = await checkDigest(bytes, br, sig.p7); }
    catch (e) { sig.error = 'Não foi possível interpretar o PKCS#7 (' + e.message + ').'; }
    out.push(sig);
  }
  return out;
}

/* ───────── Análise do arquivo ───────── */
async function inspect(file) {
  if (file.size > MAX_MB * 1048576) throw new Error(`Arquivo acima de ${MAX_MB} MB.`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (!new TextDecoder('latin1').decode(bytes.subarray(0, 1024)).includes('%PDF-')) throw new Error('O arquivo não é um PDF válido.');
  let pdf; try { pdf = await pdfjsLib.getDocument({ data: bytes.slice() }).promise; }
  catch (e) { throw new Error(e.name === 'PasswordException' ? 'PDF protegido por senha não é suportado.' : 'Não foi possível abrir o PDF: ' + e.message); }
  const vp = (await pdf.getPage(1)).getViewport({ scale: 1 });
  const d = { name: file.name, size: file.size, bytes, pdf, pages: pdf.numPages, pageSize: `${Math.round(vp.width)} × ${Math.round(vp.height)} pt`, info: {}, fields: 0, empty: 0 };
  try { // pdf-lib lê objetos compactados; nada é salvo aqui
    const doc = await PDFDocument.load(bytes, { ignoreEncryption: true, updateMetadata: false });
    d.info = { title: doc.getTitle(), author: doc.getAuthor(), creator: doc.getCreator(), producer: doc.getProducer(), created: doc.getCreationDate() };
    const f = doc.getForm().getFields().filter(x => x instanceof PDFSignature);
    d.fields = f.length; d.empty = f.filter(x => !x.acroField.V()).length;
  } catch { d.libWarn = true; }
  d.sigs = await scanSigs(bytes);
  return d;
}

/* ───────── Estado e interface ───────── */
const S = { ref: null, dst: null };
const fmtSize = n => n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(2) + ' MB';
const fmtDate = d => d ? d.toLocaleString('pt-BR') : '—';

function renderCard(slot) {
  const d = S[slot], card = $(`#card-${slot}`), dl = $('.meta', card);
  $('.view', card).disabled = !d;
  if (!d) { dl.innerHTML = ''; return; }
  const sigTxt = d.sigs.length ? `${d.sigs.length} identificada(s)` : 'Nenhuma encontrada';
  dl.innerHTML = `<dt>Arquivo</dt><dd>${esc(d.name)}</dd><dt>Tamanho</dt><dd>${fmtSize(d.size)}</dd><dt>Páginas</dt><dd>${d.pages}</dd>` +
    (slot === 'ref' ? `<dt>Assinaturas</dt><dd>${sigTxt}</dd>`
      : `<dt>Assinaturas existentes</dt><dd>${sigTxt}</dd><dt>Campos vazios</dt><dd>${d.libWarn ? 'Não foi possível verificar' : d.empty}</dd>`);
}
const tag = (cls, t) => `<span class="tag ${cls}">${esc(t)}</span>`;

function renderCert() {
  const d = S.ref, box = $('#cert'); box.hidden = !d; if (!d) return;
  $('#cert-list').innerHTML = d.sigs.length ? d.sigs.map((s, i) => {
    const p = s.p7, c = p && p.signer, root = p && p.certs.find(x => fmtDN(x.subject) === fmtDN(x.issuer));
    const tags = [tag('info', 'Estrutura identificada'), c ? tag('info', 'Certificado encontrado') : tag('warn', 'Certificado não encontrado'),
      !s.integrity ? tag('warn', 'Integridade não verificável') : s.integrity.match ? tag('ok', `Hash ${s.integrity.alg} confere`) : tag('bad', 'Hash NÃO confere: conteúdo alterado'),
      tag('warn', 'Assinatura criptográfica não validada')].join('');
    const row = (k, v) => `<dt>${k}</dt><dd>${esc(v)}</dd>`;
    return `<div class="sig"><h3>${s.timestamp ? 'Carimbo de tempo' : 'Assinatura'} ${i + 1} ${tags}</h3><dl class="meta">` +
      (s.error ? row('Erro', s.error) : '') +
      (c ? row('Titular', fmtDN(c.subject)) + row('Emissor', fmtDN(c.issuer)) +
        row('Autoridade certificadora', root ? fmtDN(root.subject) + ' (raiz incorporada)' : fmtDN(c.issuer) + ' (raiz não incorporada)') +
        row('Validade', `${fmtDate(c.nb)} até ${fmtDate(c.na)}${c.na && c.na < new Date() ? ' (expirado hoje)' : ''}`) +
        row('Algoritmo', `${ALGS[c.sigAlg] || c.sigAlg}; assinatura: ${ALGS[p.sigAlg] || p.sigAlg}; resumo: ${DIGESTS[p.digestOid] || p.digestOid}`) +
        row('Certificados incorporados', p.certs.length) : '') +
      row('Data da assinatura', p && p.st ? fmtDate(p.st) + ' (declarada pelo signatário)' : s.when || '—') +
      row('Formato', s.subFilter) + (s.name ? row('Nome no campo', s.name) : '') + (s.reason ? row('Motivo', s.reason) : '') +
      row('Cobertura', s.covers ? 'A assinatura cobre o arquivo inteiro' : 'Há bytes após a assinatura (atualização incremental)') + `</dl></div>`;
  }).join('') : '<p class="muted">Nenhuma assinatura digital encontrada neste documento.</p>';
}

function renderCompare() {
  const { ref: a, dst: b } = S, box = $('#compare'); box.hidden = !(a && b); if (!(a && b)) return;
  const rows = [['Arquivo', d => d.name], ['Tamanho', d => fmtSize(d.size)], ['Páginas', d => d.pages], ['Tamanho da página 1', d => d.pageSize],
    ['Título', d => d.info.title], ['Autor', d => d.info.author], ['Criador', d => d.info.creator], ['Produtor', d => d.info.producer],
    ['Criação', d => fmtDate(d.info.created)], ['Assinaturas digitais', d => d.sigs.length], ['Campos de assinatura vazios', d => d.libWarn ? '?' : d.empty]];
  $('tbody', box).innerHTML = rows.map(([k, f]) => `<tr><td>${k}</td><td>${esc(f(a))}</td><td>${esc(f(b))}</td></tr>`).join('');
}

function renderPrepare() {
  const d = S.dst, box = $('#prepare'); box.hidden = !d; if (!d) return;
  $('#sig-page').innerHTML = Array.from({ length: d.pages }, (_, i) => `<option value="${i}">${i + 1}</option>`).join('');
  const bp = $('#dl-prepared'); bp.disabled = true;
  $('#prep-status').textContent = d.sigs.length ? 'Este documento já contém assinatura. Inserir um campo exigiria reescrever o arquivo e poderia invalidá-la; baixe apenas a cópia original.'
    : d.libWarn ? 'Não foi possível ler a estrutura de formulário; baixe apenas a cópia original.'
    : d.empty ? `Documento pronto: já tem ${d.empty} campo(s) de assinatura vazio(s).`
    : 'Sem campos de assinatura. Você pode inserir um campo vazio para assinar depois.';
  bp.disabled = !!(d.sigs.length || d.libWarn || d.empty);
}
const renderAll = () => { renderCard('ref'); renderCard('dst'); renderCert(); renderCompare(); renderPrepare(); };

async function load(slot, file) {
  const err = $('.err', $(`#card-${slot}`)); err.textContent = '';
  if (!file) return;
  try { const d = await inspect(file); if (S[slot]) S[slot].pdf.destroy(); S[slot] = d; }
  catch (e) { err.textContent = e.message; }
  renderAll();
}

/* ───────── Exportação ───────── */
function download(bytes, name) {
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/pdf' }));
  Object.assign(document.createElement('a'), { href: url, download: name }).click();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}
function addSigField(doc, idx, pos) {
  const ctx = doc.context, page = doc.getPage(idx), { width, height } = page.getSize(), w = 180, h = 50, m = 36;
  const x = pos[1] === 'r' ? width - w - m : m, y = pos[0] === 'b' ? m : height - h - m;
  const ref = ctx.register(ctx.obj({ Type: 'Annot', Subtype: 'Widget', FT: 'Sig', T: PDFString.of('Zyntra_Assinatura_' + Date.now().toString(36)), Rect: [x, y, x + w, y + h], F: 4, P: page.ref }));
  page.node.addAnnot(ref);
  let form = doc.catalog.lookupMaybe(PDFName.of('AcroForm'), PDFDict);
  if (!form) { form = ctx.obj({}); doc.catalog.set(PDFName.of('AcroForm'), ctx.register(form)); }
  let fields = form.lookupMaybe(PDFName.of('Fields'), PDFArray);
  if (!fields) { fields = ctx.obj([]); form.set(PDFName.of('Fields'), fields); }
  fields.push(ref);
}
const base = n => n.replace(/\.pdf$/i, '');
$('#dl-original').onclick = () => S.dst && download(S.dst.bytes, S.dst.name);
$('#dl-prepared').onclick = async () => {
  const d = S.dst, err = $('.err', $('#card-dst')); if (!d || d.sigs.length) return;
  try {
    const doc = await PDFDocument.load(d.bytes);
    addSigField(doc, +$('#sig-page').value, $('#sig-pos').value);
    download(await doc.save(), base(d.name) + '-preparado.pdf');
  } catch (e) { err.textContent = 'Falha ao preparar o PDF: ' + e.message; }
};

/* ───────── Visualizador (PDF.js) ───────── */
const V = { doc: null, n: 1, scale: 1.2, task: null };
async function draw() {
  if (!V.doc) return;
  try {
    V.task && V.task.cancel();
    const p = await V.doc.getPage(V.n), vp = p.getViewport({ scale: V.scale }), c = $('#v-canvas'), r = window.devicePixelRatio || 1;
    c.width = vp.width * r; c.height = vp.height * r; c.style.width = vp.width + 'px'; c.style.height = vp.height + 'px';
    $('#v-pg').textContent = `${V.n} / ${V.doc.numPages}`;
    V.task = p.render({ canvasContext: c.getContext('2d'), viewport: vp, transform: [r, 0, 0, r, 0, 0] });
    await V.task.promise;
  } catch (e) { if (e.name !== 'RenderingCancelledException') console.error(e); }
}
const step = (n, s) => { if (!V.doc) return; V.n = Math.min(Math.max(1, V.n + n), V.doc.numPages); V.scale = Math.min(3, Math.max(.4, V.scale + s)); draw(); };
document.querySelectorAll('.view').forEach(b => b.onclick = () => {
  const slot = b.closest('.card').dataset.slot; V.doc = S[slot].pdf; V.n = 1;
  $('#v-title').textContent = S[slot].name; $('#viewer').hidden = false; draw();
});
$('#v-prev').onclick = () => step(-1, 0); $('#v-next').onclick = () => step(1, 0);
$('#v-in').onclick = () => step(0, .2); $('#v-out').onclick = () => step(0, -.2);
$('#v-close').onclick = () => { $('#viewer').hidden = true; };
addEventListener('keydown', e => { if (e.key === 'Escape') $('#viewer').hidden = true; });

/* ───────── Upload e limpeza ───────── */
document.querySelectorAll('.card[data-slot]').forEach(card => {
  const slot = card.dataset.slot, drop = $('.drop', card), input = $('input', card);
  input.onchange = () => { load(slot, input.files[0]); input.value = ''; };
  drop.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
  ['dragenter', 'dragover'].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', e => load(slot, e.dataTransfer.files[0]));
});
$('#clear').onclick = () => {
  ['ref', 'dst'].forEach(k => { if (S[k]) S[k].pdf.destroy(); S[k] = null; });
  V.doc = null; $('#viewer').hidden = true;
  document.querySelectorAll('.err').forEach(e => e.textContent = '');
  renderAll();
};
// Impede que soltar um arquivo fora dos cards abra o PDF no navegador
['dragover', 'drop'].forEach(t => addEventListener(t, e => e.preventDefault()));
