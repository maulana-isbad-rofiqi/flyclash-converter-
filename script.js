/* ===========================================================
   FlyClash Converter PRO - Developer: Itsbad
   =========================================================== */

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

// --- Explanation Data (Konten Pop-up) ---
const explanations = {
    input: `
        <strong>Input Config</strong><br>
        Tempel (Paste) konfigurasi akun V2Ray Anda di sini.<br><br>
        Mendukung format:
        <ul style="margin-left:20px; margin-top:5px; list-style-type:disc">
            <li>VMess (vmess://...)</li>
            <li>VLESS (vless://...)</li>
            <li>Trojan (trojan://...)</li>
            <li>Shadowsocks (ss://...)</li>
        </ul>
        <br><i>Tips: Bisa paste banyak akun sekaligus (satu baris satu akun).</i>
    `,
    mode: `
        <strong>Mode Strategy</strong><br>
        Menentukan bagaimana FlyClash memilih akun mana yang digunakan:<br><br>
        1. <strong>🚀 Auto Best Ping:</strong> Otomatis pilih akun yang internetnya paling ngebut (ping terkecil).<br>
        2. <strong>👆 Manual:</strong> Anda pilih sendiri akunnya di menu FlyClash.<br>
        3. <strong>⚖️ Load Balance:</strong> Menggabungkan semua akun agar beban dibagi-bagi (Speed maksimal).<br>
        4. <strong>🛡️ Failover:</strong> Pakai akun ke-1. Jika mati, otomatis pindah ke akun ke-2, dst.
    `,
    interval: `
        <strong>Interval (Detik)</strong><br>
        Seberapa sering FlyClash mengecek koneksi (Ping) ke server.<br><br>
        Contoh: Jika diisi <strong>5</strong>, maka setiap 5 detik aplikasi akan mengetes apakah akun masih hidup atau mati.
    `,
    group: `
        <strong>Group Name</strong><br>
        Nama untuk kelompok proxy ini yang akan muncul di menu FlyClash.<br><br>
        Bebas diisi apa saja, contoh: "Server Gaming", "VIP Indo", dll.
    `,
    skipcert: `
        <strong>Skip Certificate</strong><br>
        Jika diaktifkan (ON), aplikasi akan mengabaikan peringatan keamanan SSL/TLS.<br><br>
        <strong>Wajib ON</strong> jika Anda menggunakan akun gratisan atau server dengan sertifikat self-signed agar koneksi tidak error.
    `,
    adblock: `
        <strong>AdBlock Mode</strong><br>
        Jika diaktifkan (ON), script akan otomatis memblokir domain iklan yang mengganggu seperti:<br>
        - Google Ads<br>
        - DoubleClick<br>
        - Tracker & Analytics<br><br>
        <i>Bikin browsing lebih bersih dan hemat kuota.</i>
    `,
    autoinsert: `
        <strong>Auto Insert</strong><br>
        Fitur Pintar! Jika ON, grup proxy ini akan otomatis "disuntikkan" ke dalam grup utama FlyClash (seperti grup 'Proxy' atau 'Select').<br><br>
        Anda tidak perlu setting manual lagi di aplikasi. Tinggal paste script, langsung muncul.
    `,
    weights: `
        <strong>Load Balance Weights</strong><br>
        Mengatur porsi pembagian trafik untuk setiap akun.<br><br>
        Isi dengan angka dipisah koma (contoh: 50,20,10).<br>
        - Akun 1 dapat jatah 50<br>
        - Akun 2 dapat jatah 20<br><br>
        <i>Kosongkan jika ingin dibagi rata (Adil).</i>
    `,
    dns: `
        <strong>Custom DNS</strong><br>
        Memaksa koneksi menggunakan DNS tertentu (bukan DNS operator).<br><br>
        Sangat berguna untuk membuka situs yang diblokir internet positif. Default: Google (8.8.8.8).
    `
};

// --- Utilities ---
const downloadText = (filename, content, type = 'text/plain') => {
    const a = document.createElement('a');
    const url = URL.createObjectURL(new Blob([content], { type }));
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
};

// --- Parsing Logic (Tetap Sama) ---
function parseQuery(q){ const o={}; if(!q) return o; q.split('&').forEach(p=>{ const i=p.indexOf('='); if(i===-1) o[decodeURIComponent(p)]=''; else o[decodeURIComponent(p.slice(0,i))]=decodeURIComponent(p.slice(i+1)); }); return o; }
function parseVLESS(raw){ try{ const s = raw.replace(/^vless:\/\//i,''); const hash = s.indexOf('#'); const name = hash===-1?undefined:decodeURIComponent(s.slice(hash+1)); const beforeHash = hash===-1? s : s.slice(0,hash); const qIdx = beforeHash.indexOf('?'); const qStr = qIdx===-1? '': beforeHash.slice(qIdx+1); const beforeQ = qIdx===-1? beforeHash: beforeHash.slice(0,qIdx); const query = parseQuery(qStr); const at = beforeQ.indexOf('@'); const user = at===-1? '': beforeQ.slice(0,at); const hostport = at===-1? beforeQ: beforeQ.slice(at+1); const colon = hostport.lastIndexOf(':'); const host = colon===-1? hostport: hostport.slice(0,colon); const port = colon===-1?443:parseInt(hostport.slice(colon+1),10); return { proto:'vless', type:'vless', name:(name||user||`${host}:${port}`)+'-'+Math.random().toString(36).slice(2,6), uuid:user, host, port, network:query.type||'ws', path:query.path||'/', sni:query.sni||query.host||host, security:query.security||'tls', raw }; }catch(e){ return { error:true } } }
function parseVMess(raw){ try{ const s = raw.replace(/^vmess:\/\//i,''); let j=null; if(s.trim().startsWith('{')) j=JSON.parse(s); else { try{ j=JSON.parse(atob(s)); }catch{ return {error:true} } } const server = j.add || (j.vnext && j.vnext[0] && j.vnext[0].address) || ''; const port = parseInt(j.port || (j.vnext && j.vnext[0] && j.vnext[0].port) || 443,10); const uuid = j.id || j.uuid || ''; const net = j.net||j.network||'tcp'; const path = j.path || (j.ws && j.ws.path) || '/'; const host = (j.host || (j.ws && j.ws.headers && (j.ws.headers.Host||j.ws.headers.host)) || j.sni) || server; return { proto:'vmess', type:'vmess', name:(j.ps||`${server}:${port}`)+'-'+Math.random().toString(36).slice(2,6), server, port, uuid, network:net, path, host, tls: j.tls==='tls'||j.tls===true||false, raw }; }catch(e){ return { error:true } } }
function parseTrojan(raw){ try{ const s = raw.replace(/^trojan:\/\//i,''); const hash = s.indexOf('#'); const name = hash===-1?undefined:decodeURIComponent(s.slice(hash+1)); const beforeHash = hash===-1? s : s.slice(0,hash); const qIdx = beforeHash.indexOf('?'); const qStr = qIdx===-1? '': beforeHash.slice(qIdx+1); const beforeQ = qIdx===-1? beforeHash : beforeHash.slice(0,qIdx); const query = parseQuery(qStr); const at = beforeQ.indexOf('@'); const password = at===-1? '': beforeQ.slice(0,at); const hostport = at===-1? beforeQ : beforeQ.slice(at+1); const colon = hostport.lastIndexOf(':'); const host = colon===-1? hostport : hostport.slice(0,colon); const port = colon===-1?443:parseInt(hostport.slice(colon+1),10); return { proto:'trojan', type:'trojan', name:(name||`${host}:${port}`)+'-'+Math.random().toString(36).slice(2,6), password, host, port, sni: query.sni || host, raw }; }catch(e){ return { error:true } } }
function parseSS(raw){ try{ const s = raw.replace(/^ss:\/\//i,''); let name, server, port, cipher, password; if(s.includes('@') && !s.startsWith('@')){ const hash = s.indexOf('#'); name = hash===-1?undefined:decodeURIComponent(s.slice(hash+1)); const beforeHash = hash===-1? s : s.slice(0,hash); const at = beforeHash.indexOf('@'); const methods = beforeHash.slice(0,at); const hostport = beforeHash.slice(at+1); const colon = hostport.lastIndexOf(':'); server = colon===-1? hostport: hostport.slice(0,colon); port = colon===-1?8388:parseInt(hostport.slice(colon+1),10); cipher = methods.split(':')[0]; password = methods.split(':')[1]||''; } else { const hash = s.indexOf('#'); const base = hash===-1? s : s.slice(0,hash); let decoded; try{ decoded = atob(base); }catch{return {error:true}} const at = decoded.indexOf('@'); const methods = decoded.slice(0,at); const hostport = decoded.slice(at+1); const colon = hostport.lastIndexOf(':'); server = colon===-1? hostport: hostport.slice(0,colon); port = colon===-1?8388:parseInt(hostport.slice(colon+1),10); cipher = methods.split(':')[0]; password = methods.split(':')[1]||''; name = hash===-1?`${server}:${port}`:decodeURIComponent(s.slice(hash+1)); } return { proto:'ss', type:'shadowsocks', name:name+'-'+Math.random().toString(36).slice(2,6), server, port, cipher, password, raw }; }catch(e){ return { error:true } } }

function parseAny(line){
    const l = line.trim(); if(!l) return null;
    if(/^vless:\/\//i.test(l)) return parseVLESS(l);
    if(/^vmess:\/\//i.test(l)) return parseVMess(l);
    if(/^trojan:\/\//i.test(l)) return parseTrojan(l);
    if(/^ss:\/\//i.test(l)) return parseSS(l);
    const m = l.replace(/^vmess:\/\//i,''); if(/^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$/.test(m)) return parseVMess('vmess://'+m);
    return { error:true, raw:l };
}

// --- Generator ---
function nodeToClash(node, opts={}){
    if(!node || node.error) return null;
    let base = { name: node.name, server: node.host||node.server, port: node.port };
    const skip = opts.skipCert;
    if(node.type==='vless') return { ...base, type:'vless', uuid:node.uuid, tls:true, 'skip-cert-verify':skip, servername:node.sni||node.host, network:node.network, 'ws-opts':{path:node.path, headers:{Host:node.sni||node.host}} };
    if(node.type==='vmess') return { ...base, type:'vmess', uuid:node.uuid, alterId:0, tls:node.tls, 'skip-cert-verify':skip, network:node.network, 'ws-opts':node.network==='ws'?{path:node.path, headers:{Host:node.host}}:undefined };
    if(node.type==='trojan') return { ...base, type:'trojan', password:node.password, tls:true, 'skip-cert-verify':skip, servername:node.sni||node.host };
    if(node.type==='shadowsocks') return { ...base, type:'shadowsocks', cipher:node.cipher, password:node.password };
    return null;
}

function makeOverride(clashNodes, opts){
    const dnsNames = (opts.dns || '8.8.8.8,1.1.1.1').split(',').map(x=>x.trim()).filter(Boolean);
    const proxiesBlock = clashNodes.map(n=>JSON.stringify(n,null,4).replace(/\n/g,'\n        ')).join(',\n');
    const names = clashNodes.map(n=>n.name);
    
    let groupObj = { name: opts.groupName, proxies: names };
    if(opts.mode === 'auto') groupObj = { ...groupObj, type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: opts.interval, tolerance: 50 };
    else if (opts.mode === 'loadbalance') { groupObj = { ...groupObj, type: 'load-balance', strategy: 'consistent-hashing' }; if(opts.weights) { const w = opts.weights.split(',').map(Number).filter(n=>!isNaN(n)); if(w.length===names.length) groupObj.weights=w; } }
    else if (opts.mode === 'fallback') groupObj = { ...groupObj, type: 'fallback', url: 'https://www.gstatic.com/generate_204', interval: opts.interval };
    else groupObj = { ...groupObj, type: 'select' };

    const autoInsert = opts.autoInsert ? `
    try {
        const t = ['🚀 节点选择', 'Proxy', 'Auto', 'Select', 'GLOBAL'];
        (config['proxy-groups']||[]).forEach(g=>{
            if(t.includes(g.name) || g.type === 'select'){ 
                g.proxies = g.proxies || []; 
                if(!g.proxies.includes("${opts.groupName}")) g.proxies.unshift("${opts.groupName}"); 
            }
        });
        config['proxy-groups'].unshift(${JSON.stringify(groupObj, null, 4)});
    } catch(e) {}` : `config['proxy-groups'].push(${JSON.stringify(groupObj, null, 4)});`;

    const adRules = opts.adblock ? ["DOMAIN-SUFFIX,ads.google.com,REJECT","DOMAIN-KEYWORD,adservice,REJECT","DOMAIN-KEYWORD,analytics,REJECT","DOMAIN-SUFFIX,doubleclick.net,REJECT"] : [];

    return `// FlyClash Override Generated by Itsbad
// Mode: ${opts.mode} | Interval: ${opts.interval}s

function main(config){
    config.proxies = (config.proxies || []).concat([
        ${proxiesBlock}
    ]);
    if(!config['proxy-groups']) config['proxy-groups'] = [];
    ${autoInsert}
    config.dns = config.dns || {}; config.dns.enable = true; config.dns.nameserver = ${JSON.stringify(dnsNames)};
    ${adRules.length ? `config.rules = (config.rules || []).concat(${JSON.stringify(adRules)});` : ''}
    return config;
}`;
}

// --- Event Listeners ---
document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    const el = {
        input: $('#fc-input'), btnGen: $('#fc-generate'), btnClear: $('#fc-clear'), btnVal: $('#fc-validate'),
        outJS: $('#fc-js'), outYAML: $('#fc-yaml'), mode: $('#fc-mode'),
        interval: $('#fc-interval'), group: $('#fc-group'),
        skip: $('#fc-skip'), ad: $('#fc-ad'), auto: $('#fc-autoadd'),
        lbArea: $('#fc-lb-area'), lbWeights: $('#fc-lb'), dns: $('#fc-dns'),
        modal: $('#info-modal'), modalTitle: $('#modal-title'), modalDesc: $('#modal-desc'), closeModal: $('#close-modal')
    };

    // Modal Logic
    $$('.info-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const key = btn.dataset.key;
            if(explanations[key]){
                el.modalTitle.textContent = "Info";
                el.modalDesc.innerHTML = explanations[key];
                el.modal.classList.remove('hidden');
            }
        });
    });

    const hideModal = () => el.modal.classList.add('hidden');
    el.closeModal.addEventListener('click', hideModal);
    el.modal.addEventListener('click', (e) => { if(e.target === el.modal) hideModal(); });

    // Mode Change
    el.mode.addEventListener('change', () => {
        if(el.mode.value === 'loadbalance') el.lbArea.classList.remove('hidden');
        else el.lbArea.classList.add('hidden');
        
        if(el.mode.value === 'auto') el.group.value = 'AUTO BEST PING';
        if(el.mode.value === 'manual') el.group.value = 'MANUAL SELECT';
        if(el.mode.value === 'loadbalance') el.group.value = 'LOAD BALANCE';
        if(el.mode.value === 'fallback') el.group.value = 'FAILOVER PRO';
    });

    // Clear
    el.btnClear.addEventListener('click', () => {
        el.input.value = ''; el.outJS.textContent = '// Result...'; el.outYAML.textContent = '';
    });

    // Validate
    el.btnVal.addEventListener('click', () => {
        const lines = el.input.value.split('\n').filter(x => x.trim());
        const valid = lines.map(l => parseAny(l)).filter(x => x && !x.error).length;
        alert(`Detected: ${lines.length} lines.\nValid Nodes: ${valid}`);
    });

    // Generate
    el.btnGen.addEventListener('click', () => {
        const lines = el.input.value.split('\n').filter(x => x.trim());
        const nodes = lines.map(l => parseAny(l)).filter(x => x && !x.error);
        if(!nodes.length) return alert('No valid config found!');
        
        const clashNodes = nodes.map(n => nodeToClash(n, { skipCert: el.skip.checked }));
        const js = makeOverride(clashNodes, {
            mode: el.mode.value, interval: Number(el.interval.value), groupName: el.group.value,
            autoInsert: el.auto.checked, adblock: el.ad.checked, dns: el.dns.value, weights: el.lbWeights.value
        });
        
        el.outJS.textContent = js;
        const yaml = `proxies:\n${clashNodes.map(n=>`  - { name: "${n.name}", type: ${n.type} }`).join('\n')}\nproxy-groups:\n  - name: "${el.group.value}"\n    type: ${el.mode.value}\n    proxies:\n${clashNodes.map(n=>`      - "${n.name}"`).join('\n')}`;
        el.outYAML.textContent = yaml;
        
        // Auto scroll to result on mobile
        if(window.innerWidth < 768) $('.output-section').scrollIntoView({behavior: "smooth"});
    });

    // Copy/Download
    $('#fc-copy-js').addEventListener('click', () => { navigator.clipboard.writeText(el.outJS.textContent).then(()=>alert('JS Copied!')); });
    $('#fc-download-js').addEventListener('click', () => { downloadText('flyclash-override.js', el.outJS.textContent, 'application/javascript'); });
    
    // Tabs
    $$('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            $$('.tab-btn').forEach(b => b.classList.remove('active')); btn.classList.add('active');
            $$('.code-block').forEach(c => c.classList.remove('active'));
            $(`#fc-${btn.dataset.target}`).classList.add('active');
            if(btn.dataset.target==='yaml') { $('#fc-copy-js').classList.add('hidden'); $('#fc-download-js').classList.add('hidden'); $('#fc-copy-yaml').classList.remove('hidden'); }
            else { $('#fc-copy-js').classList.remove('hidden'); $('#fc-download-js').classList.remove('hidden'); $('#fc-copy-yaml').classList.add('hidden'); }
        });
    });
});
