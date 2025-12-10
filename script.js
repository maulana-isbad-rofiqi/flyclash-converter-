/* ===========================================================
   FlyClash Converter PRO - Developer: Itsbad
   =========================================================== */

// Utility Selectors
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

// --- Data Penjelasan (Pop-up Content) ---
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
        <br><i>Tips: Bisa paste banyak akun sekaligus.</i>
    `,
    mode: `
        <strong>Mode Strategy</strong><br>
        Menentukan bagaimana FlyClash memilih akun:<br><br>
        1. <strong>🚀 Auto Best Ping:</strong> Otomatis pilih yang tercepat.<br>
        2. <strong>👆 Manual:</strong> Pilih sendiri secara manual.<br>
        3. <strong>⚖️ Load Balance:</strong> Menggabungkan speed semua akun.<br>
        4. <strong>🛡️ Failover:</strong> Akun cadangan otomatis jika akun utama mati.<br>
        5. <strong>🔥 Hybrid:</strong> Membuat 3 grup sekaligus (Auto, Manual, & Fallback).
    `,
    interval: `
        <strong>Interval (Detik)</strong><br>
        Seberapa sering aplikasi mengecek ping ke server. Semakin kecil angka, semakin cepat deteksi akun mati.
    `,
    group: `
        <strong>Group Name</strong><br>
        Nama grup proxy yang akan muncul di menu utama FlyClash.
    `,
    skipcert: `
        <strong>Skip Certificate</strong><br>
        Jika ON, aplikasi akan mengabaikan error SSL/TLS. Wajib ON untuk akun gratisan.
    `,
    adblock: `
        <strong>AdBlock</strong><br>
        Memasukkan rules untuk memblokir iklan (Google Ads, DoubleClick) secara otomatis.
    `,
    autoinsert: `
        <strong>Auto Insert</strong><br>
        Otomatis menyuntikkan grup ini ke dalam grup 'Proxy' atau 'Select' bawaan FlyClash.
    `,
    weights: `
        <strong>Load Balance Weights</strong><br>
        Mengatur pembagian trafik. Contoh: "50,20" (Akun 1 dapat 50%, Akun 2 dapat 20%). Kosongkan untuk bagi rata.
    `,
    dns: `
        <strong>Custom DNS</strong><br>
        Menggunakan DNS khusus (Google/Cloudflare) untuk membuka situs yang diblokir.
    `
};

// --- Utilities Helper ---
const downloadText = (filename, content, type = 'text/plain') => {
    const a = document.createElement('a');
    const url = URL.createObjectURL(new Blob([content], { type }));
    a.href = url; 
    a.download = filename;
    document.body.appendChild(a); 
    a.click();
    document.body.removeChild(a); 
    URL.revokeObjectURL(url);
};

const tryAtob = (str) => {
    try { return atob(str); } catch (e) { return null; }
};

// --- Fungsi Parsing (Menerjemahkan Link) ---

function parseQuery(queryString) {
    const query = {};
    if (!queryString) return query;
    const pairs = queryString.split('&');
    for (const pair of pairs) {
        const [key, value] = pair.split('=');
        if (key) query[decodeURIComponent(key)] = decodeURIComponent(value || '');
    }
    return query;
}

function parseVLESS(raw) {
    try {
        const s = raw.replace(/^vless:\/\//i, '');
        const hashIndex = s.indexOf('#');
        const name = hashIndex === -1 ? undefined : decodeURIComponent(s.slice(hashIndex + 1));
        const urlPart = hashIndex === -1 ? s : s.slice(0, hashIndex);
        
        const qIndex = urlPart.indexOf('?');
        const qStr = qIndex === -1 ? '' : urlPart.slice(qIndex + 1);
        const mainPart = qIndex === -1 ? urlPart : urlPart.slice(0, qIndex);
        
        const query = parseQuery(qStr);
        const atIndex = mainPart.indexOf('@');
        const uuid = atIndex === -1 ? '' : mainPart.slice(0, atIndex);
        const hostPort = atIndex === -1 ? mainPart : mainPart.slice(atIndex + 1);
        
        const colonIndex = hostPort.lastIndexOf(':');
        const host = colonIndex === -1 ? hostPort : hostPort.slice(0, colonIndex);
        const port = colonIndex === -1 ? 443 : parseInt(hostPort.slice(colonIndex + 1), 10);

        return {
            proto: 'vless',
            type: 'vless',
            name: (name || uuid || `${host}:${port}`) + '-' + Math.random().toString(36).slice(2, 6),
            uuid: uuid,
            host: host,
            port: port,
            network: query.type || 'ws',
            path: query.path || '/',
            sni: query.sni || query.host || host,
            security: query.security || 'tls',
            raw: raw
        };
    } catch (e) { return { error: true }; }
}

function parseVMess(raw) {
    try {
        const s = raw.replace(/^vmess:\/\//i, '');
        let config = null;
        
        if (s.trim().startsWith('{')) {
            config = JSON.parse(s);
        } else {
            const decoded = tryAtob(s);
            if (!decoded) return { error: true };
            config = JSON.parse(decoded);
        }

        const server = config.add || (config.vnext && config.vnext[0] && config.vnext[0].address) || '';
        const port = parseInt(config.port || 443, 10);
        
        return {
            proto: 'vmess',
            type: 'vmess',
            name: (config.ps || `${server}:${port}`) + '-' + Math.random().toString(36).slice(2, 6),
            server: server,
            port: port,
            uuid: config.id || '',
            network: config.net || 'tcp',
            path: config.path || '/',
            host: config.host || config.sni || server,
            tls: config.tls === 'tls' || config.tls === true
        };
    } catch (e) { return { error: true }; }
}

function parseTrojan(raw) {
    try {
        const s = raw.replace(/^trojan:\/\//i, '');
        const hashIndex = s.indexOf('#');
        const name = hashIndex === -1 ? undefined : decodeURIComponent(s.slice(hashIndex + 1));
        const urlPart = hashIndex === -1 ? s : s.slice(0, hashIndex);
        
        const qIndex = urlPart.indexOf('?');
        const qStr = qIndex === -1 ? '' : urlPart.slice(qIndex + 1);
        const mainPart = qIndex === -1 ? urlPart : urlPart.slice(0, qIndex);
        
        const query = parseQuery(qStr);
        const atIndex = mainPart.indexOf('@');
        const password = atIndex === -1 ? '' : mainPart.slice(0, atIndex);
        const hostPort = atIndex === -1 ? mainPart : mainPart.slice(atIndex + 1);
        
        const colonIndex = hostPort.lastIndexOf(':');
        const host = colonIndex === -1 ? hostPort : hostPort.slice(0, colonIndex);
        const port = colonIndex === -1 ? 443 : parseInt(hostPort.slice(colonIndex + 1), 10);

        return {
            proto: 'trojan',
            type: 'trojan',
            name: (name || `${host}:${port}`) + '-' + Math.random().toString(36).slice(2, 6),
            password: password,
            host: host,
            port: port,
            sni: query.sni || host
        };
    } catch (e) { return { error: true }; }
}

function parseSS(raw) {
    try {
        const s = raw.replace(/^ss:\/\//i, '');
        let name, server, port, cipher, password;

        if (s.includes('@') && !s.startsWith('@')) {
            // Format Baru: method:pass@server:port
            const hashIndex = s.indexOf('#');
            name = hashIndex === -1 ? undefined : decodeURIComponent(s.slice(hashIndex + 1));
            const urlPart = hashIndex === -1 ? s : s.slice(0, hashIndex);
            
            const atIndex = urlPart.indexOf('@');
            const methods = urlPart.slice(0, atIndex);
            const hostPort = urlPart.slice(atIndex + 1);
            
            const colonIndex = hostPort.lastIndexOf(':');
            server = colonIndex === -1 ? hostPort : hostPort.slice(0, colonIndex);
            port = colonIndex === -1 ? 8388 : parseInt(hostPort.slice(colonIndex + 1), 10);
            
            cipher = methods.split(':')[0];
            password = methods.split(':')[1] || '';
        } else {
            // Format Lama (Base64)
            const hashIndex = s.indexOf('#');
            const base = hashIndex === -1 ? s : s.slice(0, hashIndex);
            const decoded = tryAtob(base);
            if (!decoded) return { error: true };
            
            const atIndex = decoded.indexOf('@');
            const methods = decoded.slice(0, atIndex);
            const hostPort = decoded.slice(atIndex + 1);
            
            const colonIndex = hostPort.lastIndexOf(':');
            server = colonIndex === -1 ? hostPort : hostPort.slice(0, colonIndex);
            port = colonIndex === -1 ? 8388 : parseInt(hostPort.slice(colonIndex + 1), 10);
            
            cipher = methods.split(':')[0];
            password = methods.split(':')[1] || '';
            name = hashIndex === -1 ? `${server}:${port}` : decodeURIComponent(s.slice(hashIndex + 1));
        }
        
        return {
            proto: 'ss',
            type: 'shadowsocks',
            name: name + '-' + Math.random().toString(36).slice(2, 6),
            server: server,
            port: port,
            cipher: cipher,
            password: password
        };
    } catch (e) { return { error: true }; }
}

function parseAny(line) {
    const l = line.trim();
    if (!l) return null;
    if (/^vless:\/\//i.test(l)) return parseVLESS(l);
    if (/^vmess:\/\//i.test(l)) return parseVMess(l);
    if (/^trojan:\/\//i.test(l)) return parseTrojan(l);
    if (/^ss:\/\//i.test(l)) return parseSS(l);
    
    // Cek Base64 murni (biasanya VMess)
    const m = l.replace(/^vmess:\/\//i, '');
    if (/^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$/.test(m)) return parseVMess('vmess://' + m);
    
    return { error: true, raw: l };
}

// --- Generator Logic (Membuat Format Clash) ---

function nodeToClash(node, opts = {}) {
    if (!node || node.error) return null;
    
    const base = {
        name: node.name,
        server: node.host || node.server,
        port: node.port
    };
    const skip = opts.skipCert;

    if (node.type === 'vless') {
        return {
            ...base,
            type: 'vless',
            uuid: node.uuid,
            tls: true,
            'skip-cert-verify': skip,
            servername: node.sni || node.host,
            network: node.network,
            'ws-opts': {
                path: node.path,
                headers: { Host: node.sni || node.host }
            }
        };
    }
    if (node.type === 'vmess') {
        return {
            ...base,
            type: 'vmess',
            uuid: node.uuid,
            alterId: 0,
            tls: node.tls,
            'skip-cert-verify': skip,
            network: node.network,
            'ws-opts': node.network === 'ws' ? {
                path: node.path,
                headers: { Host: node.host }
            } : undefined
        };
    }
    if (node.type === 'trojan') {
        return {
            ...base,
            type: 'trojan',
            password: node.password,
            tls: true,
            'skip-cert-verify': skip,
            servername: node.sni || node.host
        };
    }
    if (node.type === 'shadowsocks') {
        return {
            ...base,
            type: 'shadowsocks',
            cipher: node.cipher,
            password: node.password
        };
    }
    return null;
}

function makeOverride(clashNodes, opts) {
    const dnsNames = (opts.dns || '8.8.8.8,1.1.1.1').split(',').map(x => x.trim()).filter(Boolean);
    const proxiesBlock = clashNodes.map(n => JSON.stringify(n, null, 4).replace(/\n/g, '\n        ')).join(',\n');
    const names = clashNodes.map(n => n.name);
    
    let newGroups = [];

    // --- LOGIKA HYBRID (Membuat 3 Grup Sekaligus) ---
    if (opts.mode === 'hybrid') {
        newGroups.push({
            name: `${opts.groupName} - AUTO`,
            type: 'url-test',
            url: 'https://www.gstatic.com/generate_204',
            interval: opts.interval,
            tolerance: 50,
            proxies: names
        });
        newGroups.push({
            name: `${opts.groupName} - FALLBACK`,
            type: 'fallback',
            url: 'https://www.gstatic.com/generate_204',
            interval: opts.interval,
            proxies: names
        });
        newGroups.push({
            name: `${opts.groupName} - MANUAL`,
            type: 'select',
            proxies: names
        });
    } 
    // --- LOGIKA MODE BIASA ---
    else {
        let groupObj = { name: opts.groupName, proxies: names };
        
        if (opts.mode === 'auto') {
            groupObj = { ...groupObj, type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: opts.interval, tolerance: 50 };
        } else if (opts.mode === 'loadbalance') {
            groupObj = { ...groupObj, type: 'load-balance', strategy: 'consistent-hashing' };
            if (opts.weights) {
                const w = opts.weights.split(',').map(Number).filter(n => !isNaN(n));
                if (w.length === names.length) groupObj.weights = w;
            }
        } else if (opts.mode === 'fallback') {
            groupObj = { ...groupObj, type: 'fallback', url: 'https://www.gstatic.com/generate_204', interval: opts.interval };
        } else {
            groupObj = { ...groupObj, type: 'select' };
        }
        
        newGroups.push(groupObj);
    }

    // Logic untuk menyuntikkan (Inject) grup baru ke grup bawaan
    const newGroupNames = newGroups.map(g => g.name);
    const autoInsert = opts.autoInsert ? `
    try {
        const targetGroups = ['🚀 节点选择', 'Proxy', 'Auto', 'Select', 'GLOBAL'];
        (config['proxy-groups'] || []).forEach(g => {
            if (targetGroups.includes(g.name) || g.type === 'select') {
                g.proxies = g.proxies || [];
                // Masukkan grup baru ke grup yang sudah ada
                ${JSON.stringify(newGroupNames)}.forEach(newGroup => {
                    if (!g.proxies.includes(newGroup)) g.proxies.unshift(newGroup);
                });
            }
        });
        
        // Tambahkan definisi grup baru ke paling atas
        const newGroupsDef = ${JSON.stringify(newGroups, null, 4)};
        newGroupsDef.forEach(g => config['proxy-groups'].unshift(g));
        
    } catch(e) {}` 
    : 
    `// Manual Insert Mode
    const newGroupsDef = ${JSON.stringify(newGroups, null, 4)};
    newGroupsDef.forEach(g => config['proxy-groups'].push(g));`;

    // Aturan AdBlock
    const adRules = opts.adblock ? [
        "DOMAIN-SUFFIX,ads.google.com,REJECT",
        "DOMAIN-KEYWORD,adservice,REJECT",
        "DOMAIN-KEYWORD,analytics,REJECT",
        "DOMAIN-SUFFIX,doubleclick.net,REJECT"
    ] : [];

    // Template Output Akhir
    return `// FlyClash Override Generated by Itsbad
// Mode: ${opts.mode} | Interval: ${opts.interval}s

function main(config) {
    // 1. Masukkan Proxy (Akun)
    config.proxies = (config.proxies || []).concat([
        ${proxiesBlock}
    ]);

    // 2. Pastikan proxy-groups ada
    if (!config['proxy-groups']) config['proxy-groups'] = [];

    // 3. Masukkan Group Baru (Auto Insert Logic)
    ${autoInsert}

    // 4. Setup DNS
    config.dns = config.dns || {};
    config.dns.enable = true;
    config.dns.nameserver = ${JSON.stringify(dnsNames)};

    // 5. Setup Rules (AdBlock)
    ${adRules.length ? `config.rules = (config.rules || []).concat(${JSON.stringify(adRules)});` : ''}

    return config;
}`;
}

// --- Event Listeners (Interaksi User) ---
document.addEventListener('DOMContentLoaded', () => {
    // Inisialisasi Ikon
    lucide.createIcons();

    // Cache Element
    const el = {
        input: $('#fc-input'),
        btnGen: $('#fc-generate'),
        btnClear: $('#fc-clear'),
        btnVal: $('#fc-validate'),
        outJS: $('#fc-js'),
        outYAML: $('#fc-yaml'),
        mode: $('#fc-mode'),
        interval: $('#fc-interval'),
        group: $('#fc-group'),
        skip: $('#fc-skip'),
        ad: $('#fc-ad'),
        auto: $('#fc-autoadd'),
        lbArea: $('#fc-lb-area'),
        lbWeights: $('#fc-lb'),
        dns: $('#fc-dns'),
        modal: $('#info-modal'),
        modalTitle: $('#modal-title'),
        modalDesc: $('#modal-desc'),
        closeModal: $('#close-modal')
    };

    // --- Modal Logic ---
    $$('.info-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const key = btn.dataset.key;
            if (explanations[key]) {
                el.modalTitle.textContent = "Info";
                el.modalDesc.innerHTML = explanations[key];
                el.modal.classList.remove('hidden');
            }
        });
    });

    const hideModal = () => el.modal.classList.add('hidden');
    el.closeModal.addEventListener('click', hideModal);
    el.modal.addEventListener('click', (e) => {
        if (e.target === el.modal) hideModal();
    });

    // --- Mode Change Logic ---
    el.mode.addEventListener('change', () => {
        // Tampilkan/Sembunyikan LB Weights
        if (el.mode.value === 'loadbalance') {
            el.lbArea.classList.remove('hidden');
        } else {
            el.lbArea.classList.add('hidden');
        }
        
        // Auto Ganti Nama Group
        if (el.mode.value === 'auto') el.group.value = 'AUTO BEST PING';
        if (el.mode.value === 'manual') el.group.value = 'MANUAL SELECT';
        if (el.mode.value === 'loadbalance') el.group.value = 'LOAD BALANCE';
        if (el.mode.value === 'fallback') el.group.value = 'FAILOVER PRO';
        if (el.mode.value === 'hybrid') el.group.value = 'HYBRID GROUP';
    });

    // --- Button Actions ---
    el.btnClear.addEventListener('click', () => {
        el.input.value = '';
        el.outJS.textContent = '// Hasil script akan muncul di sini...';
        el.outYAML.textContent = '';
    });

    el.btnVal.addEventListener('click', () => {
        const lines = el.input.value.split('\n').filter(x => x.trim());
        const valid = lines.map(l => parseAny(l)).filter(x => x && !x.error).length;
        alert(`Total Baris: ${lines.length}\nValid Config: ${valid}`);
    });

    el.btnGen.addEventListener('click', () => {
        const lines = el.input.value.split('\n').filter(x => x.trim());
        const nodes = lines.map(l => parseAny(l)).filter(x => x && !x.error);
        
        if (!nodes.length) return alert('Tidak ada config valid yang ditemukan!');

        const clashNodes = nodes.map(n => nodeToClash(n, { skipCert: el.skip.checked }));
        
        const jsCode = makeOverride(clashNodes, {
            mode: el.mode.value,
            interval: Number(el.interval.value),
            groupName: el.group.value,
            autoInsert: el.auto.checked,
            adblock: el.ad.checked,
            dns: el.dns.value,
            weights: el.lbWeights.value
        });

        el.outJS.textContent = jsCode;

        // Generate Simple YAML Preview
        const yamlCode = `proxies:\n${clashNodes.map(n => `  - { name: "${n.name}", type: ${n.type} }`).join('\n')}\nproxy-groups:\n  - name: "${el.group.value}"\n    type: ${el.mode.value}`;
        el.outYAML.textContent = yamlCode;

        // Auto Scroll di HP
        if (window.innerWidth < 768) {
            $('.output-section').scrollIntoView({ behavior: "smooth" });
        }
    });

    // Copy & Download
    $('#fc-copy-js').addEventListener('click', () => {
        navigator.clipboard.writeText(el.outJS.textContent).then(() => alert('JS Override berhasil disalin!'));
    });

    $('#fc-download-js').addEventListener('click', () => {
        downloadText('flyclash-override.js', el.outJS.textContent, 'application/javascript');
    });

    // Tab Switching (JS / YAML)
    $$('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            $$('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            $$('.code-block').forEach(c => c.classList.remove('active'));
            $(`#fc-${btn.dataset.target}`).classList.add('active');
            
            if (btn.dataset.target === 'yaml') {
                $('#fc-copy-js').classList.add('hidden');
                $('#fc-download-js').classList.add('hidden');
                $('#fc-copy-yaml').classList.remove('hidden');
            } else {
                $('#fc-copy-js').classList.remove('hidden');
                $('#fc-download-js').classList.remove('hidden');
                $('#fc-copy-yaml').classList.add('hidden');
            }
        });
    });
});
