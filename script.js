/* ===========================================================
   FlyClash Converter PRO - Developer: Itsbad
   =========================================================== */

const $ = (s) => document.querySelector(s);
const tryAtob = (s) => { try { return atob(s); } catch (e) { return null; } };
const downloadText = (filename, content, type = 'text/plain') => {
    const a = document.createElement('a');
    const url = URL.createObjectURL(new Blob([content], { type }));
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
};

// --- Parsing Logic (Sama seperti sebelumnya) ---
function parseQuery(q){ const o={}; if(!q) return o; q.split('&').forEach(p=>{ const i=p.indexOf('='); if(i===-1) o[decodeURIComponent(p)]=''; else o[decodeURIComponent(p.slice(0,i))]=decodeURIComponent(p.slice(i+1)); }); return o; }

function parseVLESS(raw){
    try{
        const s = raw.replace(/^vless:\/\//i,''); const hash = s.indexOf('#'); const name = hash===-1?undefined:decodeURIComponent(s.slice(hash+1));
        const beforeHash = hash===-1? s : s.slice(0,hash);
        const qIdx = beforeHash.indexOf('?'); const qStr = qIdx===-1? '': beforeHash.slice(qIdx+1); const beforeQ = qIdx===-1? beforeHash: beforeHash.slice(0,qIdx);
        const query = parseQuery(qStr);
        const at = beforeQ.indexOf('@'); const user = at===-1? '': beforeQ.slice(0,at); const hostport = at===-1? beforeQ: beforeQ.slice(at+1);
        const colon = hostport.lastIndexOf(':'); const host = colon===-1? hostport: hostport.slice(0,colon); const port = colon===-1?443:parseInt(hostport.slice(colon+1),10);
        return { proto:'vless', type:'vless', name:(name||user||`${host}:${port}`)+'-'+Math.random().toString(36).slice(2,6), uuid:user, host, port, network:query.type||'ws', path:query.path||'/', sni:query.sni||query.host||host, security:query.security||'tls', raw };
    }catch(e){ return { error:true, raw, message:e.message } }
}

function parseVMess(raw){
    try{
        const s = raw.replace(/^vmess:\/\//i,''); let j=null;
        if(s.trim().startsWith('{')) j=JSON.parse(s);
        else { const dec = tryAtob(s); if(!dec) throw new Error('vmess decode failed'); j=JSON.parse(dec); }
        const server = j.add || (j.vnext && j.vnext[0] && j.vnext[0].address) || '';
        const port = parseInt(j.port || (j.vnext && j.vnext[0] && j.vnext[0].port) || 443,10);
        const uuid = j.id || j.uuid || (j.vnext&&j.vnext[0]&&j.vnext[0].id)||'';
        const net = j.net||j.network||'tcp'; const path = j.path || (j.ws && j.ws.path) || '/';
        const host = (j.host || (j.ws && j.ws.headers && (j.ws.headers.Host||j.ws.headers.host)) || j.sni) || server;
        return { proto:'vmess', type:'vmess', name:(j.ps||`${server}:${port}`)+'-'+Math.random().toString(36).slice(2,6), server, port, uuid, network:net, path, host, tls: j.tls==='tls'||j.tls===true||false, raw };
    }catch(e){ return { error:true, raw, message:e.message } }
}

function parseTrojan(raw){
    try{
        const s = raw.replace(/^trojan:\/\//i,''); const hash = s.indexOf('#'); const name = hash===-1?undefined:decodeURIComponent(s.slice(hash+1));
        const beforeHash = hash===-1? s : s.slice(0,hash); const qIdx = beforeHash.indexOf('?'); const qStr = qIdx===-1? '': beforeHash.slice(qIdx+1); const beforeQ = qIdx===-1? beforeHash : beforeHash.slice(0,qIdx);
        const query = parseQuery(qStr);
        const at = beforeQ.indexOf('@'); const password = at===-1? '': beforeQ.slice(0,at); const hostport = at===-1? beforeQ : beforeQ.slice(at+1);
        const colon = hostport.lastIndexOf(':'); const host = colon===-1? hostport : hostport.slice(0,colon); const port = colon===-1?443:parseInt(hostport.slice(colon+1),10);
        return { proto:'trojan', type:'trojan', name:(name||`${host}:${port}`)+'-'+Math.random().toString(36).slice(2,6), password, host, port, sni: query.sni || host, raw };
    }catch(e){ return { error:true, raw, message:e.message } }
}

function parseSS(raw){
    try{
        const s = raw.replace(/^ss:\/\//i,''); if(s.includes('@') && !s.startsWith('@')){
            const hash = s.indexOf('#'); const name = hash===-1?undefined:decodeURIComponent(s.slice(hash+1));
            const beforeHash = hash===-1? s : s.slice(0,hash); const at = beforeHash.indexOf('@'); const methods = beforeHash.slice(0,at); const hostport = beforeHash.slice(at+1);
            const colon = hostport.lastIndexOf(':'); const host = colon===-1? hostport: hostport.slice(0,colon); const port = colon===-1?8388:parseInt(hostport.slice(colon+1),10);
            const method = methods.split(':')[0]; const password = methods.split(':')[1]||'';
            return { proto:'ss', type:'shadowsocks', name:(name||`${host}:${port}`)+'-'+Math.random().toString(36).slice(2,6), server:host, port, cipher:method, password, raw };
        } else {
            const hash = s.indexOf('#'); const base = hash===-1? s : s.slice(0,hash); const decoded = tryAtob(base);
            if(!decoded) throw new Error('ss decode failed'); const at = decoded.indexOf('@'); const methods = decoded.slice(0,at); const hostport = decoded.slice(at+1);
            const colon = hostport.lastIndexOf(':'); const host = colon===-1? hostport: hostport.slice(0,colon); const port = colon===-1?8388:parseInt(hostport.slice(colon+1),10);
            const method = methods.split(':')[0]; const password = methods.split(':')[1]||'';
            return { proto:'ss', type:'shadowsocks', name:(hash===-1?`${host}:${port}`:decodeURIComponent(s.slice(hash+1)))+'-'+Math.random().toString(36).slice(2,6), server:host, port, cipher:method, password, raw };
        }
    }catch(e){ return { error:true, raw, message:e.message } }
}

function parseAny(line){
    if(!line || !line.trim()) return null;
    const l = line.trim();
    if(/^vless:\/\//i.test(l)) return parseVLESS(l);
    if(/^vmess:\/\//i.test(l)) return parseVMess(l);
    if(/^trojan:\/\//i.test(l)) return parseTrojan(l);
    if(/^ss:\/\//i.test(l)) return parseSS(l);
    const m = l.replace(/^vmess:\/\//i,''); if(/^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$/.test(m)) return parseVMess('vmess://'+m);
    return { error:true, raw:l, message:'Unknown format' };
}

// --- Generator Logic ---
function nodeToClash(node, opts={}){
    if(!node || node.error) return null;
    const skipCert = !!opts.skipCert;
    const proto = (node.proto||node.type||'').toLowerCase();
    
    // Common Base
    let base = { name: node.name, server: node.host||node.server, port: node.port };

    if(proto==='vless'){
        return { ...base, type: 'vless', uuid: node.uuid, tls: true, 'skip-cert-verify': skipCert, servername: node.sni||node.host, network: node.network||'ws', 'ws-opts': { path: node.path||'/', headers: node.sni?{Host:node.sni}:{Host:node.host} } };
    }
    if(proto==='vmess'){
        return { ...base, type: 'vmess', uuid: node.uuid, alterId: node.alterId||0, tls: !!node.tls, 'skip-cert-verify': skipCert, network: node.network||'ws', 'ws-opts': node.network==='ws'?{ path: node.path||'/', headers: node.host?{Host:node.host}:{}}:undefined };
    }
    if(proto==='trojan'){
        return { ...base, type: 'trojan', password: node.password, tls: true, 'skip-cert-verify': skipCert, servername: node.sni||node.host };
    }
    if(proto==='ss' || proto==='shadowsocks'){
        return { ...base, type: 'shadowsocks', cipher: node.cipher, password: node.password };
    }
    return null;
}

function makeOverride(clashNodes, opts){
    const dnsNames = (opts.dns || '8.8.8.8,1.1.1.1').split(',').map(x=>x.trim()).filter(Boolean);
    const proxiesBlock = clashNodes.map(n=>JSON.stringify(n,null,4).replace(/\n/g,'\n        ')).join(',\n');
    const names = clashNodes.map(n=>n.name);
    
    let groupObj = { name: opts.groupName, proxies: names };
    
    // Strategy logic updated
    if(opts.mode === 'auto') {
        groupObj = { ...groupObj, type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: opts.interval, tolerance: 50 };
    } else if (opts.mode === 'loadbalance') {
        groupObj = { ...groupObj, type: 'load-balance', strategy: 'consistent-hashing' };
    } else if (opts.mode === 'fallback') {
        groupObj = { ...groupObj, type: 'fallback', url: 'https://www.gstatic.com/generate_204', interval: opts.interval };
    } else {
        groupObj = { ...groupObj, type: 'select' };
    }

    const autoInsertCode = opts.autoInsert ? `
    try {
        const targetGroups = ['🚀 节点选择', 'Proxy', 'Auto', 'Select', 'GLOBAL'];
        (config['proxy-groups']||[]).forEach(g=>{
            if(targetGroups.includes(g.name) || g.type === 'select'){ 
                g.proxies = g.proxies || []; 
                if(!g.proxies.includes("${opts.groupName}")) g.proxies.unshift("${opts.groupName}"); 
            }
        });
        config['proxy-groups'].unshift(${JSON.stringify(groupObj, null, 4)});
    } catch(e) {} ` : `config['proxy-groups'].push(${JSON.stringify(groupObj, null, 4)});`;

    const adRules = opts.adblock ? [
        "DOMAIN-SUFFIX,ads.google.com,REJECT",
        "DOMAIN-KEYWORD,adservice,REJECT",
        "DOMAIN-KEYWORD,analytics,REJECT",
        "DOMAIN-SUFFIX,doubleclick.net,REJECT"
    ] : [];

    return `// FlyClash Override Generated by Itsbad
// Mode: ${opts.mode} | Interval: ${opts.interval}s

function main(config){
    config.proxies = (config.proxies || []).concat([
        ${proxiesBlock}
    ]);
    
    if(!config['proxy-groups']) config['proxy-groups'] = [];
    
    ${autoInsertCode}

    config.dns = config.dns || {};
    config.dns.enable = true;
    config.dns.nameserver = ${JSON.stringify(dnsNames)};

    ${adRules.length ? `config.rules = (config.rules || []).concat(${JSON.stringify(adRules)});` : ''}

    return config;
}`;
}

// --- Event Wiring ---
document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();

    const el = {
        input: $('#fc-input'),
        btnGen: $('#fc-generate'),
        btnClear: $('#fc-clear'),
        btnVal: $('#fc-validate'),
        outputJS: $('#fc-js'),
        outputYAML: $('#fc-yaml'),
        mode: $('#fc-mode'),
        interval: $('#fc-interval'),
        group: $('#fc-group'),
        skip: $('#fc-skip'),
        ad: $('#fc-ad'),
        auto: $('#fc-autoadd'),
        lbArea: $('#fc-lb-area'),
        dns: $('#fc-dns'),
        tabs: document.querySelectorAll('.tab-btn'),
        copy: { js: $('#fc-copy-js'), yaml: $('#fc-copy-yaml') },
        down: { js: $('#fc-download-js') }
    };

    el.mode.addEventListener('change', () => {
        if(el.mode.value === 'loadbalance') el.lbArea.classList.remove('hidden');
        else el.lbArea.classList.add('hidden');
        
        if(el.mode.value === 'auto') el.group.value = 'AUTO BEST PING';
        if(el.mode.value === 'manual') el.group.value = 'MANUAL SELECT';
        if(el.mode.value === 'loadbalance') el.group.value = 'LOAD BALANCE';
        if(el.mode.value === 'fallback') el.group.value = 'FAILOVER PRO';
    });

    el.tabs.forEach(btn => {
        btn.addEventListener('click', () => {
            el.tabs.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            document.querySelectorAll('.code-block').forEach(c => c.classList.remove('active'));
            $(`#fc-${btn.dataset.target}`).classList.add('active');
            
            if(btn.dataset.target === 'yaml') {
                el.copy.js.classList.add('hidden');
                el.down.js.classList.add('hidden');
                el.copy.yaml.classList.remove('hidden');
            } else {
                el.copy.js.classList.remove('hidden');
                el.down.js.classList.remove('hidden');
                el.copy.yaml.classList.add('hidden');
            }
        });
    });

    el.btnClear.addEventListener('click', () => {
        el.input.value = '';
        el.outputJS.textContent = '// Ready...';
        el.outputYAML.textContent = '';
    });

    el.btnVal.addEventListener('click', () => {
        const lines = el.input.value.split('\n').filter(x => x.trim());
        const valid = lines.map(l => parseAny(l)).filter(x => x && !x.error).length;
        alert(`Detected: ${lines.length} lines.\nValid Nodes: ${valid}\nInvalid: ${lines.length - valid}`);
    });

    el.btnGen.addEventListener('click', () => {
        const lines = el.input.value.split('\n').filter(x => x.trim());
        const nodes = lines.map(l => parseAny(l)).filter(x => x && !x.error);
        
        if(!nodes.length) return alert('No valid configs found!');

        const clashNodes = nodes.map(n => nodeToClash(n, { skipCert: el.skip.checked }));
        const opts = {
            mode: el.mode.value,
            interval: Number(el.interval.value),
            groupName: el.group.value,
            autoInsert: el.auto.checked,
            adblock: el.ad.checked,
            dns: el.dns.value
        };

        const jsCode = makeOverride(clashNodes, opts);
        el.outputJS.textContent = jsCode;

        const yamlCode = `proxies:\n${clashNodes.map(n => `  - { name: "${n.name}", type: ${n.type}, server: ${n.server}, port: ${n.port} }`).join('\n')}\n\nproxy-groups:\n  - name: "${opts.groupName}"\n    type: ${opts.mode}\n    proxies:\n${clashNodes.map(n => `      - "${n.name}"`).join('\n')}`;
        el.outputYAML.textContent = yamlCode;
    });

    el.copy.js.addEventListener('click', () => {
        const content = el.outputJS.textContent;
        if(content.length < 50) return;
        navigator.clipboard.writeText(content).then(() => alert('JS Override copied!'));
    });

    el.down.js.addEventListener('click', () => {
        const content = el.outputJS.textContent;
        if(content.length < 50) return;
        downloadText('flyclash-override.js', content, 'application/javascript');
    });
    
    el.copy.yaml.addEventListener('click', () => {
         const content = el.outputYAML.textContent;
         if(!content) return;
         navigator.clipboard.writeText(content).then(() => alert('YAML copied!'));
    });
});
