const { useState, useEffect } = React;
const { Zap, Shield, Globe, Copy, Download, Code, Settings, Play, RefreshCw, CheckCircle, Server } = lucide;

// --- 1. CONFIG PARSER ---
const parseConfig = (line, index) => {
    try {
        if (line.startsWith("vmess://")) {
            const b64 = line.replace("vmess://", "");
            const conf = JSON.parse(atob(b64));
            return {
                name: conf.ps || `VMess-${index}`,
                type: "vmess",
                server: conf.add,
                port: parseInt(conf.port),
                uuid: conf.id,
                alterId: parseInt(conf.aid || 0),
                cipher: "auto",
                tls: conf.tls === "tls",
                servername: conf.host || conf.sni || "",
                network: conf.net || "ws",
                "ws-opts": conf.net === "ws" ? { path: conf.path || "/", headers: { Host: conf.host || "" } } : undefined
            };
        } else if (line.startsWith("vless://") || line.startsWith("trojan://")) {
            const url = new URL(line);
            const isVless = line.startsWith("vless://");
            const params = url.searchParams;
            return {
                name: decodeURIComponent(url.hash.slice(1)) || `${isVless ? 'VLESS' : 'Trojan'}-${index}`,
                type: isVless ? "vless" : "trojan",
                server: url.hostname,
                port: parseInt(url.port),
                uuid: url.username,
                password: isVless ? undefined : url.username,
                tls: params.get("security") === "tls" || params.get("security") === "reality",
                servername: params.get("sni") || "",
                network: params.get("type") || "tcp",
                "ws-opts": params.get("type") === "ws" ? { path: params.get("path") || "/", headers: { Host: params.get("host") || "" } } : undefined
            };
        }
        return null;
    } catch (e) { return null; }
};

// --- 2. MAIN APP COMPONENT ---
const App = () => {
    // Input & Output State
    const [input, setInput] = useState("");
    const [outputJS, setOutputJS] = useState("");
    const [outputYAML, setOutputYAML] = useState("");
    const [nodesCount, setNodesCount] = useState(0);
    
    // Configuration State
    const [mode, setMode] = useState("url-test");
    const [interval, setIntervalVal] = useState(300);
    const [groupName, setGroupName] = useState("AUTO BEST PING");
    
    // DNS New State (Anti-Bengong)
    const [dnsMode, setDnsMode] = useState("default"); // default, fake-ip, custom
    const [customDnsIP, setCustomDnsIP] = useState("8.8.8.8, 1.1.1.1");
    
    // Toggles
    const [skipCert, setSkipCert] = useState(true);
    const [adblock, setAdblock] = useState(false);
    const [autoInsert, setAutoInsert] = useState(true);

    // Auto update Group Name
    useEffect(() => {
        if(mode === 'url-test') setGroupName("AUTO BEST PING");
        if(mode === 'load-balance') setGroupName("LOAD BALANCE");
        if(mode === 'fallback') setGroupName("FALLBACK");
        if(mode === 'select') setGroupName("MANUAL SELECT");
    }, [mode]);

    // --- GENERATOR LOGIC ---
    const generate = () => {
        const lines = input.split('\n').filter(l => l.trim().length > 5);
        const nodes = lines.map((l, i) => parseConfig(l.trim(), i)).filter(n => n !== null);
        setNodesCount(nodes.length);

        if (nodes.length === 0) {
            setOutputJS("// Tidak ada config valid yang ditemukan.");
            return;
        }

        // 1. Process Nodes
        nodes.forEach(n => {
            if (skipCert) n['skip-cert-verify'] = true;
            n.udp = true;
        });
        const nodesJson = JSON.stringify(nodes, null, 2);

        // 2. Process DNS (ANTI-BENGONG LOGIC)
        let dnsConfig = "";
        if (dnsMode === "default") {
            dnsConfig = "// DNS: Default (Mengikuti settingan asli FlyClash/System)";
        } else if (dnsMode === "fake-ip") {
            dnsConfig = `
    // DNS: Fake-IP Mode (Anti-Bengong)
    config.dns = {
        "enable": true,
        "ipv6": false,
        "listen": "0.0.0.0:1053",
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": ["*.lan", "*.local", "time.*.com", "wpad.+"],
        "default-nameserver": ["8.8.8.8", "1.1.1.1"],
        "nameserver": ["https://dns.google/dns-query", "https://1.1.1.1/dns-query"],
        "fallback": ["https://doh.pub/dns-query", "8.8.8.8"],
        "fallback-filter": { "geoip": true, "ipcidr": ["240.0.0.0/4"] }
    };`;
        } else {
            const dnsList = JSON.stringify(customDnsIP.split(',').map(d => d.trim()));
            dnsConfig = `
    // DNS: Custom User
    if (!config.dns) config.dns = {};
    config.dns.nameserver = ${dnsList};`;
        }

        // 3. Process Rules
        let rulesInject = "";
        if (adblock) {
            rulesInject = `
    const rules = [
        "DOMAIN-KEYWORD,ads,REJECT",
        "DOMAIN-SUFFIX,doubleclick.net,REJECT",
        "DOMAIN-SUFFIX,googleadservices.com,REJECT"
    ];
    config.rules = rules.concat(config.rules || []);`;
        }

        // 4. Construct Final Script
        const script = `// FlyClash Override Generated
// Created: ${new Date().toLocaleString()}
// Nodes: ${nodes.length}

function main(config) {
    const proxies = ${nodesJson};
    
    // 1. Tambahkan Proxy
    config.proxies = (config.proxies || []).concat(proxies);
    
    // 2. Buat Group Strategy
    const group = {
        "name": "${groupName}",
        "type": "${mode}",
        "url": "http://www.gstatic.com/generate_204",
        "interval": ${interval},
        "proxies": proxies.map(p => p.name)
    };
    
    if (!config['proxy-groups']) config['proxy-groups'] = [];
    
    // ${autoInsert ? "Insert ke posisi paling atas" : "Push ke bawah"}
    ${autoInsert ? "config['proxy-groups'].unshift(group);" : "config['proxy-groups'].push(group);"}

    // 3. DNS Configuration
    ${dnsConfig}

    // 4. Rules
    ${rulesInject}

    // 5. Auto Add to other Select Groups
    config['proxy-groups'].forEach(g => {
        if (g.type === 'select' && g.name !== "${groupName}") {
            g.proxies.push("${groupName}");
        }
    });

    return config;
}`;
        setOutputJS(script);
        
        // YAML Preview Simpel
        setOutputYAML(`proxies:\n${nodes.map(n => `  - { name: ${n.name}, type: ${n.type}, server: ${n.server} }`).join('\n')}\n\nproxy-groups:\n  - name: ${groupName}\n    type: ${mode}\n    proxies:\n${nodes.map(n => `      - ${n.name}`).join('\n')}`);
    };

    // --- UTILS ---
    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        alert("Berhasil disalin!");
    };

    const downloadFile = (content, filename) => {
        const blob = new Blob([content], { type: "text/javascript" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        a.click();
    };

    // --- RENDER UI ---
    return (
        <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            {/* HEADER */}
            <div className="lg:col-span-12 flex items-center justify-between mb-2">
                <div>
                    <h1 className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-primary to-accent flex items-center gap-2">
                        <Zap className="text-primary fill-current" /> FlyClash Converter <span className="text-xs border border-primary px-2 py-0.5 rounded text-primary">PRO</span>
                    </h1>
                </div>
            </div>

            {/* LEFT: INPUTS */}
            <div className="lg:col-span-5 space-y-6">
                
                {/* Input Box */}
                <div className="glass p-5 rounded-xl border-l-4 border-l-primary">
                    <label className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2 block">Input Config</label>
                    <textarea 
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        className="w-full h-48 bg-background border border-zinc-700 rounded-lg p-3 text-xs font-mono text-zinc-300 focus:border-primary focus:outline-none resize-none placeholder-zinc-700"
                        placeholder="Paste link vmess/vless/trojan di sini..."
                    ></textarea>
                    <div className="flex justify-between items-center mt-3">
                        <span className="text-xs text-zinc-500">{nodesCount} nodes detected</span>
                        <div className="flex gap-2">
                            <button onClick={() => setInput("")} className="px-3 py-1.5 text-xs text-red-400 hover:bg-red-500/10 rounded-md transition">Clear</button>
                            <button onClick={generate} className="px-4 py-1.5 bg-primary hover:bg-indigo-500 text-white text-xs font-bold rounded-md shadow-lg shadow-indigo-500/20 transition flex items-center gap-2">
                                <Play size={14}/> Generate
                            </button>
                        </div>
                    </div>
                </div>

                {/* Mode Grid */}
                <div className="grid grid-cols-2 gap-3">
                    {[
                        {id: 'url-test', icon: Zap, label: 'Auto Ping'},
                        {id: 'select', icon: Settings, label: 'Manual'},
                        {id: 'load-balance', icon: RefreshCw, label: 'Load Balance'},
                        {id: 'fallback', icon: CheckCircle, label: 'Fallback'}
                    ].map((m) => (
                        <button 
                            key={m.id}
                            onClick={() => setMode(m.id)}
                            className={`p-3 rounded-xl border flex flex-col items-center justify-center gap-2 transition-all ${mode === m.id ? 'bg-primary/20 border-primary text-white' : 'glass border-transparent text-zinc-400 hover:bg-zinc-800'}`}
                        >
                            <m.icon size={20} />
                            <span className="text-xs font-medium">{m.label}</span>
                        </button>
                    ))}
                </div>

                {/* Detailed Settings */}
                <div className="glass p-5 rounded-xl space-y-4">
                    <h3 className="text-sm font-semibold text-white flex items-center gap-2"><Settings size={16}/> Configuration</h3>
                    
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="text-xs text-zinc-500 mb-1 block">Interval (s)</label>
                            <input type="number" value={interval} onChange={(e) => setIntervalVal(e.target.value)} className="w-full input-dark rounded-md p-2 text-sm" />
                        </div>
                        <div>
                            <label className="text-xs text-zinc-500 mb-1 block">Group Name</label>
                            <input type="text" value={groupName} onChange={(e) => setGroupName(e.target.value)} className="w-full input-dark rounded-md p-2 text-sm" />
                        </div>
                    </div>

                    {/* DNS SETTINGS BARU */}
                    <div>
                        <label className="text-xs text-zinc-500 mb-1 flex items-center gap-2">
                            <Server size={12}/> DNS Strategy
                        </label>
                        <select 
                            value={dnsMode} 
                            onChange={(e) => setDnsMode(e.target.value)}
                            className="w-full input-dark rounded-md p-2 text-sm mb-2 cursor-pointer"
                        >
                            <option value="default">Default (Aman - No Override)</option>
                            <option value="fake-ip">⚡ Anti-Bengong (Fake-IP)</option>
                            <option value="custom">Custom IP Manual</option>
                        </select>
                        {dnsMode === 'custom' && (
                            <input 
                                type="text" 
                                value={customDnsIP} 
                                onChange={(e) => setCustomDnsIP(e.target.value)} 
                                placeholder="8.8.8.8, 1.1.1.1"
                                className="w-full input-dark rounded-md p-2 text-sm" 
                            />
                        )}
                    </div>

                    <div className="grid grid-cols-3 gap-2 pt-2">
                        <label className="flex items-center gap-2 p-2 rounded bg-zinc-800/50 cursor-pointer border border-zinc-700/50 hover:border-zinc-500">
                            <input type="checkbox" checked={skipCert} onChange={() => setSkipCert(!skipCert)} className="accent-primary" />
                            <span className="text-xs text-zinc-300">Skip Cert</span>
                        </label>
                        <label className="flex items-center gap-2 p-2 rounded bg-zinc-800/50 cursor-pointer border border-zinc-700/50 hover:border-zinc-500">
                            <input type="checkbox" checked={adblock} onChange={() => setAdblock(!adblock)} className="accent-primary" />
                            <span className="text-xs text-zinc-300">Adblock</span>
                        </label>
                        <label className="flex items-center gap-2 p-2 rounded bg-zinc-800/50 cursor-pointer border border-zinc-700/50 hover:border-zinc-500">
                            <input type="checkbox" checked={autoInsert} onChange={() => setAutoInsert(!autoInsert)} className="accent-primary" />
                            <span className="text-xs text-zinc-300">Top Insert</span>
                        </label>
                    </div>
                </div>
            </div>

            {/* RIGHT: OUTPUT */}
            <div className="lg:col-span-7 flex flex-col gap-6">
                
                {/* JS Output Card */}
                <div className="glass flex flex-col rounded-xl overflow-hidden h-[600px] border border-zinc-800">
                    <div className="bg-zinc-900/80 p-3 border-b border-zinc-800 flex justify-between items-center backdrop-blur-sm">
                        <span className="text-xs font-mono text-primary flex items-center gap-2"><Code size={14}/> Result - JS Override</span>
                        <div className="flex gap-2">
                            <button onClick={() => copyToClipboard(outputJS)} className="text-xs bg-zinc-800 hover:bg-zinc-700 text-white px-3 py-1 rounded flex items-center gap-1 transition"><Copy size={12}/> Copy</button>
                            <button onClick={() => downloadFile(outputJS, 'override.js')} className="text-xs bg-primary hover:bg-indigo-600 text-white px-3 py-1 rounded flex items-center gap-1 transition"><Download size={12}/> Save JS</button>
                        </div>
                    </div>
                    <div className="flex-1 bg-[#0d0d10] p-4 overflow-auto font-mono text-xs leading-relaxed">
                        <pre className="text-zinc-400 whitespace-pre-wrap">{outputJS || "// Hasil script akan muncul di sini..."}</pre>
                    </div>
                </div>

                {/* YAML Preview */}
                <div className="glass rounded-xl overflow-hidden border border-zinc-800">
                    <div className="bg-zinc-900/80 p-2 border-b border-zinc-800 flex justify-between items-center">
                            <span className="text-xs font-mono text-zinc-400 px-2">Structure Preview</span>
                    </div>
                    <div className="bg-[#0d0d10] p-3 overflow-auto max-h-32 font-mono text-[10px] text-zinc-500">
                        <pre>{outputYAML || "..."}</pre>
                    </div>
                </div>

            </div>
        </div>
    );
};

// --- INITIALIZE ---
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
lucide.createIcons();
