const express = require('express');
const path = require('path');
const os = require('os');
const child_process = require('child_process');
const util = require('util');
const exec = util.promisify(child_process.exec);
const si = require('systeminformation'); // For system info (npm install systeminformation)
const request = require('request'); // For web requests (npm install request)
const cheerio = require('cheerio'); // For scraping (npm install cheerio)
const Parser = require('rss-parser'); // For RSS feeds (npm install rss-parser)
const socket = require('socket.io'); // For real-time updates (npm install socket.io)
const re = require('re'); // Simple regex, but use built-in RegExp
const cache = require('memory-cache'); // Simple cache (npm install memory-cache)
const dotenv = require('dotenv'); // For .env (npm install dotenv)

dotenv.config();

const app = express();
const server = require('http').createServer(app);
const io = socket(server); // For real-time

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'templates'));
app.use(express.static(path.join(__dirname, 'public'))); // For static files like logo

// Cache for news
const newsCache = new cache.Cache();

// Validate inputs
function validateInput(text, maxLength = 100, allowedChars = /^[a-zA-Z0-9\.\-]+$/ ) {
    return allowedChars.test(text) && text.length <= maxLength;
}

// Helper functions
async function getSystemInfo() {
    try {
        const cpu = await si.cpu();
        const mem = await si.mem();
        const disk = await si.fsSize();
        const net = await si.networkStats();
        const processes = await si.processes();
        const uptime = os.uptime();
        return {
            cpuUsage: processes.load.cpu,
            cpuFreq: cpu.speed,
            memoryTotal: mem.total / (1024 ** 3),
            memoryUsed: mem.used / (1024 ** 3),
            diskTotal: disk[0].size / (1024 ** 3),
            diskUsed: disk[0].used / (1024 ** 3),
            netSent: net[0].tx_bytes / (1024 ** 2),
            netRecv: net[0].rx_bytes / (1024 ** 2),
            uptime: new Date(uptime * 1000).toISOString().substr(11, 8),
            processes: processes.list.slice(0, 10).map(p => ({ pid: p.pid, name: p.name, cpu: p.cpu, memory: p.mem }))
        };
    } catch (e) {
        console.error(`System info error: ${e}`);
        return {};
    }
}

async function getServiceStatus(serviceName) {
    if (!validateInput(serviceName)) return false;
    try {
        const { stdout } = await exec(`systemctl is-active ${serviceName}`);
        return stdout.trim() === 'active';
    } catch {
        return false;
    }
}

async function getUsers() {
    try {
        const { stdout } = await exec('getent passwd');
        return stdout.split('\n').map(line => {
            const [username, , uid, , , home] = line.split(':');
            return { username, uid: parseInt(uid), home };
        }).filter(u => u.username);
    } catch (e) {
        console.error(`Users error: ${e}`);
        return [];
    }
}

async function getGroups() {
    try {
        const { stdout } = await exec('getent group');
        return stdout.split('\n').map(line => {
            const [groupname, , gid] = line.split(':');
            return { groupname, gid: parseInt(gid) };
        }).filter(g => g.groupname);
    } catch (e) {
        console.error(`Groups error: ${e}`);
        return [];
    }
}

async function runNmap(target) {
    if (!validateInput(target, 100, /^[\w\.\-:]+$/)) return 'Invalid target';
    try {
        const { stdout } = await exec(`nmap -sS ${target}`, { timeout: 300000 });
        return stdout;
    } catch (e) {
        console.error(`Nmap error: ${e}`);
        return `Error: ${e.message}`;
    }
}

async function runNikto(target) {
    if (!validateInput(target, 100, /^[\w\.\-:]+$/)) return 'Invalid target';
    try {
        const { stdout } = await exec(`nikto -h ${target}`, { timeout: 300000 });
        return stdout;
    } catch (e) {
        console.error(`Nikto error: ${e}`);
        return `Error: ${e.message}`;
    }
}

function searchWeb(query, callback) {
    if (!validateInput(query, 200, /^[\w\s]+$/)) return callback([]);
    const url = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
    request({ url, headers: { 'User-Agent': 'Mozilla/5.0' } }, (err, res, body) => {
        if (err) return callback([]);
        const $ = cheerio.load(body);
        const results = [];
        $('.g').slice(0, 5).each((i, g) => {
            const title = $(g).find('h3').text();
            const link = $(g).find('a').attr('href');
            const snippet = $(g).find('.VwiC3b').text();
            if (title && link) results.push({ title, link, snippet });
        });
        callback(results);
    });
}

async function fetchGamingNews() {
    if (newsCache.get('gaming')) return newsCache.get('gaming');
    const parser = new Parser();
    const feeds = ['https://www.ign.com/rss/articles.xml', 'https://www.gamespot.com/feeds/news/'];
    let news = [];
    for (const feed of feeds) {
        try {
            const output = await parser.parseURL(feed);
            news = news.concat(output.items.slice(0, 5).map(item => ({ title: item.title, link: item.link, summary: item.contentSnippet })));
        } catch (e) {
            console.error(`Gaming news error: ${e}`);
        }
    }
    newsCache.put('gaming', news, 3600000);
    return news;
}

async function fetchCybersecurityNews() {
    if (newsCache.get('cybersecurity')) return newsCache.get('cybersecurity');
    const parser = new Parser();
    const feeds = ['https://thehackernews.com/feed', 'https://krebsonsecurity.com/feed/'];
    let news = [];
    for (const feed of feeds) {
        try {
            const output = await parser.parseURL(feed);
            news = news.concat(output.items.slice(0, 5).map(item => ({ title: item.title, link: item.link, summary: item.contentSnippet })));
        } catch (e) {
            console.error(`Cybersecurity news error: ${e}`);
        }
    }
    newsCache.put('cybersecurity', news, 3600000);
    return news;
}

async function getNetworkInfo() {
    try {
        const nets = await si.networkConnections();
        return nets.slice(0, 10).map(conn => ({
            local: `${conn.localAddress}:${conn.localPort}`,
            remote: `${conn.peerAddress}:${conn.peerPort}`,
            status: conn.state
        }));
    } catch (e) {
        console.error(`Network info error: ${e}`);
        return [];
    }
}

async function runDiagnostic() {
    try {
        const mem = await si.mem();
        const disk = await si.fsSize();
        const cpuLoad = await si.currentLoad();
        return {
            diskSpace: disk[0].use < 90,
            memoryUsage: (mem.used / mem.total) * 100 < 90,
            cpuUsage: cpuLoad.currentLoad < 90
        };
    } catch (e) {
        console.error(`Diagnostic error: ${e}`);
        return {};
    }
}

// New functions added
async function getFirewallStatus() {
    try {
        const { stdout } = await exec('sudo ufw status');
        return stdout;
    } catch (e) {
        return `Error: ${e.message}`;
    }
}

async function addUser(username, password) {
    if (!validateInput(username) || !validateInput(password)) return 'Invalid input';
    try {
        await exec(`sudo useradd -m ${username}`);
        await exec(`echo "${username}:${password}" | sudo chpasswd`);
        return 'User added';
    } catch (e) {
        return `Error: ${e.message}`;
    }
}

async function deleteUser(username) {
    if (!validateInput(username)) return 'Invalid input';
    try {
        await exec(`sudo userdel -r ${username}`);
        return 'User deleted';
    } catch (e) {
        return `Error: ${e.message}`;
    }
}

// Real-time monitoring with Socket.IO
io.on('connection', (socket) => {
    console.log('User connected');
    const interval = setInterval(async () => {
        const info = await getSystemInfo();
        socket.emit('systemUpdate', info);
    }, 5000);
    socket.on('disconnect', () => clearInterval(interval));
});

// Routes
app.get('/', async (req, res) => {
    const systemInfo = await getSystemInfo();
    res.render('index', { systemInfo });
});

app.route('/services')
    .get(async (req, res) => {
        const services = ['ssh', 'apache2', 'nginx', 'docker', 'mysql'];
        const serviceStatus = {};
        for (const service of services) {
            serviceStatus[service] = await getServiceStatus(service);
        }
        res.render('services', { services: serviceStatus });
    })
    .post(async (req, res) => {
        const { service_name, action } = req.body;
        if (!validateInput(service_name)) return res.json({ status: 'error', message: 'Invalid service name' });
        try {
            await exec(`sudo systemctl ${action} ${service_name}`);
            console.log(`${action.charAt(0).toUpperCase() + action.slice(1)}ed service: ${service_name}`);
            res.json({ status: 'success', message: `Service ${service_name} ${action}ed` });
        } catch (e) {
            console.error(`Failed to ${action} service ${service_name}: ${e}`);
            res.json({ status: 'error', message: `Failed to ${action} service` });
        }
    });

app.get('/logs', async (req, res) => {
    try {
        const { stdout } = await exec('tail -n 100 /var/log/syslog');
        const logs = stdout.split('\n');
        res.render('logs', { logs });
    } catch (e) {
        console.error(`Failed to read logs: ${e}`);
        res.render('logs', { logs: ['Error reading logs'] });
    }
});

app.get('/files', (req, res) => {
    let dirPath = req.query.path || '/';
    if (!path.isAbsolute(dirPath)) dirPath = '/';
    try {
        const files = fs.readdirSync(dirPath).map(f => ({
            name: f,
            isDir: fs.statSync(path.join(dirPath, f)).isDirectory()
        }));
        res.render('files', { path: dirPath, files });
    } catch (e) {
        console.error(`File explorer error: ${e}`);
        res.render('files', { path: dirPath, files: [] });
    }
});

app.route('/packages')
    .get(async (req, res) => {
        try {
            const { stdout } = await exec('dpkg -l');
            const packages = stdout.split('\n').filter(line => line.startsWith('ii')).map(line => line.split(/\s+/)[1]).slice(0, 50);
            res.render('packages', { packages });
        } catch (e) {
            console.error(`Package list error: ${e}`);
            res.render('packages', { packages: [] });
        }
    })
    .post(async (req, res) => {
        const { package_name, action } = req.body;
        if (!validateInput(package_name)) return res.json({ status: 'error', message: 'Invalid package name' });
        try {
            await exec(`sudo apt ${action} -y ${package_name}`);
            console.log(`${action.charAt(0).toUpperCase() + action.slice(1)}ed package: ${package_name}`);
            res.json({ status: 'success', message: `Package ${package_name} ${action}ed` });
        } catch (e) {
            console.error(`Failed to ${action} package ${package_name}: ${e}`);
            res.json({ status: 'error', message: `Failed to ${action} package` });
        }
    });

app.get('/users', async (req, res) => {
    const users = await getUsers();
    const groups = await getGroups();
    res.render('users', { users, groups });
});

app.route('/pentest')
    .get((req, res) => res.render('pentest'))
    .post(async (req, res) => {
        const { tool, target } = req.body;
        if (!['nmap', 'nikto'].includes(tool)) return res.json({ status: 'error', message: 'Invalid tool' });
        const result = tool === 'nmap' ? await runNmap(target) : await runNikto(target);
        res.json({ status: 'success', result });
    });

app.route('/search')
    .get((req, res) => res.render('search'))
    .post((req, res) => {
        const { query } = req.body;
        searchWeb(query, results => res.json({ status: 'success', results }));
    });

app.get('/gaming', async (req, res) => {
    const news = await fetchGamingNews();
    res.render('gaming', { news });
});

app.get('/cybersecurity', async (req, res) => {
    const news = await fetchCybersecurityNews();
    res.render('cybersecurity', { news });
});

app.get('/network', async (req, res) => {
    const netInfo = await getNetworkInfo();
    res.render('network', { netInfo });
});

app.get('/diagnostics', async (req, res) => {
    const checks = await runDiagnostic();
    res.render('diagnostics', { checks });
});

app.route('/terminal')
    .get((req, res) => res.render('terminal'))
    .post(async (req, res) => {
        const { command } = req.body;
        if (!validateInput(command, 200, /^[\w\s\-\.\/]+$/)) return res.json({ status: 'error', message: 'Invalid command' });
        try {
            const { stdout, stderr } = await exec(command, { timeout: 30000 });
            res.json({ status: 'success', output: stdout + stderr });
        } catch (e) {
            console.error(`Terminal error: ${e}`);
            res.json({ status: 'error', message: e.message });
        }
    });

app.get('/logo', (req, res) => {
    const logoPath = '/usr/share/HackerOS/ICONS/HackerOS.png';
    if (fs.existsSync(logoPath)) {
        res.sendFile(logoPath);
    } else {
        res.status(404).send('');
    }
});

// New routes
app.get('/firewall', async (req, res) => {
    const status = await getFirewallStatus();
    res.render('firewall', { status });
});

app.route('/manage-users')
    .post(async (req, res) => {
        const { action, username, password } = req.body;
        let result;
        if (action === 'add') {
            result = await addUser(username, password);
        } else if (action === 'delete') {
            result = await deleteUser(username);
        }
        res.json({ status: result.includes('Error') ? 'error' : 'success', message: result });
    });

server.listen(4545, '0.0.0.0', () => console.log('Server running on port 4545'));
