const fs = require('fs');
const path = require('path');
const https = require('https');

// Get file paths
const inputArg = process.argv[2];
let lockFilePath, packageJsonPath;

if (inputArg) {
    const resolved = path.resolve(inputArg);
    // Check if it's a directory or file (simple check, assuming file if ends in .json)
    if (resolved.endsWith('.json')) {
        lockFilePath = resolved;
        packageJsonPath = path.join(path.dirname(resolved), 'package.json');
    } else {
        // Assume directory
        lockFilePath = path.join(resolved, 'package-lock.json');
        packageJsonPath = path.join(resolved, 'package.json');
    }
} else {
    lockFilePath = path.join(__dirname, 'package-lock.json');
    packageJsonPath = path.join(__dirname, 'package.json');
}

const COMPROMISED_LIST_URL = 'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv';
const OUTPUT_FILE = path.join(__dirname, 'compromised_libraries_report.csv');

/**
 * Parses package-lock.json to extract installed dependencies.
 */
function getLockfileDependencies(filePath) {
    try {
        if (!fs.existsSync(filePath)) return [];
        const data = fs.readFileSync(filePath, 'utf8');
        const json = JSON.parse(data);
        const dependencies = [];
        const seen = new Set();

        // Handle package-lock.json v2/v3 'packages' structure
        if (json.packages) {
            for (const [pkgPath, info] of Object.entries(json.packages)) {
                if (pkgPath === "") continue;
                const name = pkgPath.split('node_modules/').pop();
                const version = info.version;
                if (name && version) {
                    const identifier = `${name}@${version}`;
                    if (!seen.has(identifier)) {
                        seen.add(identifier);
                        dependencies.push({ name, version, source: 'package-lock.json' });
                    }
                }
            }
        }
        // Handle package-lock.json v1
        else if (json.dependencies) {
            function traverse(deps) {
                if (!deps) return;
                for (const [name, info] of Object.entries(deps)) {
                    const version = info.version;
                    const identifier = `${name}@${version}`;
                    if (!seen.has(identifier)) {
                        seen.add(identifier);
                        dependencies.push({ name, version, source: 'package-lock.json' });
                    }
                    if (info.dependencies) traverse(info.dependencies);
                }
            }
            traverse(json.dependencies);
        }
        return dependencies;
    } catch (err) {
        console.warn(`Warning: Failed to parse ${filePath}: ${err.message}`);
        return [];
    }
}

/**
 * Parses package.json to extract direct dependencies.
 */
function getPackageJsonDependencies(filePath) {
    try {
        if (!fs.existsSync(filePath)) return [];
        const data = fs.readFileSync(filePath, 'utf8');
        const json = JSON.parse(data);
        const dependencies = [];

        const allDeps = { ...json.dependencies, ...json.devDependencies };

        for (const [name, version] of Object.entries(allDeps)) {
            // Clean version string (remove ^, ~, etc for basic reporting, 
            // though strict audit might need the raw string. Keeping raw for now.)
            dependencies.push({ name, version, source: 'package.json' });
        }
        return dependencies;
    } catch (err) {
        console.warn(`Warning: Failed to parse ${filePath}: ${err.message}`);
        return [];
    }
}

/**
 * Fetches the compromised package list from the remote URL.
 */
function fetchCompromisedList(url) {
    return new Promise((resolve, reject) => {
        const agent = new https.Agent({
            rejectUnauthorized: false
        });

        https.get(url, { agent }, (res) => {
            if (res.statusCode !== 200) {
                reject(new Error(`Failed to fetch CSV. Status Code: ${res.statusCode}`));
                return;
            }

            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => resolve(data));
        }).on('error', (err) => reject(err));
    });
}

/**
 * Parses the compromised CSV content into a Map.
 */
function parseCompromisedCSV(csvContent) {
    const lines = csvContent.split('\n').filter(l => l.trim() !== '');
    const compromisedMap = new Map(); // name -> Set of versions (or 'ALL')

    // Skip header (start from index 1)
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        const firstCommaIndex = line.indexOf(',');
        if (firstCommaIndex === -1) continue;

        const name = line.substring(0, firstCommaIndex).trim();
        let versionRaw = line.substring(firstCommaIndex + 1).trim();

        // Handle quotes if present
        if (versionRaw.startsWith('"') && versionRaw.endsWith('"')) {
            versionRaw = versionRaw.slice(1, -1);
        }

        let versions;
        if (!versionRaw) {
            versions = 'ALL';
        } else {
            versions = new Set();
            // Split by '||' and clean up
            const parts = versionRaw.split('||');
            for (const p of parts) {
                const v = p.replace(/=/g, '').trim();
                if (v) versions.add(v);
            }
        }
        compromisedMap.set(name, versions);
    }
    return compromisedMap;
}

/**
 * Main execution function.
 */
async function runAudit() {
    console.log('Starting dependency audit...');

    try {
        // 1. Get Local Dependencies
        console.log(`Reading dependencies from:`);
        console.log(` - Lockfile: ${lockFilePath}`);
        console.log(` - Manifest: ${packageJsonPath}`);

        const lockDeps = getLockfileDependencies(lockFilePath);
        const pkgDeps = getPackageJsonDependencies(packageJsonPath);

        // Merge dependencies
        const allDeps = [...lockDeps, ...pkgDeps];
        console.log(`Found ${allDeps.length} total dependencies (${lockDeps.length} from lockfile, ${pkgDeps.length} from package.json).`);

        // 2. Fetch Compromised List
        console.log(`Fetching compromised list from ${COMPROMISED_LIST_URL}...`);
        const csvContent = await fetchCompromisedList(COMPROMISED_LIST_URL);
        const compromisedMap = parseCompromisedCSV(csvContent);
        console.log(`Loaded ${compromisedMap.size} compromised package definitions.`);

        // 3. Cross-check
        console.log('Cross-checking dependencies...');
        const results = [];
        let compromisedCount = 0;

        for (const dep of allDeps) {
            let isCompromised = false;
            let matchedRule = '';

            if (compromisedMap.has(dep.name)) {
                const compromisedVersions = compromisedMap.get(dep.name);
                if (compromisedVersions === 'ALL') {
                    isCompromised = true;
                    matchedRule = 'ALL';
                } else {
                    // Simple check: if version string matches exactly or is contained
                    // Note: This is a basic check. Semver matching would be more robust for ranges.
                    // For package.json ranges (e.g. ^1.0.0), this might not match specific compromised versions unless exact.
                    if (compromisedVersions.has(dep.version)) {
                        isCompromised = true;
                        matchedRule = dep.version;
                    }
                }
            }

            if (isCompromised) compromisedCount++;

            results.push({
                name: dep.name,
                version: dep.version,
                source: dep.source,
                isCompromised: isCompromised,
                matchedRule: matchedRule
            });
        }

        // 4. Generate Report
        const header = 'Library Name,Version,Source,Is Compromised,Matched Rule';
        const rows = results.map(r => `${r.name},${r.version},${r.source},${r.isCompromised ? 'YES' : 'NO'},${r.matchedRule}`).join('\n');

        fs.writeFileSync(OUTPUT_FILE, header + '\n' + rows);

        console.log('--------------------------------------------------');
        console.log(`Audit Complete!`);
        console.log(`Compromised Libraries Found: ${compromisedCount}`);
        console.log(`Report generated at: ${OUTPUT_FILE}`);
        console.log('--------------------------------------------------');

    } catch (error) {
        console.error('An error occurred during the audit:', error);
    }
}

runAudit();
