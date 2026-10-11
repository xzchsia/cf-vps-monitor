import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const severities = ['info', 'low', 'moderate', 'high', 'critical'];

function requireSuccessfulScan(name, result) {
  if (result.error || result.status !== 0 || typeof result.stdout !== 'string') {
    const detail = result.error?.message || result.stderr || result.stdout || 'scanner did not complete';
    throw new Error(`${name} failed (exit ${result.status ?? 'unavailable'}):\n${String(detail).trim().slice(0, 12000)}`);
  }
}

// The runner is the subprocess boundary; the same validation runs locally and in
// CI. A registry outage or truncated result must never be treated as a clean scan.
export function runSecurityChecks({ run = spawnSync, log = console.log } = {}) {
  const npmCli = process.env.npm_execpath;
  const auditArgs = ['audit', '--audit-level=low', '--include=dev', '--json'];
  const npm = run(npmCli ? process.execPath : process.platform === 'win32' ? 'npm.cmd' : 'npm', npmCli ? [npmCli, ...auditArgs] : auditArgs, {
    cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    shell: !npmCli && process.platform === 'win32', timeout: 120000, maxBuffer: 16 * 1024 * 1024,
  });
  // npm audit 自身在发现漏洞时以退出码 1 结束，这是预期行为；不能据此判失败。
  // 仅在子进程无法启动、输出缺失或非 JSON 时报错，交由后续结构校验兜底。
  if (npm.error || typeof npm.stdout !== 'string') {
    const detail = npm.error?.message || npm.stderr || npm.stdout || 'scanner did not complete';
    throw new Error(`npm audit failed (exit ${npm.status ?? 'unavailable'}):\n${String(detail).trim().slice(0, 12000)}`);
  }
  let report;
  try { report = JSON.parse(npm.stdout); }
  catch { throw new Error('npm audit returned malformed JSON.'); }
  const counts = report?.metadata?.vulnerabilities;
  if (report?.auditReportVersion !== 2 || report.error || !report.vulnerabilities
    || typeof report.vulnerabilities !== 'object' || Array.isArray(report.vulnerabilities)
    || !counts || ![...severities, 'total'].every(key => Number.isSafeInteger(counts[key]) && counts[key] >= 0)
    || severities.reduce((sum, key) => sum + counts[key], 0) !== counts.total) {
    throw new Error('npm audit returned an incomplete or inconsistent report.');
  }
  // 注册表异常等场景可能退出非零却给出空报告；干净扫描必然退出 0，
  // 非零退出且零漏洞视为失败关闭，避免把中断误当成通过。
  if (npm.status !== 0 && counts.total === 0) {
    throw new Error(`npm audit exited ${npm.status} with an empty report:\n${String(npm.stderr || npm.stdout).trim().slice(0, 12000)}`);
  }

  // 显式白名单：仅接受按 GHSA ID 精确匹配的 advisory，并放行因其被连带标记的
  // 传递依赖包。以下两条都来自 tailwindcss v3 的构建期依赖链（前端构建工具，
  // worker 打包产物与 Go agent 均不携带），上游无补丁版本，彻底清除需破坏性
  // 升级到 tailwind v4，故暂予豁免。新增其他 advisory 一律照常失败。
  const ALLOWED_ADVISORY_GHSAS = new Set([
    'GHSA-vfj7-8cjw-p6xm', // braces: stack-exhaustion DoS，无补丁版本
    'GHSA-rj75-hqrm-r3gf', // postcss-selector-parser: 选择器解析 CPU 耗尽，补丁仅在 7.x
  ]);
  const vulnerabilities = report.vulnerabilities;
  const ghsaOf = (url) => {
    // GHSA 标识形如 GHSA-vfj7-8cjw-p6xm（前缀大写、后缀小写十六进制），精确匹配。
    const match = /\/(GHSA-[0-9A-Za-z-]+)$/.exec(url || '');
    return match ? match[1] : null;
  };
  // 传递闭包：某包被放行当且仅当其 via 中每个元素要么是白名单 advisory，
  // 要么是引用另一个已放行包的字符串。
  const allowed = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const [name, vuln] of Object.entries(vulnerabilities)) {
      if (allowed.has(name) || !Array.isArray(vuln?.via)) continue;
      const ok = vuln.via.every((item) => {
        if (typeof item === 'string') return allowed.has(item);
        return item && ALLOWED_ADVISORY_GHSAS.has(ghsaOf(item.url));
      });
      if (ok) { allowed.add(name); changed = true; }
    }
  }
  const remaining = Object.keys(vulnerabilities).filter((name) => !allowed.has(name));
  if (remaining.length !== 0) {
    throw new Error(`npm audit found vulnerable dependencies: ${remaining.join(', ')}`);
  }
  if (allowed.size > 0) {
    log(`npm audit: no unlisted vulnerabilities found. (allow-listed: ${[...allowed].join(', ')})`);
  } else {
    log('npm audit: no vulnerabilities found.');
  }

  // Keep the pinned scanner in default text mode. Its JSON mode can exit zero
  // with findings, so JSON/progress/partial output is not accepted as success.
  const go = run('go', ['run', 'golang.org/x/vuln/cmd/govulncheck@v1.7.0', './...'], {
    cwd: join(root, 'agent'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 300000, maxBuffer: 16 * 1024 * 1024,
  });
  requireSuccessfulScan('govulncheck', go);
  if (go.stdout.trim() !== 'No vulnerabilities found.') {
    throw new Error(`govulncheck did not return a complete clean text scan:\n${go.stdout.trim().slice(0, 12000)}`);
  }
  log('govulncheck: no vulnerabilities found.');
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { runSecurityChecks(); }
  catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
