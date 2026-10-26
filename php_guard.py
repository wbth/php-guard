#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""php_guard - audit kerentanan PHP per server (lokal). Lihat README.md."""
import argparse, datetime, glob, gzip, hashlib, json, os, platform, pwd, re
import shutil, socket, subprocess, sys, time
from collections import Counter

VERSION = '1.0'
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
EOL = {
    (7, 0): '2019-01-10', (7, 1): '2019-12-01', (7, 2): '2020-11-30', (7, 3): '2021-12-06',
    (7, 4): '2022-11-28', (8, 0): '2023-11-26', (8, 1): '2025-12-31',
}
UPGRADE_TARGET = '8.3+'
CVES = ('CVE-2026-109618', 'CVE-2026-109619')
CVE_NOPATCH = 'CVE-2026-115560'
DEFAULT_SINCE = '2026-10-20'
DROPIN = 'zz-php-guard-cve2026.ini'
NAME_RE = re.compile(r'^(php(\d[\d.]*)?|php-cgi[\d.]*|php-fpm[\d.]*|lsphp[\d.]*|frankenphp)$')

BIN_GLOBS = [
    '/usr/bin/php', '/usr/bin/php[0-9]*', '/usr/bin/php-cgi*', '/usr/sbin/php-fpm*',
    '/usr/local/bin/php*', '/usr/local/sbin/php-fpm*', '/usr/bin/frankenphp', '/usr/local/bin/frankenphp',
    '/usr/local/php*/bin/php', '/usr/local/php*/sbin/php-fpm',
    '/opt/cpanel/ea-php*/root/usr/bin/php', '/opt/cpanel/ea-php*/root/usr/sbin/php-fpm',
    '/usr/local/cpanel/3rdparty/bin/php',
    '/opt/plesk/php/*/bin/php', '/opt/plesk/php/*/sbin/php-fpm',
    '/opt/remi/php*/root/usr/bin/php', '/opt/remi/php*/root/usr/sbin/php-fpm',
    '/opt/alt/php*/usr/bin/php', '/opt/alt/php*/usr/sbin/php-fpm',
    '/usr/local/lsws/lsphp*/bin/php', '/usr/local/lsws/lsphp*/bin/lsphp', '/usr/local/lsws/fcgi-bin/lsphp*',
    '/www/server/php/*/bin/php', '/www/server/php/*/sbin/php-fpm',
]
MODPHP_GLOBS = [
    '/usr/lib/apache2/modules/libphp*.so', '/usr/lib64/httpd/modules/libphp*.so', '/usr/lib/httpd/modules/libphp*.so',
    '/etc/httpd/modules/libphp*.so', '/etc/apache2/modules/libphp*.so', '/usr/local/apache/modules/libphp*.so',
]
POOL_GLOBS = [
    '/etc/php/*/fpm/pool.d/*.conf', '/etc/php-fpm.d/*.conf', '/etc/php-fpm.conf',
    '/etc/opt/remi/php*/php-fpm.d/*.conf', '/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf',
    '/opt/plesk/php/*/etc/php-fpm.d/*.conf', '/opt/alt/php*/etc/php-fpm.d/*.conf',
    '/www/server/php/*/etc/php-fpm.conf', '/usr/local/php*/etc/php-fpm.d/*.conf', '/usr/local/php*/etc/php-fpm.conf',
]
WEB_ROOTS = ['/var/www', '/srv', '/usr/share/nginx/html', '/home', '/www/wwwroot']
WEB_USERS = ('www-data', 'apache', 'nginx', 'nobody', 'http', 'lsadm', 'www')
WEB_PARENTS = re.compile(r'^(php-fpm|php-cgi|lsphp|httpd|apache2|litespeed|lshttpd|frankenphp|php\d|php$)')
CHILD_TOOLS = re.compile(r'^(sh|bash|dash|zsh|ash|nc|ncat|netcat|socat|curl|wget|python\d*(\.\d+)?|perl|ruby|telnet|base64|xmrig.*)$')
DPKG_RE = re.compile(r'^(php[\d.]*(-[\w.+-]+)?|libapache2-mod-php[\d.]*|lsphp\d+(-[\w.+-]+)?)(:\w+)?$')
RPM_RE = re.compile(r'^(php[\d.]*(-[\w.+-]+)?|lsphp\d+(-[\w.+-]+)?)$')
RPM_PANEL_RE = re.compile(r'^(ea-php\d+(-[\w.+-]+)?|alt-php\d+(-[\w.+-]+)?)$')
APK_RE = re.compile(r'^php\d*(-[\w.+-]+)?$')

PANEL_HINT = {
    'cpanel': "cPanel EA4: `yum/dnf update 'ea-php*'` (atau `fix --include-panels`), lalu restart ea-phpXX-php-fpm/httpd",
    'cpanel-internal': "PHP internal cPanel: perbarui lewat `/scripts/upcp`",
    'plesk': 'Plesk: Tools & Settings > Updates (atau `plesk installer`) untuk komponen PHP',
    'cloudlinux-alt': "CloudLinux alt-php: `yum update 'alt-php*'` (atau `fix --include-panels`), lalu restart web server",
    'aapanel': 'aaPanel: App Store > PHP > update/compile ulang ke rilis perbaikan',
    'directadmin/custom': 'DirectAdmin: `cd /usr/local/directadmin/custombuild && ./build update && ./build php`; build manual: compile ulang dari rilis perbaikan',
    'litespeed': 'LiteSpeed lsphp: update paket lsphpXX dari repo LiteSpeed lalu restart lsws',
    'remi-scl': "Remi SCL: `dnf upgrade 'phpXX-php*'` (tercakup `fix`) lalu restart phpXX-php-fpm",
    'manual': 'PHP tak terkelola paket: compile ulang dari rilis perbaikan atau pindah ke paket distro/vendor',
}
VERDICT_RANK = {'VULNERABLE': 6, 'EOL_UNSUPPORTED': 5, 'UNVERIFIED': 4, 'RESTART_REQUIRED': 3,
                'PATCHED_BACKPORT': 1, 'PATCHED': 0, 'NO_PHP_FOUND': 0}


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def run(args, timeout=20, env=None):
    e = dict(os.environ)
    e['LC_ALL'] = 'C'
    if env:
        e.update(env)
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           stdin=subprocess.DEVNULL, timeout=timeout, env=e)
        return p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')
    except (OSError, subprocess.TimeoutExpired) as ex:
        return -1, '', str(ex)


def is_elf(path):
    try:
        with open(path, 'rb') as f:
            return f.read(4) == b'\x7fELF'
    except OSError:
        return False


def sha256_file(path, limit=50 * 1024 * 1024):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            h.update(f.read(limit))
        return h.hexdigest()
    except OSError:
        return ''


def vtuple(text):
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', text or '')
    return tuple(int(x) for x in m.groups()) if m else None


def vstr(v):
    return '.'.join(str(x) for x in v) if v else ''


def eol_date(v):
    """Tanggal EOL branch (akhir dukungan keamanan); '' bila masih didukung/tak dikenal."""
    return EOL.get(v[:2], '') if v else ''


def upstream_status(v):
    """Status versi vs pengetahuan bawaan (cakupan PHP 7.0 s/d terbaru):
      'fixed'/'below_fixed' -> branch masih didukung (8.2-8.5), dibanding patch aman;
      'eol'                 -> branch habis dukungan (7.0-8.1), tak ada patch resmi;
      'unknown_branch'      -> branch di atas yang dikenal (mis. 8.6+)."""
    t = FIXED.get(v[:2])
    if t:
        return ('fixed' if v >= t else 'below_fixed'), vstr(t)
    if v[:2] in EOL or v[:2] < (8, 2):
        return 'eol', None
    return 'unknown_branch', None


def osinfo():
    d = {}
    try:
        with open('/etc/os-release') as f:
            for line in f:
                if '=' in line:
                    k, v = line.rstrip('\n').split('=', 1)
                    d[k] = v.strip().strip('"')
    except OSError:
        pass
    return {'id': d.get('ID', 'unknown'), 'version': d.get('VERSION_ID', ''), 'like': d.get('ID_LIKE', ''),
            'pretty': d.get('PRETTY_NAME', platform.platform())}


def panel_of(path):
    for pre, name in (('/opt/cpanel/', 'cpanel'), ('/usr/local/cpanel/', 'cpanel-internal'), ('/opt/plesk/', 'plesk'),
                      ('/opt/alt/', 'cloudlinux-alt'), ('/www/server/', 'aapanel'), ('/usr/local/lsws/', 'litespeed'),
                      ('/usr/local/php', 'directadmin/custom'), ('/opt/remi/', 'remi-scl')):
        if path.startswith(pre):
            return name
    return ''


def kind_of(path):
    b = os.path.basename(path)
    if b.startswith('libphp'):
        return 'apache'
    for k in ('fpm', 'cgi', 'lsphp', 'frankenphp'):
        if k in b:
            return k
    return 'cli'


def pkg_owner(path):
    cands = [path, os.path.realpath(path)]
    if shutil.which('dpkg-query'):
        for p in cands:
            rc, out, _ = run(['dpkg-query', '-S', p])
            if rc == 0 and out.strip():
                name = out.strip().splitlines()[0].split(': ')[0].split(',')[0].split(':')[0].strip()
                rc2, ver, _ = run(['dpkg-query', '-W', '-f=${Version}', name])
                return {'manager': 'dpkg', 'name': name, 'version': ver.strip() if rc2 == 0 else ''}
    if shutil.which('rpm'):
        for p in cands:
            rc, out, _ = run(['rpm', '-qf', '--qf', '%{NAME}|%{VERSION}-%{RELEASE}\n', p])
            line = out.strip().splitlines()[0] if out.strip() else ''
            if rc == 0 and '|' in line:
                n, v = line.split('|', 1)
                return {'manager': 'rpm', 'name': n, 'version': v}
    if shutil.which('apk'):
        rc, out, _ = run(['apk', 'info', '--who-owns', path])
        m = re.search(r'is owned by (\S+)', out)
        if m:
            mm = re.match(r'^(.*)-(\d[^-]*-r\d+)$', m.group(1))
            return {'manager': 'apk', 'name': mm.group(1) if mm else m.group(1), 'version': mm.group(2) if mm else ''}
    return {}


def vendor_backport(owner):
    """Cari ID CVE di changelog paket distro (bukti backport)."""
    if not owner:
        return 'no_package'
    texts = []
    if owner['manager'] == 'dpkg':
        names = [owner['name']]
        m = re.match(r'^(php\d+\.\d+|php)-', owner['name']) or re.match(r'^libapache2-mod-(php\d+\.\d+)$', owner['name'])
        if m:
            names.append(m.group(1) + '-common')
        for n in names:
            for fn in ('changelog.Debian.gz', 'changelog.gz'):
                try:
                    with gzip.open('/usr/share/doc/%s/%s' % (n, fn), 'rt', errors='replace') as f:
                        texts.append(f.read(4000000))
                    break
                except Exception:
                    pass
    elif owner['manager'] == 'rpm':
        rc, out, _ = run(['rpm', '-q', '--changelog', owner['name']], timeout=25)
        if rc == 0:
            texts.append(out)
    if not texts:
        return 'changelog_unavailable'
    blob = '\n'.join(texts)
    hits = [c for c in CVES if c in blob]
    return 'confirmed' if len(hits) == 2 else ('partial' if hits else 'not_in_changelog')


def installed_php_pkgs(include_panels=False):
    if shutil.which('dpkg-query') and shutil.which('apt-get'):
        rc, out, _ = run(['dpkg-query', '-W', '-f=${db:Status-Abbrev}|${binary:Package}\n'], timeout=30)
        pk = [l.split('|', 1)[1] for l in out.splitlines() if l.startswith('ii') and '|' in l]
        return 'apt', sorted(p for p in pk if DPKG_RE.match(p))
    if shutil.which('rpm') and (shutil.which('dnf') or shutil.which('yum') or shutil.which('zypper')):
        rc, out, _ = run(['rpm', '-qa', '--qf', '%{NAME}\n'], timeout=60)
        pk = set(p for p in out.split() if RPM_RE.match(p) or (include_panels and RPM_PANEL_RE.match(p)))
        mgr = 'dnf' if shutil.which('dnf') else ('yum' if shutil.which('yum') else 'zypper')
        return mgr, sorted(pk)
    if shutil.which('apk'):
        rc, out, _ = run(['apk', 'info'], timeout=30)
        return 'apk', sorted(p for p in out.split() if APK_RE.match(p))
    if shutil.which('pacman'):
        return 'pacman', []
    return None, []


def php_info(path, kind):
    if kind == 'frankenphp':
        return {}
    rc, out, _ = run([path, '-i'], timeout=15)
    if '=>' not in out:
        return {}

    def g(k):
        m = re.search(r'^' + re.escape(k) + r' => (.*?)(?: => (.*))?$', out, re.M)
        if not m:
            return None
        return (m.group(2) if m.group(2) is not None else m.group(1)).strip()
    rc2, mo, _ = run([path, '-m'], timeout=10)
    mods = [l.strip() for l in mo.splitlines() if l.strip() and not l.startswith('[') and ' ' not in l.strip()]
    return {'sapi': g('Server API'), 'ini': g('Loaded Configuration File'),
            'scan_dir': g('Scan this dir for additional .ini files'),
            'upload_progress': g('session.upload_progress.enabled'),
            'fatal_error_backtraces': g('fatal_error_backtraces'),
            'memory_limit': g('memory_limit'), 'post_max_size': g('post_max_size'),
            'modules': mods, 'module_count': len(mods)}


def ini_from_files(files, key):
    val = None
    rx = re.compile(r'^\s*' + re.escape(key) + r'\s*=\s*"?([^";\s]+)', re.I)
    for fpath in files:
        try:
            with open(fpath, errors='replace') as f:
                for line in f:
                    m = rx.match(line)
                    if m:
                        val = m.group(1)
        except OSError:
            pass
    return val


def is_off(v):
    return v is not None and str(v).strip().lower() in ('0', 'off', 'false', 'no', '')


def pool_overrides():
    rx = re.compile(r'^\s*php(_admin)?_(value|flag)\[session\.upload_progress\.enabled\]\s*=\s*(\S+)', re.I)
    res = []
    for g in POOL_GLOBS:
        for p in glob.glob(g):
            try:
                with open(p, errors='replace') as f:
                    for n, line in enumerate(f, 1):
                        m = rx.match(line)
                        if m and not is_off(m.group(3)):
                            res.append({'file': p, 'line': n, 'value': m.group(3)})
            except OSError:
                pass
    return res


def scan_procs():
    exes, groups = set(), {}
    try:
        with open('/proc/stat') as f:
            btime = int([l for l in f if l.startswith('btime')][0].split()[1])
        hz = os.sysconf('SC_CLK_TCK')
    except Exception:
        return exes, []
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            exe = os.readlink('/proc/%s/exe' % pid)
        except OSError:
            continue
        deleted = exe.endswith(' (deleted)')
        path = exe[:-10] if deleted else exe
        base = os.path.basename(path)
        if NAME_RE.match(base):
            key = path
            if not deleted:
                exes.add(path)
        elif base in ('httpd', 'apache2', 'lshttpd', 'litespeed'):
            try:
                with open('/proc/%s/maps' % pid) as f:
                    lib = [ln.split(None, 5)[-1] for ln in f if 'libphp' in ln]
            except OSError:
                continue
            if not lib:
                continue
            deleted = lib[0].endswith(' (deleted)')
            key = path = lib[0][:-10] if deleted else lib[0]
        else:
            continue
        try:
            with open('/proc/%s/stat' % pid) as f:
                start = btime + int(f.read().rsplit(')', 1)[1].split()[19]) / float(hz)
        except Exception:
            start = None
        stale = deleted
        if not stale and start and os.path.exists(path):
            try:
                stale = os.stat(path).st_ctime > start + 2
            except OSError:
                pass
        g = groups.setdefault(key, {'path': key, 'processes': 0, 'stale': 0, 'binary_deleted': False, 'oldest_start': None})
        g['processes'] += 1
        if start and (g['oldest_start'] is None or start < g['oldest_start']):
            g['oldest_start'] = start
        g['stale'] += 1 if stale else 0
        g['binary_deleted'] = g['binary_deleted'] or deleted
    return exes, list(groups.values())


def discover(proc_exes):
    cands = set(proc_exes)
    for g in BIN_GLOBS:
        cands.update(glob.glob(g))
    out, seen = [], set()
    for p in sorted(cands):
        if not NAME_RE.match(os.path.basename(p)):
            continue
        real = os.path.realpath(p)
        if real in seen or not os.path.isfile(real) or not os.access(real, os.X_OK) or not is_elf(real):
            continue
        seen.add(real)
        kind = kind_of(real)
        rc, o, e = run([real, 'version' if kind == 'frankenphp' else '-v'], timeout=10)
        m = re.search(r'PHP\s+(\d+\.\d+\.\d+\S*)', o + ' ' + e)
        if not m:
            continue
        out.append(make_install(p, real, kind, vtuple(m.group(1)), m.group(1), 'binary -v'))
    for g in MODPHP_GLOBS:
        for so in glob.glob(g):
            real = os.path.realpath(so)
            if real in seen or not os.path.isfile(real):
                continue
            seen.add(real)
            owner = pkg_owner(real)
            v, src, raw = vtuple(owner.get('version')), 'package', owner.get('version', '')
            if not v:
                try:
                    with open(real, 'rb') as f:
                        c = Counter(re.findall(rb'(?<![\d.])([78]\.\d\.\d{1,2})(?![\d.])', f.read(80 * 1024 * 1024)))
                    if c:
                        raw = c.most_common(1)[0][0].decode()
                        v, src = vtuple(raw), 'binary_strings(heuristik)'
                except OSError:
                    pass
            if v:
                out.append(make_install(so, real, 'apache', v, raw, src, owner))
    return out


def make_install(path, real, kind, v, raw, source, owner=None):
    owner = owner if owner is not None else pkg_owner(real)
    st, target = upstream_status(v)
    inst = {'binary': path, 'realpath': real, 'kind': kind, 'version': vstr(v), 'version_raw': raw,
            'version_source': source, 'branch': '%d.%d' % v[:2], 'upstream_status': st, 'fixed_in': target,
            'eol_date': eol_date(v), 'package': owner, 'panel': panel_of(real), 'sha256': sha256_file(real)}
    inst['vendor_backport'] = vendor_backport(owner) if st != 'fixed' else 'not_needed'
    if kind not in ('apache', 'frankenphp'):
        inst['info'] = php_info(real, kind)
    else:
        inst['info'] = {}
        m = re.match(r'^libapache2-mod-(php)(\d+\.\d+)$', owner.get('name', ''))
        if kind == 'apache' and m:
            d = '/etc/php/%s/apache2' % m.group(2)
            files = [d + '/php.ini'] + sorted(glob.glob(d + '/conf.d/*.ini'))
            inst['info'] = {'sapi': 'apache2handler', 'ini': d + '/php.ini', 'scan_dir': d + '/conf.d',
                            'upload_progress': ini_from_files(files, 'session.upload_progress.enabled') or 'On(default)'}
    return inst


def assess(inst, proc_groups, strict_backport=False):
    st, vb = inst['upstream_status'], inst['vendor_backport']
    if st == 'fixed':
        v = 'PATCHED'
    elif vb == 'confirmed':
        v = 'UNVERIFIED' if strict_backport else 'PATCHED_BACKPORT'
    elif st == 'eol':
        v = 'EOL_UNSUPPORTED'
    elif st == 'unknown_branch' or vb in ('changelog_unavailable', 'partial'):
        v = 'UNVERIFIED'
    else:
        v = 'VULNERABLE'
    run_ = [g for g in proc_groups if g['path'] in (inst['realpath'], inst['binary'])]
    starts = [g['oldest_start'] for g in run_ if g.get('oldest_start')]
    inst['running'] = {'processes': sum(g['processes'] for g in run_), 'stale': sum(g['stale'] for g in run_),
                       'oldest_start': min(starts) if starts else None}
    if v.startswith('PATCHED') and inst['running']['stale']:
        v = 'RESTART_REQUIRED'
    inst['verdict'] = v
    inst['active_risk'] = bool(v in ('VULNERABLE', 'EOL_UNSUPPORTED') and inst['running']['processes'] > 0)
    return inst


def scan_containers():
    res = []
    probe = ('for b in php php-fpm; do command -v "$b" >/dev/null 2>&1 && "$b" -v 2>/dev/null | head -n1; done; '
             'command -v frankenphp >/dev/null 2>&1 && frankenphp version 2>/dev/null | head -n1; true')
    for rt in ('docker', 'podman'):
        if not shutil.which(rt):
            continue
        rc, out, _ = run([rt, 'ps', '--format', '{{.ID}}|{{.Image}}|{{.Names}}'], timeout=20)
        for line in out.splitlines()[:100]:
            cid, img, name = (line.split('|') + ['', ''])[:3]
            rc2, o2, e2 = run([rt, 'exec', cid, 'sh', '-c', probe], timeout=20)
            vers = re.findall(r'PHP\s+(\d+\.\d+\.\d+\S*)', o2)
            if not vers:
                continue
            items = []
            for raw in sorted(set(vers)):
                v = vtuple(raw)
                st, target = upstream_status(v)
                distro = bool(re.search(r'(ubuntu|deb|el\d)', raw))
                verdict = ('PATCHED' if st == 'fixed'
                           else 'EOL_UNSUPPORTED' if st == 'eol'
                           else 'UNVERIFIED' if distro or st == 'unknown_branch'
                           else 'VULNERABLE')
                items.append({'version_raw': raw, 'upstream_status': st, 'fixed_in': target, 'verdict': verdict})
            res.append({'runtime': rt, 'id': cid, 'image': img, 'name': name, 'php': items,
                        'verdict': max((i['verdict'] for i in items), key=lambda x: VERDICT_RANK[x])})
    return res


SUSP_HIGH = re.compile(rb'(?:assert|eval|system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*'
                       rb'(?:(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|urldecode|hex2bin|stripslashes)\s*\(\s*){0,4}'
                       rb'\$_(?:POST|GET|REQUEST|COOKIE|SERVER)'
                       rb'|\$_(?:POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(', re.I)
SUSP_MED = re.compile(rb'eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(|preg_replace\s*\(\s*[\'"][^\'"]{0,80}/e[\'"]', re.I)
PHP_EXT = ('.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.phar', '.pht', '.inc')


def iocs(max_files, since):
    F = []
    add = F.append
    count, truncated, recent = 0, False, 0
    since_ts = time.mktime(datetime.datetime.strptime(since, '%Y-%m-%d').timetuple())
    skip = {'.git', '.svn', 'node_modules', '.cache'}
    for root in WEB_ROOTS:
        if truncated or not os.path.isdir(root):
            continue
        for base, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if d not in skip]
            for name in files:
                p = os.path.join(base, name)
                low = name.lower()
                if low in ('.user.ini', '.htaccess'):
                    try:
                        with open(p, 'rb') as f:
                            c = f.read(200000)
                        if re.search(rb'upload_progress\.enabled\s*[= ]\s*"?(1|on|true)', c, re.I):
                            add({'severity': 'medium', 'type': 'per_dir_reenables_upload_progress', 'path': p})
                        if re.search(rb'auto_(prepend|append)_file', c, re.I):
                            add({'severity': 'medium', 'type': 'per_dir_auto_prepend', 'path': p, 'sha256': sha256_file(p)})
                    except OSError:
                        pass
                    continue
                if not low.endswith(PHP_EXT):
                    continue
                count += 1
                if count > max_files:
                    truncated = True
                    break
                try:
                    st = os.lstat(p)
                    if max(st.st_mtime, st.st_ctime) >= since_ts:
                        recent += 1
                        if recent <= 200:
                            add({'severity': 'low', 'type': 'php_modified_since_%s' % since, 'path': p,
                                 'mtime_utc': datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc).isoformat()})
                    if st.st_size > 5000000:
                        continue
                    with open(p, 'rb') as f:
                        c = f.read(1500000)
                    lp = p.lower()
                    if SUSP_HIGH.search(c):
                        add({'severity': 'high', 'type': 'webshell_pattern', 'path': p, 'sha256': hashlib.sha256(c).hexdigest()})
                    elif SUSP_MED.search(c):
                        add({'severity': 'medium', 'type': 'obfuscated_eval', 'path': p, 'sha256': hashlib.sha256(c).hexdigest()})
                    if ('/uploads/' in lp or '/upload/' in lp) and not (low == 'index.php' and st.st_size < 200):
                        add({'severity': 'medium', 'type': 'php_in_upload_dir', 'path': p, 'sha256': hashlib.sha256(c).hexdigest()})
                except OSError:
                    pass
                if len(F) >= 1000:
                    truncated = True
                    break
            if truncated:
                break
    rc, out, _ = run(['ps', '-eo', 'pid=,ppid=,user=,comm=,args='], timeout=10)
    procs = {}
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4:
            procs[parts[0]] = parts + [''] * (5 - len(parts))
    for pid, (p_, ppid, user, comm, args) in procs.items():
        par = procs.get(ppid)
        if par and WEB_PARENTS.match(par[3]) and CHILD_TOOLS.match(comm):
            add({'severity': 'high', 'type': 'shell_spawned_by_web_worker', 'pid': pid, 'user': user,
                 'parent': par[3], 'cmd': args[:400]})
    try:
        for e in pwd.getpwall():
            if e.pw_uid == 0 and e.pw_name != 'root':
                add({'severity': 'high', 'type': 'extra_uid0_account', 'account': e.pw_name})
            if e.pw_name in WEB_USERS:
                for k in (os.path.join(e.pw_dir, '.ssh', 'authorized_keys'),):
                    if os.path.isfile(k):
                        add({'severity': 'high', 'type': 'web_user_authorized_keys', 'path': k})
                for c in ('/var/spool/cron/crontabs/' + e.pw_name, '/var/spool/cron/' + e.pw_name):
                    if os.path.isfile(c):
                        add({'severity': 'medium', 'type': 'web_user_crontab', 'path': c})
    except Exception:
        pass
    for d in ('/tmp', '/var/tmp', '/dev/shm'):
        for base, dirs, files in os.walk(d):
            if base.count(os.sep) - d.count(os.sep) >= 2:
                dirs[:] = []
            for n in files:
                p = os.path.join(base, n)
                if os.path.isfile(p) and not os.path.islink(p) and is_elf(p):
                    add({'severity': 'medium', 'type': 'elf_in_tmp', 'path': p, 'sha256': sha256_file(p)})
    sev = Counter(f['severity'] for f in F)
    return {'findings': F, 'counts': {'high': sev['high'], 'medium': sev['medium'], 'low': sev['low']},
            'php_files_inspected': min(count, max_files), 'php_modified_since': recent, 'truncated': truncated,
            'note': 'Triage heuristik saja. Nol temuan BUKAN bukti host bersih; temuan BUKAN bukti eksploitasi CVE ini.'}


def scan(args):
    t0 = time.time()
    proc_exes, groups = scan_procs()
    insts = [assess(i, groups, getattr(args, 'strict_backport', False)) for i in discover(proc_exes)]
    known = set(i['realpath'] for i in insts) | set(i['binary'] for i in insts)
    orphans = [g for g in groups if g['path'] not in known and g['stale']]
    rep = {'tool': 'php_guard', 'tool_version': VERSION, 'host': socket.getfqdn() or platform.node(),
           'scanned_at': utcnow().isoformat(), 'os': osinfo(), 'euid': os.geteuid(), 'kernel': platform.release(),
           'installations': insts, 'stale_processes_unmatched': orphans,
           'containers': [] if args.no_containers else scan_containers(),
           'fpm_pool_overrides_enabling_upload_progress': pool_overrides()}
    rep['ioc'] = None if args.no_ioc else iocs(args.max_files, args.since)
    rep['web_apps'] = [] if getattr(args, 'no_webapps', False) else detect_web_apps(
        getattr(args, 'webroot', None) or WEBROOT_DEFAULTS)
    rep['compromise'] = None if getattr(args, 'no_compromise', False) else compromise_scan(args)
    rep['health'] = None if getattr(args, 'no_health', False) else health_check(args)
    enrich_cves(rep, load_cvedb(getattr(args, 'cvedb', None)))
    finalize(rep)
    rep['duration_sec'] = round(time.time() - t0, 1)
    return rep


def _compromise_status(rep):
    """Status kompromi TERPISAH dari status patch: 'PATCHED' bukan bukti host bersih."""
    if rep.get('compromise') is None and rep.get('ioc') is None:
        return 'NOT_CHECKED'
    cc = (rep.get('compromise') or {}).get('counts') or {}
    ic = (rep.get('ioc') or {}).get('counts') or {}
    if cc.get('high', 0) + ic.get('high', 0):
        return 'HIGH_RISK_INDICATORS'
    if cc.get('medium', 0) + ic.get('medium', 0):
        return 'SUSPICIOUS'
    return 'NO_INDICATORS'


def finalize(rep):
    insts = rep['installations']
    verdicts = [i['verdict'] for i in insts] + [c['verdict'] for c in rep.get('containers', [])]
    if rep.get('stale_processes_unmatched'):
        verdicts.append('RESTART_REQUIRED')
    rep['host_verdict'] = max(verdicts, key=lambda x: VERDICT_RANK[x]) if verdicts else 'NO_PHP_FOUND'
    rep['vulnerability_status'] = rep['host_verdict']
    rep['compromise_status'] = _compromise_status(rep)
    web = [i for i in insts if i['kind'] != 'cli']
    vals = [i['info'].get('upload_progress') for i in web if i.get('info')]
    if not web:
        mit = 'N/A'
    elif rep['fpm_pool_overrides_enabling_upload_progress'] or any(v is not None and not is_off(v) for v in vals):
        mit = 'MISSING'
    elif vals and all(is_off(v) for v in vals):
        mit = 'PENDING_RESTART' if any(config_newer_than_procs(i) for i in web) else 'OK'
    else:
        mit = 'UNKNOWN'
    rep['mitigation_' + CVE_NOPATCH.replace('-', '_')] = mit
    rep['mitigation_status'] = mit
    rep['next_steps'] = next_steps(rep)


def config_newer_than_procs(inst):
    """True bila php.ini/conf.d berubah setelah worker yang jalan dimulai (setting belum aktif)."""
    start = (inst.get('running') or {}).get('oldest_start')
    info = inst.get('info') or {}
    if not start:
        return False
    files = [info.get('ini') or '']
    for d in (info.get('scan_dir') or '').split(':'):
        files += glob.glob(os.path.join(d, '*.ini')) if d else []
    for f in files:
        try:
            if f and os.stat(f).st_ctime > start + 2:
                return True
        except OSError:
            pass
    return False


def _steps_incident(rep, s):
    if rep.get('health_regressed'):
        s.append('PERINGATAN: kesehatan web TURUN setelah aksi (OK -> DEGRADED). Kemungkinan patch/restart '
                 'merusak layanan. Pertimbangkan rollback paket & cek log php-fpm/web server SEGERA.')
    ioc = rep.get('ioc') or {}
    active = [i for i in rep['installations'] if i.get('active_risk')]
    if active:
        s.append('PRIORITAS: %d instalasi PHP rentan/EOL dengan worker PHP aktif (proses jalan): %s. Tangani lebih dulu.'
                 % (len(active), ', '.join('%s %s' % (i['kind'], i['version_raw']) for i in active)))
    comp = rep.get('compromise') or {}
    if (comp.get('counts') or {}).get('high'):
        hi = [i['type'] for i in comp.get('indicators', []) if i['severity'] == 'high']
        s.append('TANDA KOMPROMI (HIGH): %s. Perlakukan host sebagai kemungkinan ter-breach: '
                 'snapshot/isolasi, simpan laporan JSON, JANGAN hapus bukti, eskalasi ke tim IR sebelum remediasi.'
                 % ', '.join(sorted(set(hi))))
    if (ioc.get('counts') or {}).get('high'):
        s.append('Ada indikator HIGH: snapshot/isolasi host, simpan laporan JSON, jangan hapus file temuan, eskalasi ke tim IR. '
                 'Patch tetap perlu, lakukan setelah bukti diamankan (`fix --force-with-findings`).')


def _steps_php(rep, s):
    bad = [i for i in rep['installations'] if i['verdict'] in ('VULNERABLE', 'UNVERIFIED', 'EOL_UNSUPPORTED')]
    if any(i['package'] and not RPM_PANEL_RE.match(i['package'].get('name', '')) and i['panel'] not in ('plesk', 'aapanel', 'directadmin/custom', 'cpanel-internal') for i in bad):
        s.append('Upgrade paket PHP: `sudo python3 php_guard.py fix --restart` (uji di canary dulu).')
    for p in sorted(set((i['panel'] or 'manual') for i in bad if not i['package'] or i['panel'] in ('cpanel', 'cloudlinux-alt', 'plesk', 'aapanel', 'directadmin/custom', 'cpanel-internal'))):
        s.append(PANEL_HINT.get(p, PANEL_HINT['manual']))
    eol_insts = [i for i in rep['installations'] if i['upstream_status'] == 'eol' and i['verdict'] != 'PATCHED_BACKPORT']
    if eol_insts:
        brs = ', '.join('%s (EOL %s)' % (i['branch'], i['eol_date'] or '?') for i in sorted(
            {i['branch']: i for i in eol_insts}.values(), key=lambda x: x['branch']))
        s.append('Branch EOL: %s -> tak ada perbaikan keamanan resmi lagi. Migrasi ke PHP %s, '
                 'atau pakai paket backport vendor/distro yang changelog-nya memuat perbaikan terkait.'
                 % (brs, UPGRADE_TARGET))
    if any(i['verdict'] == 'UNVERIFIED' for i in rep['installations']):
        s.append('UNVERIFIED: cocokkan versi paket dengan advisory distro (ubuntu.com/security, security-tracker.debian.org, access.redhat.com/security).')
    if rep['host_verdict'] == 'RESTART_REQUIRED' or any(i['verdict'] == 'RESTART_REQUIRED' for i in rep['installations']):
        s.append('Biner sudah baru tapi proses lama masih jalan: `sudo python3 php_guard.py restart`.')
    if any(c['verdict'] != 'PATCHED' for c in rep.get('containers', [])):
        s.append('Container: rebuild image dengan base PHP yang sudah patch, lalu redeploy (update di dalam container tidak permanen).')


def _steps_mitigation(rep, s):
    if rep['mitigation_status'] == 'PENDING_RESTART':
        s.append('Config mitigasi sudah ada tapi worker PHP belum direstart: `sudo python3 php_guard.py restart`.')
    if rep['mitigation_status'] in ('MISSING', 'UNKNOWN'):
        s.append('Pasang mitigasi %s (berlaku juga setelah patch): `sudo python3 php_guard.py mitigate --restart`.' % CVE_NOPATCH)


def _steps_cvedb(rep, s):
    cdb = rep.get('cvedb') or {}
    if not cdb.get('present'):
        s.append('DB CVE belum ada: jalankan `python3 php_guard.py cve-update` di mesin operator (online), '
                 'lalu kopi php_guard_cve.json ke server. Scan tetap jalan tanpa ini (verdict versi/EOL).')
    elif cdb.get('stale'):
        s.append('DB CVE sudah lawas (umur %s hari, ambang %d): perbarui dengan `cve-update` di mesin operator.'
                 % (cdb.get('age_days'), CVEDB_STALE_DAYS))


def _steps_env(rep, s):
    if rep['host_verdict'] == 'NO_PHP_FOUND':
        s.append('Tidak ada PHP terdeteksi di path umum. Jika host ini memang melayani PHP, periksa manual (build custom/container/K8s).')
    if rep['euid'] != 0:
        s.append('Scan tidak dijalankan sebagai root: hasil proses & file bisa tidak lengkap. Ulangi dengan sudo.')


def _steps_webapps(rep, s):
    bad = [a for a in rep.get('web_apps') or [] if a.get('status') in ('EOL', 'OUTDATED')]
    if bad:
        s.append('Framework/CMS EOL/OUTDATED (%d): %s. Upgrade core-nya; plugin/tema hanya diinventaris, cek advisory-nya terpisah.' % (
            len(bad), ', '.join('%s %s di %s' % (a['app'], a['version'] or '?', a['path']) for a in bad[:5])))
    apps = rep.get('web_apps') or []

    def paths(pred):
        return sorted(set(a['path'] for a in apps if pred(a)))
    wp = paths(lambda a: a['app'] == 'WordPress')
    if wp:
        s.append('Cek kerentanan plugin/tema WordPress (%s): `wp plugin list --update=available --path=DIR` (wp-cli), '
                 '`wpscan --url SITUS`, atau pasang Wordfence/Patchstack.' % ', '.join(wp[:5]))
    dr = paths(lambda a: a['app'] == 'Drupal' and not (a['version'] or '').startswith('7'))
    if dr:
        s.append('Cek advisory modul Drupal (%s): `drush pm:security` di direktori situs.' % ', '.join(dr[:5]))
    cp = paths(lambda a: a['category'] != 'fe' and os.path.isfile(os.path.join(a['path'], 'composer.lock')))
    if cp:
        s.append('Cek advisory dependensi Composer (%s): `composer audit` di direktori proyek.' % ', '.join(cp[:5]))


def next_steps(rep):
    s = []
    _steps_incident(rep, s)
    _steps_php(rep, s)
    _steps_mitigation(rep, s)
    _steps_cvedb(rep, s)
    _steps_webapps(rep, s)
    _steps_env(rep, s)
    return s


def web_units():
    if not shutil.which('systemctl'):
        return []
    rc, out, _ = run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--plain'])
    units = [l.split()[0] for l in out.splitlines() if l.strip()]
    return [u for u in units if re.search(r'(php.*fpm|^apache2|^httpd|^lsws|^lshttpd|^litespeed|^frankenphp)', u)]


def restart_services():
    res = []
    units = web_units()
    if not units:
        return [{'unit': '-', 'status': 'tidak ada unit systemd php-fpm/apache/lsws yang jalan; restart manual (panel/init.d/container)'}]
    for u in units:
        if re.match(r'^(apache2|httpd)', u):
            ctl = shutil.which('apache2ctl') or shutil.which('apachectl') or shutil.which('httpd')
            if ctl:
                rc, o, e = run([ctl, '-t'], timeout=30)
                if rc != 0:
                    res.append({'unit': u, 'status': 'skipped_configtest_failed', 'detail': (o + e)[-600:]})
                    continue
        rc, _, e = run(['systemctl', 'restart', u], timeout=180)
        _, act, _ = run(['systemctl', 'is-active', u])
        res.append({'unit': u, 'status': 'restarted' if rc == 0 and act.strip() == 'active' else 'FAILED',
                    'active': act.strip(), 'error': e[-600:]})
    return res


def high_gate(rep, args):
    h = (((rep.get('ioc') or {}).get('counts') or {}).get('high', 0)
         + ((rep.get('compromise') or {}).get('counts') or {}).get('high', 0))
    if h and not args.force_with_findings:
        return ('Ditolak: %d indikator HIGH (webshell/kompromi). Jangan ubah host yang diduga '
                'disusupi sebelum bukti forensik diamankan. Lalu ulang dengan --force-with-findings.' % h)
    return None


def do_fix(rep, args):
    if os.geteuid() != 0:
        return {'status': 'refused', 'reason': 'Perlu root'}
    g = high_gate(rep, args)
    if g:
        return {'status': 'refused', 'reason': g}
    mgr, pkgs = installed_php_pkgs(args.include_panels)
    if mgr == 'pacman':
        return {'status': 'refused', 'reason': 'Arch: wajib `pacman -Syu` penuh, lakukan manual'}
    if not mgr or not pkgs:
        return {'status': 'manual_required', 'reason': 'Tidak ada paket PHP terkelola package manager', 'hints': [PANEL_HINT.get(i['panel'] or 'manual') for i in rep['installations']]}
    env = None
    if mgr == 'apt':
        env = {'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'l'}
        steps = [['apt-get', 'update'],
                 ['apt-get', '-y', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold',
                  'install', '--only-upgrade'] + pkgs]
    elif mgr in ('dnf', 'yum'):
        steps = [[mgr, '-y', 'upgrade' if mgr == 'dnf' else 'update'] + pkgs]
    elif mgr == 'zypper':
        steps = [['zypper', '--non-interactive', 'update'] + pkgs]
    else:
        steps = [['apk', 'update'], ['apk', 'add', '--upgrade'] + pkgs]
    log = []
    for i, st in enumerate(steps):
        rc, o, e = run(st, timeout=1200, env=env)
        log.append({'command': ' '.join(st), 'rc': rc, 'stdout_tail': o[-3000:], 'stderr_tail': e[-1500:]})
        is_refresh = (mgr in ('apt', 'apk') and i == 0)
        if rc != 0:
            if is_refresh and not getattr(args, 'allow_stale_metadata', False):
                return {'status': 'FAILED', 'manager': mgr, 'packages': pkgs, 'steps': log,
                        'reason': 'Refresh repository (%s) gagal; patch dihentikan agar tidak memasang dari '
                                  'metadata basi. Perbaiki jaringan/repo, atau pakai --allow-stale-metadata '
                                  'untuk lanjut secara sadar.' % ' '.join(st)}
            if not is_refresh:
                return {'status': 'FAILED', 'manager': mgr, 'packages': pkgs, 'steps': log}
    return {'status': 'packages_updated', 'manager': mgr, 'packages': pkgs, 'steps': log}


def do_mitigate(rep, args):
    if os.geteuid() != 0:
        return {'status': 'refused', 'reason': 'Perlu root'}
    targets = {}
    for i in rep['installations']:
        if i['kind'] == 'cli':
            continue
        sd = (i.get('info') or {}).get('scan_dir')
        if not sd or sd == '(none)':
            continue
        for d in sd.split(':'):
            if os.path.isdir(d):
                t = targets.setdefault(d, {'need_feb': False, 'used_by': []})
                t['used_by'].append(i['binary'])
                if i['branch'] == '8.5' and not i['verdict'].startswith('PATCHED'):
                    t['need_feb'] = True
    if not targets:
        return {'status': 'manual_required', 'reason': 'Direktori conf.d PHP web tidak ditemukan; set session.upload_progress.enabled=0 di php.ini/pool secara manual'}
    written = []
    for d, t in sorted(targets.items()):
        lines = ['; Ditambahkan oleh php_guard.py %s pada %s' % (VERSION, utcnow().isoformat()),
                 '; Mitigasi CVE-2026-109619 & %s. Pertahankan sampai PHP merilis perbaikan %s.' % (CVE_NOPATCH, CVE_NOPATCH),
                 'session.upload_progress.enabled = 0']
        if t['need_feb']:
            lines.append('fatal_error_backtraces = 0   ; PHP 8.5 belum patch (CVE-2026-109619)')
        path = os.path.join(d, DROPIN)
        try:
            with open(path, 'w') as f:
                f.write('\n'.join(lines) + '\n')
            os.chmod(path, 0o644)
            written.append({'file': path, 'used_by': t['used_by']})
        except OSError as e:
            written.append({'file': path, 'error': str(e)})
    return {'status': 'written', 'files': written,
            'note': 'Berlaku setelah worker PHP direstart. Override php_value di pool FPM tetap perlu dicek (lihat laporan).'}


def _sum_header(rep, w):
    w('=' * 78)
    w('php_guard %s | %s | %s' % (VERSION, rep.get('host'), rep['os'].get('pretty')))
    w('Waktu scan: %s  (root=%s)' % (rep['scanned_at'], rep['euid'] == 0))
    w('STATUS HOST : %s' % rep['host_verdict'])
    w('  kerentanan PHP : %s' % rep.get('vulnerability_status', rep['host_verdict']))
    w('  kompromi       : %s  (PATCHED bukan bukti host bersih)' % rep.get('compromise_status', 'NOT_CHECKED'))
    h = rep.get('health')
    if h:
        up = sum(1 for p in h['fpm_pools'] if p['reachable'])
        w('  kesehatan web  : %s%s (fpm %d/%d, http:80 %s)'
          % (h['status'], ' <== TURUN setelah aksi!' if rep.get('health_regressed') else '',
             up, len(h['fpm_pools']), h['http_127_0_0_1_80'] if h['http_127_0_0_1_80'] is not None else '-'))
    w('Mitigasi %s (upload_progress=0): %s' % (CVE_NOPATCH, rep['mitigation_status']))
    w('-' * 78)


def _sum_installations(rep, w):
    for i in rep['installations']:
        pk = i['package'].get('name', '-') if i['package'] else '-'
        info = i.get('info') or {}
        w('[%-10s] %s' % (i['kind'], i['binary']))
        w('    versi %s (branch %s%s) | paket %s %s | panel %s'
          % (i['version_raw'], i['branch'], ' EOL ' + i['eol_date'] if i.get('eol_date') else '',
             pk, (i['package'] or {}).get('version', ''), i['panel'] or '-'))
        patokan = i['fixed_in'] or ('EOL ' + i['eol_date'] if i.get('eol_date') else '-')
        active = '  <== RENTAN & AKTIF (worker PHP aktif)' if i.get('active_risk') else ''
        w('    upstream=%s (patch-aman %s) backport=%s -> %s%s'
          % (i['upstream_status'], patokan, i['vendor_backport'], i['verdict'], active))
        w('    proses %d (lama %d) | upload_progress=%s'
          % (i['running']['processes'], i['running']['stale'], info.get('upload_progress', '?')))
        cve = i.get('cve_unpatched') or []
        if cve:
            w('    CVE belum ter-patch (%d): %s'
              % (len(cve), ', '.join('%s<fix %s>' % (c['cve'], c['fixed_in']) for c in cve[:12])
                 + (' ...' if len(cve) > 12 else '')))
    for c in rep.get('containers', []):
        w('[container ] %s %s (%s) -> %s : %s' % (c['runtime'], c['name'], c['image'], c['verdict'],
                                                  ', '.join(x['version_raw'] for x in c['php'])))
    for g in rep.get('stale_processes_unmatched', []):
        w('[proses lama] %s : %d proses masih memakai biner lama/terhapus' % (g['path'], g['stale']))
    for o in rep.get('fpm_pool_overrides_enabling_upload_progress', []):
        w('[pool FPM ] %s:%d menyalakan upload_progress (%s)' % (o['file'], o['line'], o['value']))


def _sum_webapps(rep, w):
    apps = rep.get('web_apps') or []
    if not apps:
        return
    w('-' * 78)
    w('Framework/CMS terdeteksi: %d' % len(apps))
    for a in apps:
        w('  [%-3s] %-12s %-10s %-9s %s' % (a['category'], a['app'], a['version'] or '?',
                                            a.get('status', ''), a['path']))
        w('        aman-min %s -> %s' % (a.get('min_safe') or '-', a['suggestion']))
        ext = a.get('extensions')
        if ext:
            cnt = Counter(e['type'] for e in ext)
            w('        ekstensi: %s (versi saja, belum dicek CVE; daftar lengkap di JSON)' %
              ', '.join('%s %d' % (t, cnt[t]) for t in sorted(cnt)))
            for e in ext[:10]:
                w('          - %-9s %-28s %s' % (e['type'], e['slug'][:28], e['version'] or '?'))
            if len(ext) > 10:
                w('          ... +%d lagi' % (len(ext) - 10))


def _sum_compromise(rep, w):
    comp = rep.get('compromise')
    if not comp:
        return
    w('-' * 78)
    cc = comp.get('counts', {})
    w('KOMPROMI: indikator HIGH %d | MEDIUM %d' % (cc.get('high', 0), cc.get('medium', 0)))
    for it in comp.get('indicators', [])[:20]:
        w('  %-6s %-24s %s' % (it['severity'].upper(), it['type'], it['detail']))
    pi = comp.get('package_integrity') or {}
    if pi.get('enabled'):
        w('  integritas paket (%s): %d file berubah' % (pi.get('tool'), pi.get('count', 0)))


def _sum_cvedb(rep, w):
    cdb = rep.get('cvedb') or {}
    if cdb.get('present'):
        age = cdb.get('age_days')
        tag = '' if age is None else ' | umur %d hari%s' % (age, ' — LAWAS, jalankan cve-update' if cdb.get('stale') else '')
        w('DB CVE: %d CVE (%s, diperbarui %s%s)'
          % (cdb.get('count', 0), cdb.get('source', ''), (cdb.get('generated_at') or '')[:10], tag))
    elif cdb:
        w('DB CVE: tidak ada -> detail CVE per-nomor dilewati (verdict pakai tabel versi/EOL bawaan).')


def _sum_ioc(rep, w):
    ioc = rep.get('ioc')
    if not ioc:
        return
    c = ioc['counts']
    w('Indikator: HIGH %d | MEDIUM %d | LOW %d | file PHP dicek %d%s'
      % (c['high'], c['medium'], c['low'], ioc['php_files_inspected'], ' (TERPOTONG)' if ioc['truncated'] else ''))
    for f in [x for x in ioc['findings'] if x['severity'] == 'high'][:10]:
        w('    HIGH %s %s' % (f['type'], f.get('path') or f.get('cmd') or f.get('account', '')))


def _sum_actions(rep, w):
    for k in ('fix_result', 'mitigate_result'):
        if rep.get(k):
            w('%s: %s %s' % (k, rep[k].get('status'), rep[k].get('reason', '')))
    for r in rep.get('restart_result') or []:
        w('restart %s: %s' % (r['unit'], r['status']))
    if rep['next_steps']:
        w('Langkah berikutnya:')
        for n, s in enumerate(rep['next_steps'], 1):
            w('  %d. %s' % (n, s))
    w('=' * 78)


def summary(rep):
    W = []
    w = W.append
    _sum_header(rep, w)
    _sum_installations(rep, w)
    _sum_webapps(rep, w)
    _sum_compromise(rep, w)
    _sum_cvedb(rep, w)
    _sum_ioc(rep, w)
    _sum_actions(rep, w)
    return '\n'.join(W)


def exit_code(rep):
    if rep.get('health_regressed'):
        return 2
    if ((rep.get('ioc') or {}).get('counts') or {}).get('high') or \
       ((rep.get('compromise') or {}).get('counts') or {}).get('high'):
        return 2
    for k in ('fix_result', 'mitigate_result'):
        if (rep.get(k) or {}).get('status') == 'FAILED':
            return 3
    if any(a.get('status') in ('EOL', 'OUTDATED') for a in rep.get('web_apps') or []):
        return 1
    if rep['host_verdict'] in ('PATCHED', 'PATCHED_BACKPORT', 'NO_PHP_FOUND') and rep['mitigation_status'] in ('OK', 'N/A'):
        return 0
    return 1


def save_report(rep, path):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(rep, f, indent=2, ensure_ascii=False, sort_keys=True)
    os.chmod(path, 0o600)
    uid, gid = os.environ.get('SUDO_UID'), os.environ.get('SUDO_GID')
    if os.geteuid() == 0 and uid and gid:
        try:
            os.chown(path, int(uid), int(gid))
        except OSError:
            pass


def local_main(args):
    rep = scan(args)
    rep['action'] = args.cmd
    rescan = False
    if args.cmd == 'fix':
        rep['fix_result'] = do_fix(rep, args)
        rescan = rep['fix_result']['status'] == 'packages_updated'
    elif args.cmd == 'mitigate':
        rep['mitigate_result'] = do_mitigate(rep, args)
        rescan = rep['mitigate_result']['status'] == 'written'
    if args.cmd == 'restart' or (args.cmd in ('fix', 'mitigate') and args.restart and rescan):
        if os.geteuid() != 0:
            rep['restart_result'] = [{'unit': '-', 'status': 'refused (perlu root)'}]
        else:
            rep['restart_result'] = restart_services()
            time.sleep(2)
        rescan = True
    if rescan:
        before = {k: rep[k] for k in ('fix_result', 'mitigate_result', 'restart_result') if k in rep}
        ioc = rep['ioc']
        args.no_ioc = True
        rep2 = scan(args)
        rep2.update(before)
        rep2['ioc'] = ioc
        rep2['action'] = args.cmd
        finalize(rep2)
        before_h = (rep.get('health') or {}).get('status')
        after_h = (rep2.get('health') or {}).get('status')
        rep2['health_regressed'] = bool(before_h == 'OK' and after_h in ('DEGRADED', 'UNVERIFIED'))
        rep2['state_before_action'] = {'host_verdict': rep['host_verdict'],
                                       'mitigation_status': rep['mitigation_status'], 'health': before_h}
        rep = rep2
    out = args.out or 'php_guard_%s_%s.json' % (re.sub(r'[^\w.-]', '_', platform.node()), utcnow().strftime('%Y%m%dT%H%M%SZ'))
    save_report(rep, out)
    if not args.quiet:
        print(summary(rep))
        print('Laporan JSON: %s' % os.path.abspath(out))
    return exit_code(rep)


CVEDB_NAME = 'php_guard_cve.json'
CVEDB_STALE_DAYS = 30
CHANGELOG_URLS = ['https://www.php.net/ChangeLog-8.php', 'https://www.php.net/ChangeLog-7.php']


def cve_age_days(iso):
    """Umur DB CVE dalam hari dari stempel generated_at. Memakai bagian tanggal
    saja (granularitas hari) agar kompatibel Python 3.6 -- tak memakai
    datetime.fromisoformat yang baru ada di 3.7. None bila tak terbaca."""
    if not iso:
        return None
    try:
        t = datetime.datetime.strptime(str(iso)[:10], '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc)
    except (ValueError, TypeError):
        return None
    return (utcnow() - t).days


def cvedb_path(explicit=None):
    if explicit:
        return os.path.expanduser(explicit)
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), CVEDB_NAME)
    return here if os.path.exists(here) else CVEDB_NAME


def load_cvedb(explicit=None):
    """Muat basis data CVE JSON. None bila tak ada/tak valid (scan tetap jalan)."""
    p = cvedb_path(explicit)
    if not os.path.exists(p):
        return None
    try:
        with open(p) as f:
            db = json.load(f)
        if isinstance(db, dict) and isinstance(db.get('branches'), dict):
            return db
    except (OSError, ValueError):
        pass
    return None


def cves_for_version(v, cvedb):
    """CVE yang memengaruhi versi v: fixed_in di branch sama DAN lebih baru dari v."""
    if not v or not cvedb:
        return []
    out = []
    for e in cvedb.get('branches', {}).get('%d.%d' % v[:2], []):
        fv = vtuple(e.get('fixed_in', ''))
        if fv and fv > v:
            out.append({'cve': e.get('cve'), 'fixed_in': e.get('fixed_in')})
    out.sort(key=lambda x: vtuple(x['fixed_in']) or (0, 0, 0))
    return out


def enrich_cves(rep, cvedb):
    """Tempel daftar cve_unpatched per instalasi; naikkan verdict PATCHED->VULNERABLE
    bila ternyata ada rilis keamanan lebih baru (DB CVE lebih mutakhir dari tabel FIXED)."""
    if not cvedb:
        rep['cvedb'] = {'present': False}
        return
    gen = cvedb.get('generated_at')
    rep['cvedb'] = {'present': True, 'generated_at': gen, 'source': cvedb.get('source'),
                    'age_days': cve_age_days(gen), 'stale': (cve_age_days(gen) or 0) > CVEDB_STALE_DAYS,
                    'count': sum(len(x) for x in cvedb.get('branches', {}).values())}
    for i in rep['installations']:
        lst = cves_for_version(vtuple(i['version_raw']), cvedb)
        i['cve_unpatched'] = lst
        if lst and i['verdict'] in ('PATCHED', 'RESTART_REQUIRED'):
            i['verdict'] = 'VULNERABLE'
            i['active_risk'] = i['running']['processes'] > 0
    for c in rep.get('containers', []):
        for it in c.get('php', []):
            it['cve_unpatched'] = cves_for_version(vtuple(it['version_raw']), cvedb)


def parse_changelog(html):
    """Ekstrak {branch: [{cve, fixed_in}]} dari HTML php.net ChangeLog."""
    heads = [(m.start(), m.group(1)) for m in re.finditer(r'Version\s+(\d+\.\d+\.\d+)', html)]
    seen = {}
    for idx, (pos, ver) in enumerate(heads):
        end = heads[idx + 1][0] if idx + 1 < len(heads) else len(html)
        vt = vtuple(ver)
        for cve in set(re.findall(r'CVE-\d{4}-\d{3,7}', html[pos:end])):
            prev = seen.get(cve)
            if prev is None or vt < prev[1]:
                seen[cve] = (ver, vt)
    branches = {}
    for cve, (ver, vt) in seen.items():
        branches.setdefault('%d.%d' % vt[:2], []).append({'cve': cve, 'fixed_in': ver})
    for b in branches.values():
        b.sort(key=lambda e: vtuple(e['fixed_in']))
    return branches


def do_cve_update(args):
    import urllib.request
    out = args.out or CVEDB_NAME
    older = getattr(args, 'if_older_than', None)
    if older is not None and os.path.exists(out):
        try:
            with open(out) as f:
                age = cve_age_days(json.load(f).get('generated_at'))
            if age is not None and age < older:
                print('DB CVE masih segar (umur %d hari < %d) di %s -- dilewati.' % (age, older, out))
                return 0
        except (OSError, ValueError):
            pass
    urls = args.source or CHANGELOG_URLS
    merged = {}
    for url in urls:
        sys.stderr.write('mengambil %s ...\n' % url)
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'php_guard/%s' % VERSION})
            with urllib.request.urlopen(req, timeout=60) as r:
                html = r.read().decode('utf-8', 'replace')
        except Exception as e:
            sys.stderr.write('  gagal: %s\n' % e)
            continue
        for b, lst in parse_changelog(html).items():
            cur = {e['cve']: e for e in merged.get(b, [])}
            for e in lst:
                if e['cve'] not in cur or vtuple(e['fixed_in']) < vtuple(cur[e['cve']]['fixed_in']):
                    cur[e['cve']] = e
            merged[b] = sorted(cur.values(), key=lambda x: vtuple(x['fixed_in']))
    total = sum(len(v) for v in merged.values())
    if not total:
        sys.exit('Tidak ada CVE terparse (format ChangeLog berubah atau tak ada koneksi).')
    with open(out, 'w') as f:
        json.dump({'generated_at': utcnow().isoformat(), 'source': 'php.net ChangeLog',
                   'branches': merged}, f, indent=2, ensure_ascii=False, sort_keys=True)
    print('%d CVE dari %d branch ditulis ke %s' % (total, len(merged), out))
    print('Kopi file ini ke tiap server (satu folder dengan php_guard.py), lalu jalankan scan.')
    return 0


WEBROOT_DEFAULTS = ['/var/www', '/var/www/html', '/srv/www', '/srv/http',
                    '/usr/share/nginx/html', '/usr/share/webapps', '/home']

WEBAPP_SIGS = [
    ('WordPress', 'cms', 'wp-includes/version.php', 'wp-includes/version.php', r"\$wp_version\s*=\s*'([^']+)'"),
    ('Joomla', 'cms', 'administrator/manifests/files/joomla.xml', 'administrator/manifests/files/joomla.xml', r'<version>\s*([0-9][0-9.]*)'),
    ('Drupal', 'cms', 'core/lib/Drupal.php', 'core/lib/Drupal.php', r"const VERSION\s*=\s*'([^']+)'"),
    ('Drupal', 'cms', 'includes/bootstrap.inc', 'includes/bootstrap.inc', r"define\('VERSION',\s*'([^']+)'"),
    ('Moodle', 'cms', 'lib/moodlelib.php', 'version.php', r"\$release\s*=\s*'([\d.]+)"),
    ('MediaWiki', 'cms', 'includes/Defines.php', 'includes/Defines.php', r"MW_VERSION',\s*'([^']+)'"),
    ('phpBB', 'cms', 'includes/constants.php', 'includes/constants.php', r"PHPBB_VERSION',\s*'([^']+)'"),
    ('phpMyAdmin', 'app', 'libraries/classes/Version.php', 'libraries/classes/Version.php', r"VERSION\s*=\s*'([^']+)'"),
    ('PrestaShop', 'cms', 'config/settings.inc.php', 'config/settings.inc.php', r"_PS_VERSION_',\s*'([^']+)'"),
    ('OpenCart', 'cms', 'system/startup.php', 'index.php', r"define\('VERSION',\s*'([^']+)'"),
    ('CodeIgniter', 'be', 'system/core/CodeIgniter.php', 'system/core/CodeIgniter.php', r"CI_VERSION',\s*'([^']+)'"),
]

COMPOSER_PKGS = [('laravel/framework', 'Laravel', 'be'), ('symfony/framework-bundle', 'Symfony', 'be'),
                 ('symfony/symfony', 'Symfony', 'be'), ('codeigniter4/framework', 'CodeIgniter', 'be'),
                 ('cakephp/cakephp', 'CakePHP', 'be'), ('yiisoft/yii2', 'Yii', 'be'),
                 ('laminas/laminas-mvc', 'Laminas', 'be'), ('magento/product-community-edition', 'Magento', 'cms'),
                 ('drupal/core', 'Drupal', 'cms')]

NPM_PKGS = [('react', 'React'), ('vue', 'Vue'), ('@angular/core', 'Angular'),
            ('next', 'Next.js'), ('nuxt', 'Nuxt'), ('svelte', 'Svelte'),
            ('bootstrap', 'Bootstrap'), ('jquery', 'jQuery')]

WEBAPP_EOL = {
    ('Magento', '1'): 'Magento 1 EOL 2020-06-30 -> migrasi ke Magento 2 / Adobe Commerce.',
    ('Drupal', '7'): 'Drupal 7 EOL 2025-01-05 -> migrasi ke Drupal 10+.',
    ('Drupal', '8'): 'Drupal 8 EOL 2021-11-17 -> upgrade ke Drupal 10+.',
    ('Joomla', '3'): 'Joomla 3 EOL 2023-08-17 -> upgrade ke Joomla 4/5.',
    ('CodeIgniter', '3'): 'CodeIgniter 3 tak lagi dikembangkan -> migrasi ke CodeIgniter 4.',
    ('CakePHP', '2'): 'CakePHP 2 EOL -> upgrade ke CakePHP 4/5.',
    ('Yii', '1'): 'Yii 1 EOL -> upgrade ke Yii 2+.',
}


WEBAPP_MINSAFE = {
    'WordPress': ('6.0', 'pakai branch 6.x & aktifkan auto-update core + plugin'),
    'Drupal': ('10', 'Drupal 10+ (9 dan 7 sudah EOL)'),
    'Joomla': ('4', 'Joomla 4/5 (3 EOL)'),
    'Laravel': ('10', 'Laravel 10/11 (cek kebijakan dukungan rilis)'),
    'Symfony': ('6.4', 'Symfony 6.4 LTS atau 7.x'),
    'CodeIgniter': ('4', 'CodeIgniter 4 (3 tak dikembangkan lagi)'),
    'CakePHP': ('4', 'CakePHP 4/5'),
    'Yii': ('2', 'Yii 2+'),
    'Laminas': ('3', 'Laminas MVC 3+ (Zend Framework EOL)'),
    'Magento': ('2.4', 'Magento 2.4.x (1 EOL)'),
    'Moodle': ('4.1', 'Moodle 4.1 LTS atau lebih baru'),
    'MediaWiki': ('1.39', 'MediaWiki 1.39 LTS atau lebih baru'),
    'phpMyAdmin': ('5.2', 'phpMyAdmin 5.2+'),
    'phpBB': ('3.3', 'phpBB 3.3+'),
    'PrestaShop': ('8', 'PrestaShop 8.x'),
    'OpenCart': ('4', 'OpenCart 4.x'),
}


def _ver_tuple(s):
    parts = re.findall(r'\d+', s or '')
    return tuple(int(x) for x in parts[:4]) if parts else None


def _read_file(path, limit=300000):
    try:
        with open(path, 'rb') as f:
            return f.read(limit).decode('utf-8', 'replace')
    except OSError:
        return ''


def _app_status(name, version, cat):
    """Kembalikan (status, min_safe, suggestion) untuk aplikasi terdeteksi."""
    major = (version or '').split('.')[0]
    eol = WEBAPP_EOL.get((name, major))
    minsafe = WEBAPP_MINSAFE.get(name)
    ms = minsafe[0] if minsafe else ''
    if eol:
        return 'EOL', ms, eol
    if cat == 'fe':
        return 'INFO', '', 'Perbarui dependensi FE & jalankan `npm audit` untuk %s.' % name
    v = _ver_tuple(version)
    if minsafe and v:
        if v < _ver_tuple(minsafe[0]):
            return 'OUTDATED', ms, 'Versi < aman minimum %s -> upgrade. %s.' % (minsafe[0], minsafe[1])
        return 'OK', ms, 'Memenuhi versi aman minimum (%s). Tetap pantau rilis & advisory %s.' % (minsafe[0], name)
    return 'UNKNOWN', ms, 'Samakan dengan rilis terbaru & cek advisory keamanan %s.' % name


def _app_record(name, cat, version, path):
    status, min_safe, suggestion = _app_status(name, version, cat)
    rec = {'app': name, 'category': cat, 'version': version, 'path': path,
           'status': status, 'min_safe': min_safe, 'suggestion': suggestion}
    if name in EXT_INVENTORY:
        rec['extensions'] = EXT_INVENTORY[name](path)
    return rec


MAX_EXT = 500


def _hdr(text, key):
    m = re.search(r'^[ \t/*#@]*' + re.escape(key) + r'\s*:\s*(.+?)\s*(?:\*/)?$', text, re.M | re.I)
    return m.group(1).strip() if m else ''


def _ls(d):
    try:
        return sorted(os.listdir(d))
    except OSError:
        return []


def _wp_extensions(root):
    """Plugin, mu-plugin, dan tema WordPress dari header file (nama & versi saja, tanpa cek CVE)."""
    out, wc = [], os.path.join(root, 'wp-content')
    for typ, sub in (('plugin', 'plugins'), ('mu-plugin', 'mu-plugins')):
        base = os.path.join(wc, sub)
        for n in _ls(base):
            p = os.path.join(base, n)
            files = [os.path.join(p, f) for f in _ls(p) if f.endswith('.php')] if os.path.isdir(p) else \
                ([p] if n.endswith('.php') else [])
            for f in files:
                txt = _read_file(f, 8192)
                name = _hdr(txt, 'Plugin Name')
                if name:
                    out.append({'type': typ, 'slug': n[:-4] if n.endswith('.php') else n, 'name': name,
                                'version': _hdr(txt, 'Version'), 'path': p})
                    break
            if len(out) >= MAX_EXT:
                return out
    base = os.path.join(wc, 'themes')
    for n in _ls(base):
        txt = _read_file(os.path.join(base, n, 'style.css'), 8192)
        name = _hdr(txt, 'Theme Name')
        if name:
            out.append({'type': 'theme', 'slug': n, 'name': name, 'version': _hdr(txt, 'Version'),
                        'path': os.path.join(base, n)})
        if len(out) >= MAX_EXT:
            break
    return out


def _joomla_extensions(root):
    """Komponen, plugin, modul, dan template Joomla dari manifest XML."""
    out, seen = [], set()
    globs = [('component', 'administrator/components/com_*/*.xml'), ('plugin', 'plugins/*/*/*.xml'),
             ('module', 'modules/mod_*/*.xml'), ('template', 'templates/*/templateDetails.xml')]
    for typ, g in globs:
        for f in sorted(glob.glob(os.path.join(root, g))):
            d = os.path.dirname(f)
            if d in seen:
                continue
            txt = _read_file(f, 16384)
            if not re.search(r'<(extension|install)\b', txt):
                continue
            nm, vm = re.search(r'<name>\s*([^<]+?)\s*</name>', txt), re.search(r'<version>\s*([^<]+?)\s*</version>', txt)
            seen.add(d)
            out.append({'type': typ, 'slug': os.path.basename(d), 'name': nm.group(1) if nm else os.path.basename(d),
                        'version': vm.group(1) if vm else '', 'path': d})
            if len(out) >= MAX_EXT:
                return out
    return out


def _drupal_extensions(root):
    """Modul & tema Drupal non-core: *.info.yml (8+) atau *.info (7)."""
    out = []
    subs = [('module', 'sites/all/modules'), ('theme', 'sites/all/themes')]
    if os.path.exists(os.path.join(root, 'core/lib/Drupal.php')):
        subs = [('module', 'modules'), ('theme', 'themes')] + subs  # di Drupal 7 folder ini berisi modul core
    for typ, sub in subs:
        base = os.path.join(root, sub)
        for n in _ls(base):
            d = os.path.join(base, n)
            dirs = [os.path.join(d, x) for x in _ls(d)] if n in ('contrib', 'custom') else [d]
            for d2 in dirs:
                slug = os.path.basename(d2)
                for ext, rx in (('.info.yml', r"^version:\s*['\"]?([^'\"\s]+)"), ('.info', r'^version\s*=\s*"?([^"\s]+)')):
                    txt = _read_file(os.path.join(d2, slug + ext), 8192)
                    if txt:
                        nm = re.search(r'^name\s*[:=]\s*[\'"]?(.+?)[\'"]?\s*$', txt, re.M)
                        vm = re.search(rx, txt, re.M)
                        out.append({'type': typ, 'slug': slug, 'name': nm.group(1) if nm else slug,
                                    'version': vm.group(1) if vm else '', 'path': d2})
                        break
                if len(out) >= MAX_EXT:
                    return out
    return out


EXT_INVENTORY = {'WordPress': _wp_extensions, 'Joomla': _joomla_extensions, 'Drupal': _drupal_extensions}


def _detect_in_dir(d, found, seen):
    for name, cat, marker, vfile, rx in WEBAPP_SIGS:
        if (name, d) in seen or not os.path.exists(os.path.join(d, marker)):
            continue
        m = re.search(rx, _read_file(os.path.join(d, vfile)))
        seen.add((name, d))
        found.append(_app_record(name, cat, m.group(1) if m else '', d))
    cl = os.path.join(d, 'composer.lock')
    if os.path.exists(cl):
        try:
            data = json.loads(_read_file(cl, 3000000) or '{}')
            pkgs = {p.get('name'): p.get('version', '') for p in (data.get('packages') or []) + (data.get('packages-dev') or [])}
        except ValueError:
            pkgs = {}
        for pkg, label, cat in COMPOSER_PKGS:
            if pkg in pkgs and (label, d) not in seen:
                seen.add((label, d))
                found.append(_app_record(label, cat, re.sub(r'^v', '', pkgs[pkg] or ''), d))
    pj = os.path.join(d, 'package.json')
    if os.path.exists(pj):
        try:
            data = json.loads(_read_file(pj) or '{}')
            deps = dict(data.get('dependencies') or {}); deps.update(data.get('devDependencies') or {})
        except ValueError:
            deps = {}
        for pkg, label in NPM_PKGS:
            if pkg in deps and (label, d) not in seen:
                seen.add((label, d))
                found.append(_app_record(label, 'fe', re.sub(r'^[\^~>=v ]+', '', str(deps[pkg])), d))


def detect_web_apps(roots, max_depth=4, max_dirs=8000):
    found, seen, visited = [], set(), 0
    for root in roots:
        if not os.path.isdir(root):
            continue
        base = root.rstrip('/').count('/')
        for dirpath, dirnames, _ in os.walk(root):
            visited += 1
            if visited > max_dirs:
                break
            if dirpath.rstrip('/').count('/') - base > max_depth:
                dirnames[:] = []
                continue
            dirnames[:] = [x for x in dirnames if x not in ('node_modules', '.git', 'vendor', 'cache', 'storage', 'tmp')]
            _detect_in_dir(dirpath, found, seen)
    return found


PERSIST_SUSP = re.compile(
    r'(curl\s|wget\s|base64\s+-d|/tmp/|/dev/shm/|/var/tmp/|python[0-9.]*\s+-c|perl\s+-e|'
    r'bash\s+-i|sh\s+-i|\bnc\b.*\s-e|ncat\s|/dev/tcp/|\beval\b|\|\s*sh\b|\|\s*bash\b|'
    r'xmrig|kinsing|chmod\s+\+?x|chattr\s|crontab\s+-)', re.I)
HTTP_SUSP = [
    ('webshell_access', re.compile(r'\.(php|phtml|phar)\?[^ ]*(cmd|exec|system|shell|passthru|eval|c99|r57|wso|b374k|filesrc|download|whoami)=', re.I)),
    ('sqli', re.compile(r'(union(\s|/\*\*/|\+)+select|information_schema|concat\(|sleep\(\s*\d|benchmark\()', re.I)),
    ('traversal', re.compile(r'(\.\./){2,}|/etc/passwd|/proc/self/environ', re.I)),
    ('scanner_ua', re.compile(r'(sqlmap|nikto|acunetix|nessus|masscan|wpscan|dirbuster|gobuster|hydra)', re.I)),
    ('rce_probe', re.compile(r'(allow_url_include|php://input|data://text|expect://|\$\{jndi:)', re.I)),
]
AUTH_FAILED = re.compile(r'Failed password|authentication failure|Invalid user')
AUTH_ACCEPT = re.compile(r'Accepted (password|publickey|keyboard)')
AUTH_SUDO = re.compile(r'sudo:.*COMMAND=')
AUTH_USERADD = re.compile(r'useradd\[|new user:|new group:')


def _sha_line(s):
    return hashlib.sha256(s.encode('utf-8', 'replace')).hexdigest()[:16]


def _iter_lines(path, max_lines):
    op = gzip.open if path.endswith('.gz') else open
    try:
        with op(path, 'rt', errors='replace') as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                yield line
    except OSError:
        return


def _scan_cron_file(f, hits):
    if not os.path.isfile(f):
        return
    for ln, line in enumerate(_iter_lines(f, 5000), 1):
        s = line.strip()
        if s and not s.startswith('#') and PERSIST_SUSP.search(s):
            hits.append({'file': f, 'line': ln, 'snippet': s[:160], 'sha256': _sha_line(s)})


def _scan_cron():
    hits = []
    always = ['/etc/crontab']
    for pat in ('/var/spool/cron/crontabs/*', '/var/spool/cron/*'):
        always += glob.glob(pat)
    for f in always:
        _scan_cron_file(f, hits)
    for pat in ('/etc/cron.d/*', '/etc/cron.hourly/*', '/etc/cron.daily/*',
                '/etc/cron.weekly/*', '/etc/cron.monthly/*'):
        for f in glob.glob(pat):
            if pkg_owner(f):
                continue
            _scan_cron_file(f, hits)
    return hits


def _scan_systemd():
    hits = []
    for d in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system'):
        for u in glob.glob(os.path.join(d, '*.service')):
            m = re.search(r'ExecStart=.*', _read_file(u, 20000))
            exe = m.group(0) if m else ''
            if exe and (PERSIST_SUSP.search(exe) or re.search(r'/(tmp|dev/shm|var/tmp)/', exe)):
                hits.append({'file': u, 'exec': exe[:160], 'sha256': _sha_line(exe)})
    return hits


def _scan_ssh_keys():
    out = []
    files = ['/root/.ssh/authorized_keys', '/root/.ssh/authorized_keys2']
    files += glob.glob('/home/*/.ssh/authorized_keys') + glob.glob('/home/*/.ssh/authorized_keys2')
    for f in files:
        try:
            st = os.stat(f)
        except OSError:
            continue
        entries = []
        for line in _iter_lines(f, 5000):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            comment = parts[-1] if len(parts) >= 3 else ''
            entries.append({'sha256': _sha_line(line), 'comment': comment[:60],
                            'options_flag': bool(re.search(r'command=|no-pty|from="?\*', line))})
        out.append({'file': f, 'mtime': datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc).isoformat(),
                    'world_writable': bool(st.st_mode & 0o002), 'keys': len(entries), 'entries': entries})
    return out


def _scan_http_log(max_lines=300000, max_hits=300):
    logs = []
    for pat in ('/var/log/nginx/*access*', '/var/log/apache2/*access*', '/var/log/httpd/*access*',
                '/var/log/httpd/*access_log*', '/var/log/*access.log*'):
        logs += glob.glob(pat)
    logs = sorted(set(logs))
    matches, counts, seen, n = [], Counter(), set(), 0
    for p in logs:
        for line in _iter_lines(p, max_lines):
            n += 1
            for name, rx in HTTP_SUSP:
                if rx.search(line):
                    counts[name] += 1
                    h = _sha_line(line)
                    if (name, h) not in seen and len(matches) < max_hits:
                        seen.add((name, h))
                        matches.append({'log': p, 'pattern': name, 'line_sha256': h})
                    break
    return {'logs_scanned': logs, 'lines': n, 'counts': dict(counts), 'matches': matches}


def _scan_auth_log(max_lines=300000):
    logs = sorted(set(glob.glob('/var/log/auth.log*') + glob.glob('/var/log/secure*')))
    c = Counter()
    for p in logs:
        for line in _iter_lines(p, max_lines):
            if AUTH_FAILED.search(line):
                c['failed'] += 1
            elif AUTH_ACCEPT.search(line):
                c['accepted'] += 1
            if AUTH_SUDO.search(line):
                c['sudo'] += 1
            if AUTH_USERADD.search(line):
                c['useradd'] += 1
    flags = []
    if c['failed'] >= 200:
        flags.append('Banyak gagal login (%d) -> kemungkinan brute-force SSH.' % c['failed'])
    if c['useradd']:
        flags.append('Ada penambahan user/group (%d) -> verifikasi keabsahannya.' % c['useradd'])
    return {'logs_scanned': logs, 'counts': dict(c), 'flags': flags}


def _scan_pkg_integrity():
    res = {'enabled': True, 'tool': None, 'modified': [], 'count': 0}
    if shutil.which('dpkg'):
        res['tool'] = 'dpkg --verify'
        _, out, _ = run(['dpkg', '--verify'], timeout=300)
        for line in out.splitlines():
            p = line.split(None, 2)
            if p and len(p[0]) >= 3 and '5' in p[0]:
                res['modified'].append(p[-1])
    elif shutil.which('rpm'):
        res['tool'] = 'rpm -Va'
        _, out, _ = run(['rpm', '-Va'], timeout=600)
        for line in out.splitlines():
            if line[:9] and '5' in line[:9]:
                res['modified'].append(line.split()[-1])
    res['count'] = len(res['modified'])
    res['modified'] = res['modified'][:200]
    return res


def compromise_scan(args):
    """Kumpulkan tanda-tanda kompromi. Semua best-effort & gagal-aman (butuh root penuh)."""
    comp = {'persistence': {'cron': _scan_cron(), 'systemd': _scan_systemd(),
                            'ssh_authorized_keys': _scan_ssh_keys()},
            'http_log': _scan_http_log(), 'auth_log': _scan_auth_log(),
            'package_integrity': _scan_pkg_integrity() if getattr(args, 'verify_packages', False) else {'enabled': False}}
    ind = []
    for c in comp['persistence']['cron']:
        ind.append({'severity': 'high', 'type': 'cron_suspicious', 'detail': '%s:%d %s' % (c['file'], c['line'], c['snippet'][:80])})
    for s in comp['persistence']['systemd']:
        ind.append({'severity': 'high', 'type': 'systemd_suspicious', 'detail': s['file']})
    for k in comp['persistence']['ssh_authorized_keys']:
        if k['world_writable']:
            ind.append({'severity': 'high', 'type': 'ssh_keys_world_writable', 'detail': k['file']})
        for e in k['entries']:
            if e['options_flag']:
                ind.append({'severity': 'medium', 'type': 'ssh_key_forced_option', 'detail': '%s (%s)' % (k['file'], e['comment'])})
    hc = comp['http_log']['counts']
    if hc.get('webshell_access'):
        ind.append({'severity': 'high', 'type': 'http_webshell_access', 'detail': '%d permintaan mirip akses webshell' % hc['webshell_access']})
    for name in ('sqli', 'traversal', 'rce_probe', 'scanner_ua'):
        if hc.get(name):
            ind.append({'severity': 'medium', 'type': 'http_' + name, 'detail': '%d permintaan pola %s' % (hc[name], name)})
    for fl in comp['auth_log']['flags']:
        ind.append({'severity': 'medium', 'type': 'auth_anomaly', 'detail': fl})
    if comp['package_integrity'].get('count'):
        ind.append({'severity': 'medium', 'type': 'package_integrity',
                    'detail': '%d file paket berubah (%s)' % (comp['package_integrity']['count'], comp['package_integrity'].get('tool'))})
    comp['indicators'] = ind
    comp['counts'] = {'high': sum(1 for i in ind if i['severity'] == 'high'),
                      'medium': sum(1 for i in ind if i['severity'] == 'medium')}
    return comp


def _fpm_listeners():
    seen, out = set(), []
    for pat in POOL_GLOBS:
        for f in glob.glob(pat):
            for line in _iter_lines(f, 3000):
                m = re.match(r'\s*listen\s*=\s*(\S+)', line)
                if m and not line.lstrip().startswith(';') and m.group(1) not in seen:
                    seen.add(m.group(1))
                    out.append(m.group(1))
    return out


def _probe_listen(target, timeout=3):
    """True bila socket/port FPM menerima koneksi (liveness, bukan sekadar unit 'active')."""
    try:
        if target.startswith('/'):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(target)
            s.close()
            return True
        if ':' in target:
            host, port = target.rsplit(':', 1)
            host = host.strip('[]') or '127.0.0.1'
        else:
            host, port = '127.0.0.1', target
        socket.create_connection((host, int(port)), timeout).close()
        return True
    except (OSError, ValueError):
        return False


def _http_status(port=80, timeout=3):
    """Kode status dari HEAD http://127.0.0.1:<port>/ (loopback). None bila tak terhubung."""
    try:
        s = socket.create_connection(('127.0.0.1', port), timeout)
        s.sendall(b'HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
        data = s.recv(64)
        s.close()
        m = re.match(rb'HTTP/\d\.\d\s+(\d{3})', data)
        return int(m.group(1)) if m else None
    except OSError:
        return None


def _health_status(pools, http80, https_open):
    if any(not p['reachable'] for p in pools):
        return 'DEGRADED', True
    if http80 is not None and http80 >= 500:
        return 'DEGRADED', True
    web_serving = (http80 is not None and http80 < 500) or https_open
    if web_serving:
        return 'OK', False
    if pools:
        return 'UNVERIFIED', False
    return 'UNKNOWN', False


def health_check(args):
    """Health check LOKAL & minimal (loopback, tanpa koneksi keluar): liveness socket
    FPM + status HTTP 127.0.0.1. Untuk mendeteksi 'service active tapi situs mati'
    setelah restart/fix. Bukan pengganti monitoring."""
    pools = [{'listen': t, 'reachable': _probe_listen(t)} for t in _fpm_listeners()]
    http80 = _http_status(80)
    https_open = _probe_listen('443')
    status, degraded = _health_status(pools, http80, https_open)
    return {'checked_at': utcnow().isoformat(), 'fpm_pools': pools,
            'http_127_0_0_1_80': http80, 'https_127_0_0_1_443_open': https_open,
            'status': status, 'degraded': degraded}


def _synthetic_report():
    old = (utcnow() - datetime.timedelta(days=45)).isoformat()
    rep = {
        'host': 'h1', 'os': {'pretty': 'Debian 12'}, 'euid': 0,
        'scanned_at': utcnow().isoformat(), 'host_verdict': 'VULNERABLE',
        'mitigation_status': 'MISSING',
        'installations': [
            {'kind': 'fpm', 'binary': '/usr/sbin/php-fpm8.2', 'version_raw': '8.2.20', 'branch': '8.2',
             'eol_date': '', 'upstream_status': 'below_fixed', 'fixed_in': '8.2.35', 'vendor_backport': 'none',
             'verdict': 'VULNERABLE', 'active_risk': True, 'running': {'processes': 4, 'stale': 1},
             'package': {'name': 'php8.2-fpm', 'version': '8.2.20-1'}, 'panel': None,
             'info': {'upload_progress': 'On'}, 'cve_unpatched': [{'cve': 'CVE-2026-0001', 'fixed_in': '8.2.26'}]},
            {'kind': 'cli', 'binary': '/usr/bin/php8.1', 'version_raw': '8.1.10', 'branch': '8.1',
             'eol_date': '2025-12-31', 'upstream_status': 'eol', 'fixed_in': None, 'vendor_backport': 'none',
             'verdict': 'EOL_UNSUPPORTED', 'active_risk': False, 'running': {'processes': 0, 'stale': 0},
             'package': None, 'panel': None, 'info': {}, 'cve_unpatched': []},
        ],
        'containers': [], 'stale_processes_unmatched': [], 'fpm_pool_overrides_enabling_upload_progress': [],
        'web_apps': [{'category': 'cms', 'app': 'WordPress', 'version': '5.8.1', 'status': 'OUTDATED',
                      'min_safe': '6.0', 'suggestion': 'upgrade', 'path': '/var/www'}],
        'compromise': {'counts': {'high': 1, 'medium': 1},
                       'indicators': [{'severity': 'high', 'type': 'cron_suspicious', 'detail': 'x'},
                                      {'severity': 'medium', 'type': 'auth_anomaly', 'detail': 'y'}],
                       'package_integrity': {'enabled': False}},
        'cvedb': {'present': True, 'count': 260, 'source': 'php.net ChangeLog',
                  'generated_at': old, 'age_days': 45, 'stale': True},
        'ioc': {'counts': {'high': 1, 'medium': 0, 'low': 0}, 'php_files_inspected': 10, 'truncated': False,
                'findings': [{'severity': 'high', 'type': 'webshell_pattern', 'path': '/x.php'}]},
        'vulnerability_status': 'VULNERABLE', 'compromise_status': 'HIGH_RISK_INDICATORS',
        'health': {'status': 'OK', 'fpm_pools': [{'listen': '/run/php/x.sock', 'reachable': True}],
                   'http_127_0_0_1_80': 200, 'https_127_0_0_1_443_open': True, 'degraded': False},
    }
    rep['next_steps'] = next_steps(rep)
    return rep


def selftest():
    fails = []

    def ck(cond, label):
        if not cond:
            fails.append(label)

    ck(vtuple('8.2.35') == (8, 2, 35), 'vtuple')
    ck(vstr((8, 2, 35)) == '8.2.35', 'vstr')
    ck(upstream_status((8, 2, 20)) == ('below_fixed', '8.2.35'), 'upstream below_fixed')
    ck(upstream_status((8, 2, 35)) == ('fixed', '8.2.35'), 'upstream fixed')
    ck(upstream_status((8, 1, 10))[0] == 'eol' and eol_date((8, 1, 10)) == '2025-12-31', 'eol 8.1')
    ck(upstream_status((7, 4, 33))[0] == 'eol', 'eol 7.4')
    ck(upstream_status((8, 6, 0))[0] == 'unknown_branch', 'unknown branch')

    i1 = assess({'upstream_status': 'eol', 'vendor_backport': 'none', 'realpath': '/a', 'binary': '/a'},
                [{'path': '/a', 'processes': 2, 'stale': 0, 'oldest_start': 1}])
    ck(i1['verdict'] == 'EOL_UNSUPPORTED' and i1['active_risk'], 'assess eol+active')
    i2 = assess({'upstream_status': 'fixed', 'vendor_backport': 'none', 'realpath': '/b', 'binary': '/b'},
                [{'path': '/b', 'processes': 1, 'stale': 0, 'oldest_start': 1}])
    ck(i2['verdict'] == 'PATCHED' and not i2['active_risk'], 'assess patched')
    bp = {'upstream_status': 'below_fixed', 'vendor_backport': 'confirmed', 'realpath': '/c', 'binary': '/c'}
    ck(assess(dict(bp), [])['verdict'] == 'PATCHED_BACKPORT', 'backport default -> PATCHED_BACKPORT')
    ck(assess(dict(bp), [], strict_backport=True)['verdict'] == 'UNVERIFIED', 'backport strict -> UNVERIFIED')

    db = {'branches': {'8.1': [{'cve': 'CVE-X', 'fixed_in': '8.1.28'}, {'cve': 'CVE-Y', 'fixed_in': '8.1.5'}]}}
    ck([c['cve'] for c in cves_for_version((8, 1, 10), db)] == ['CVE-X'], 'cves_for_version filter+sort')
    rep_b = {'installations': [{'version_raw': '8.1.10', 'verdict': 'PATCHED', 'running': {'processes': 2}}], 'containers': []}
    enrich_cves(rep_b, {'generated_at': utcnow().isoformat(), 'branches': db['branches']})
    ck(rep_b['installations'][0]['verdict'] == 'VULNERABLE', 'enrich bumps PATCHED->VULNERABLE')

    br = parse_changelog('Version 8.2.5 fixed CVE-2024-1111 blah Version 8.2.3 CVE-2024-2222')
    ck(bool(br.get('8.2')) and any(e['cve'] == 'CVE-2024-1111' for e in br['8.2']), 'parse_changelog')
    ck(_ver_tuple('6.4.1') == (6, 4, 1) and _ver_tuple('') is None, '_ver_tuple')
    ck(_app_status('WordPress', '5.8.1', 'cms')[0] == 'OUTDATED', 'app OUTDATED')
    ck(_app_status('WordPress', '6.5', 'cms')[0] == 'OK', 'app OK')
    ck(_app_status('Drupal', '7.98', 'cms')[0] == 'EOL', 'app EOL')
    ck(dict((p,l) for p,l in NPM_PKGS).get('bootstrap') == 'Bootstrap', 'NPM Bootstrap terdaftar')
    import tempfile
    td = tempfile.mkdtemp()
    try:
        def mk(rel, txt):
            f = os.path.join(td, rel)
            os.makedirs(os.path.dirname(f), exist_ok=True)
            with open(f, 'w') as fh:
                fh.write(txt)
        mk('wp/wp-includes/version.php', "<?php $wp_version = '6.5';")
        mk('wp/wp-content/plugins/akismet/akismet.php', "<?php\n/*\nPlugin Name: Akismet Anti-spam\nVersion: 5.3.1\n*/")
        mk('wp/wp-content/plugins/hello.php', "<?php\n/**\n * Plugin Name: Hello Dolly\n * Version: 1.7.2\n */")
        mk('wp/wp-content/plugins/index.php', "<?php // Silence is golden.")
        mk('wp/wp-content/themes/twentyone/style.css', "/*\nTheme Name: Twenty Twenty-One\nVersion: 2.1\n*/")
        mk('d7/includes/bootstrap.inc', "<?php define('VERSION', '7.98');")
        mk('d7/modules/node/node.info', 'name = Node\nversion = "7.98"')
        mk('d7/sites/all/modules/views/views.info', 'name = Views\nversion = "7.x-3.29"')
        mk('d10/core/lib/Drupal.php', "<?php class Drupal { const VERSION = '10.2.0'; }")
        mk('d10/modules/contrib/token/token.info.yml', "name: Token\ntype: module\nversion: '8.x-1.13'")
        mk('jm/administrator/manifests/files/joomla.xml', '<extension><version>5.1.0</version></extension>')
        mk('jm/plugins/system/foo/foo.xml', '<extension type="plugin"><name>plg_system_foo</name><version>2.0.1</version></extension>')
        f, seen = [], set()
        for sub in ('wp', 'd7', 'd10', 'jm'):
            _detect_in_dir(os.path.join(td, sub), f, seen)
        ex = dict((a['app'] + a['version'], dict((e['slug'], e['version']) for e in a.get('extensions', []))) for a in f)
        ck(ex.get('WordPress6.5') == {'akismet': '5.3.1', 'hello': '1.7.2', 'twentyone': '2.1'}, 'inventaris plugin/tema WP')
        ck(ex.get('Drupal7.98') == {'views': '7.x-3.29'}, 'inventaris Drupal 7 tanpa modul core')
        ck(ex.get('Drupal10.2.0') == {'token': '8.x-1.13'}, 'inventaris Drupal 10 contrib')
        ck(ex.get('Joomla5.1.0') == {'foo': '2.0.1'}, 'inventaris plugin Joomla')
    finally:
        shutil.rmtree(td, ignore_errors=True)
    ck(cve_age_days((utcnow() - datetime.timedelta(days=45)).isoformat()) == 45, 'cve_age_days 45')
    ck(cve_age_days('2020-01-01T00:00:00') is not None and cve_age_days('bukan-tanggal') is None, 'cve_age_days 3.6-safe')

    class _A:
        force_with_findings = False
    ck(high_gate({'ioc': None, 'compromise': {'counts': {'high': 1}}}, _A()) is not None, 'high_gate blokir kompromi HIGH')
    ck(high_gate({'ioc': {'counts': {'high': 1}}, 'compromise': None}, _A()) is not None, 'high_gate blokir IOC HIGH')
    ck(high_gate({'ioc': None, 'compromise': {'counts': {'high': 0}}}, _A()) is None, 'high_gate lolos saat bersih')
    ck(_compromise_status({'compromise': {'counts': {'high': 1}}, 'ioc': None}) == 'HIGH_RISK_INDICATORS', 'compromise_status high')
    ck(_compromise_status({'compromise': {'counts': {'medium': 2}}, 'ioc': None}) == 'SUSPICIOUS', 'compromise_status med')
    ck(_compromise_status({'compromise': {'counts': {}}, 'ioc': {'counts': {}}}) == 'NO_INDICATORS', 'compromise_status clean')
    ck(_compromise_status({'compromise': None, 'ioc': None}) == 'NOT_CHECKED', 'compromise_status not checked')

    ck(_health_status([{'reachable': True}], 200, True)[0] == 'OK', 'health OK')
    ck(_health_status([{'reachable': False}], 200, True)[0] == 'DEGRADED', 'health FPM down')
    ck(_health_status([{'reachable': True}], 502, True)[0] == 'DEGRADED', 'health http 5xx')
    ck(_health_status([], None, False)[0] == 'UNKNOWN', 'health no signal')
    ck(_health_status([{'reachable': True}], None, False)[0] == 'UNVERIFIED', 'health FPM up tapi HTTP tak terverifikasi')

    ck(bool(SUSP_HIGH.search(b'<?php @eval(base64_decode($_POST["x"])); ?>')), 'webshell eval(base64_decode($_POST)) HIGH')
    ck(bool(SUSP_HIGH.search(b'assert(gzinflate(base64_decode($_REQUEST[1])))')), 'webshell decoder bertingkat HIGH')
    ck(not SUSP_HIGH.search(b'eval(base64_decode("aGVsbG8="))') and bool(SUSP_MED.search(b'eval(base64_decode("aGVsbG8="))')),
       'eval(base64_decode(literal)) tetap MEDIUM')
    ck(bool(PERSIST_SUSP.search('curl http://x|bash')) and not PERSIST_SUSP.search('/usr/bin/backup.sh'), 'persist regex')
    ck(bool(dict(HTTP_SUSP)['webshell_access'].search('/s.php?cmd=id')), 'http webshell regex')
    ck(bool(AUTH_FAILED.search('Failed password for root')), 'auth regex')

    rep = _synthetic_report()
    out = summary(rep)
    for token in ('STATUS HOST :', 'kompromi       : HIGH_RISK_INDICATORS', 'kesehatan web  : OK',
                  'RENTAN & AKTIF', 'EOL 2025-12-31', 'CVE belum ter-patch', 'Framework/CMS terdeteksi',
                  'KOMPROMI:', 'DB CVE:', 'LAWAS', 'Indikator: HIGH'):
        ck(token in out, 'summary berisi %r' % token)
    steps = ' || '.join(rep['next_steps'])
    for token in ('PRIORITAS', 'TANDA KOMPROMI (HIGH)', 'Branch EOL', 'DB CVE sudah lawas', 'Pasang mitigasi'):
        ck(token in steps, 'next_steps berisi %r' % token)
    ck(exit_code(rep) == 2, 'exit_code 2 saat IOC high')
    ck(exit_code({'ioc': None, 'compromise': None, 'host_verdict': 'PATCHED',
                  'mitigation_status': 'OK'}) == 0, 'exit_code 0 saat aman')
    ck(exit_code({'ioc': None, 'compromise': None, 'host_verdict': 'PATCHED', 'mitigation_status': 'OK',
                  'web_apps': [{'app': 'Drupal', 'version': '7.98', 'status': 'EOL'}]}) == 1, 'exit_code 1 saat CMS EOL')
    ck(exit_code({'ioc': None, 'compromise': None, 'host_verdict': 'PATCHED', 'mitigation_status': 'OK',
                  'web_apps': [{'app': 'WordPress', 'version': '6.5', 'status': 'OK'}]}) == 0, 'exit_code 0 saat CMS OK')
    ck('Framework/CMS EOL/OUTDATED' in steps, 'next_steps sebut CMS OUTDATED')
    ck('wp plugin list --update=available' in steps, 'next_steps sarankan cek plugin WordPress')

    if fails:
        sys.stderr.write('SELFTEST GAGAL (%d):\n  - %s\n' % (len(fails), '\n  - '.join(fails)))
        return 1
    print('selftest OK')
    return 0


def build_parser():
    ap = argparse.ArgumentParser(description='php_guard - audit kerentanan PHP per server (lihat README.md)')
    ap.add_argument('--version', action='version', version='php_guard ' + VERSION)
    sub = ap.add_subparsers(dest='mode')

    def common(p):
        p.add_argument('--since', default=DEFAULT_SINCE, help='tandai file PHP yang berubah sejak tanggal ini (YYYY-MM-DD)')
        p.add_argument('--max-files', type=int, default=60000, help='batas file PHP yang diperiksa')
        p.add_argument('--no-ioc', action='store_true', help='lewati triage indikator kompromi')
        p.add_argument('--no-containers', action='store_true', help='lewati cek container docker/podman')
        p.add_argument('--restart', action='store_true', help='restart php-fpm/apache/lsws setelah fix/mitigate')
        p.add_argument('--force-with-findings', action='store_true', help='izinkan fix walau ada indikator HIGH')
        p.add_argument('--include-panels', action='store_true', help='ikut upgrade paket ea-php*/alt-php* (cPanel/CloudLinux)')
        p.add_argument('--cvedb', help='file JSON CVE (hasil cve-update); default php_guard_cve.json di folder skrip')
        p.add_argument('--webroot', action='append', default=[], help='direktori web root untuk deteksi framework/CMS (boleh diulang)')
        p.add_argument('--no-webapps', action='store_true', help='lewati deteksi framework/CMS')
        p.add_argument('--strict-backport', action='store_true', help='backport yang hanya dikonfirmasi changelog dianggap UNVERIFIED (audit keyakinan tinggi)')
        p.add_argument('--no-compromise', action='store_true', help='lewati pemeriksaan tanda kompromi (persistence/log)')
        p.add_argument('--no-health', action='store_true', help='lewati health check lokal (liveness FPM + http loopback)')
        p.add_argument('--allow-stale-metadata', action='store_true', help='lanjutkan fix walau refresh repo (apt/apk update) gagal (pakai cache)')
        p.add_argument('--verify-packages', action='store_true', help='jalankan dpkg --verify / rpm -Va (lambat) untuk integritas paket')

    for name, hlp in (('scan', 'audit read-only (default)'), ('mitigate', 'pasang session.upload_progress.enabled=0'),
                      ('fix', 'upgrade paket PHP'), ('restart', 'restart layanan PHP/web')):
        p = sub.add_parser(name, help=hlp)
        common(p)
        p.add_argument('--out', help='path laporan JSON')
        p.add_argument('--quiet', action='store_true')

    cu = sub.add_parser('cve-update', help='[mesin operator/online] tarik CVE dari php.net ChangeLog -> php_guard_cve.json')
    cu.add_argument('-o', '--out', help='file keluaran (default: php_guard_cve.json)')
    cu.add_argument('--source', action='append', default=[], help='URL ChangeLog alternatif (boleh diulang)')
    cu.add_argument('--if-older-than', type=int, metavar='HARI', help='lewati bila file keluaran masih lebih baru dari HARI (untuk cron)')

    sub.add_parser('selftest', help='uji mandiri fungsi inti (lintas-OS, tanpa menyentuh sistem)')

    return ap


def main():
    ap = build_parser()
    argv = sys.argv[1:] or ['scan']
    args = ap.parse_args(argv)
    if sys.version_info < (3, 6):
        sys.exit('Butuh Python 3.6+')
    try:
        datetime.datetime.strptime(getattr(args, 'since', DEFAULT_SINCE), '%Y-%m-%d')
    except ValueError:
        sys.exit('--since harus format YYYY-MM-DD')
    if args.mode == 'selftest':
        return selftest()
    if args.mode == 'cve-update':
        return do_cve_update(args)
    args.cmd = args.mode or 'scan'
    if not sys.platform.startswith('linux'):
        sys.exit('Hanya untuk Linux.')
    return local_main(args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
