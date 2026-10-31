-- Helper macros available to every rule (loaded before the hunt).
CREATE OR REPLACE MACRO lc(x) AS lower(coalesce(CAST(x AS VARCHAR), ''));
CREATE OR REPLACE MACRO bn(p) AS lower(regexp_extract(coalesce(p, ''), '[^\\/]+$'));
CREATE OR REPLACE MACRO is_internal(ip) AS (coalesce(ip, '') LIKE '10.%' OR coalesce(ip, '') LIKE '192.168.%'
    OR regexp_matches(coalesce(ip, ''), '^172\.(1[6-9]|2[0-9]|3[01])\.') OR coalesce(ip, '') LIKE 'fe80:%'
    OR coalesce(ip, '') LIKE '127.%' OR coalesce(ip, '') LIKE 'fd%:%');
CREATE OR REPLACE MACRO is_external(ip) AS (ip IS NOT NULL AND regexp_matches(ip, '^[0-9a-fA-F:.]+$')
    AND NOT is_internal(ip));
CREATE OR REPLACE MACRO is_proc(et) AS et IN ('sysmon:1', 'win:4688', 'audit:execve');
CREATE OR REPLACE MACRO is_logon_ok(et) AS et IN ('win:4624', 'auth:success');
CREATE OR REPLACE MACRO is_logon_fail(et) AS et IN ('win:4625', 'auth:fail', 'auth:invalid_user', 'win:4771', 'win:4776f');
CREATE OR REPLACE MACRO sys_acct(u) AS (u IS NULL OR u IN ('system', 'local service', 'network service',
    'anonymous logon', 'anonymous', '-', 'localsystem', 'nobody', 'trustedinstaller') OR u LIKE '%$'
    OR u LIKE 'dwm-%' OR u LIKE 'umfd-%');
CREATE OR REPLACE MACRO web_acct(u) AS u IN ('www-data', 'apache', 'nginx', 'httpd', 'wwwrun', 'iusr',
    'defaultapppool', 'tomcat', 'www');
CREATE OR REPLACE MACRO shell_bin(b) AS b IN ('sh', 'bash', 'dash', 'zsh', 'ksh', 'csh', 'tcsh', 'busybox',
    'nc', 'ncat', 'netcat', 'socat', 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'pwsh');
CREATE OR REPLACE MACRO script_host(b) AS b IN ('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe',
    'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'msbuild.exe',
    'installutil.exe', 'wmic.exe', 'hh.exe');
CREATE OR REPLACE MACRO host_of(q_ip, q_ts) AS (SELECT s.host FROM ip_segments s WHERE s.ip = q_ip
    AND ((q_ts >= s.valid_from AND q_ts < s.valid_to) OR (s.seg_no = 1 AND q_ts < s.valid_from)) LIMIT 1);
CREATE OR REPLACE MACRO role_of(q_h) AS (SELECT r.role FROM hosts r WHERE r.host = q_h LIMIT 1);
