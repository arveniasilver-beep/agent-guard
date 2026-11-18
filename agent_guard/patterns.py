"""Tehlikeli komut desenleri.

DANGEROUS_PATTERNS listesi ve yardimci yol sabitleri Nous Research'un
Hermes Agent projesinden (MIT lisansli) uyarlanmistir.
Atif icin THIRD_PARTY_NOTICES.md dosyasina bakin.

Uyarlama notlari:
  - Hermes'in kendi sureclerini koruyan desenler DeerFlow surec adlarina cevrildi.
  - Yapilandirma yolu hem '.deerflow' hem '.deer-flow' yazimini kabul eder.

KAPSAM UYARISI: Bu surum yalnizca desen eslestirmesi yapar. Hermes'in
obfuskasyon normalizasyonu (base64 cozme, degisken genisletme, alinti hileleri)
henuz tasinmadi; kasitli gizleme girisimleri bu kapiyi atlatabilir. Amac,
modelin kazara yaptigi yikici islemleri durdurmaktir.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Yol ve sinir sabitleri (Hermes'ten uyarlandi)
# ---------------------------------------------------------------------------

_COMMAND_TAIL = r'(?:\s*(?:&&|\|\||;).*)?$'

_MACOS_PRIVATE_SYSTEM_PATH = r'/private/(?:etc|var|tmp|home)/'

_AGENT_ENV_PATH = (
    r'(?:~\/\.deer-?flow/|'
    r'(?:\$home|\$\{home\})/\.deer-?flow/|'
    r'(?:\$deerflow_home|\$\{deerflow_home\})/)'
    r'\.env\b'
)

_WRITE_TARGET_BOUNDARY = r'(?=[\s;&|<>"\']|$)'

_AGENT_CONFIG_PATH = (
    r'(?:~\/\.deer-?flow/|'
    r'(?:\$home|\$\{home\})/\.deer-?flow/|'
    r'(?:\$deerflow_home|\$\{deerflow_home\})/)'
    r'config\.yaml\b'
)

_SSH_SENSITIVE_PATH = r'(?:~|\$home|\$\{home\})/\.ssh(?:/|$)'

_PROJECT_ENV_PATH = r'(?:(?:/|\.{1,2}/)?(?:[^\s/"\'`]+/)*\.env(?:\.[^/\s"\'`]+)*)'

_CREDENTIAL_FILES = (
    r'(?:~|\$home|\$\{home\})/\.'
    r'(?:netrc|pgpass|npmrc|pypirc)\b'
)

_SHELL_RC_FILES = (
    r'(?:~|\$home|\$\{home\})/\.'
    r'(?:bashrc|zshrc|profile|bash_profile|zprofile)\b'
)

_PROJECT_CONFIG_PATH = r'(?:(?:/|\.{1,2}/)?(?:[^\s/"\'`]+/)*config\.yaml)'

_SYSTEM_CONFIG_PATH = (
    rf'(?:/etc/|{_MACOS_PRIVATE_SYSTEM_PATH})'
)

_USER_SENSITIVE_WRITE_TARGET = (
    rf'(?:{_SSH_SENSITIVE_PATH}|'
    rf'{_SHELL_RC_FILES}|'
    rf'{_CREDENTIAL_FILES})'
)

_SENSITIVE_WRITE_TARGET = (
    rf'(?:{_SYSTEM_CONFIG_PATH}|/dev/sd|'
    rf'{_SSH_SENSITIVE_PATH}|'
    rf'{_AGENT_ENV_PATH}|'
    rf'{_AGENT_CONFIG_PATH}|'
    rf'{_SHELL_RC_FILES}|'
    rf'{_CREDENTIAL_FILES})'
)

_PROJECT_SENSITIVE_WRITE_TARGET = rf'(?:{_PROJECT_ENV_PATH}|{_PROJECT_CONFIG_PATH})'

# ---------------------------------------------------------------------------
# Tehlikeli komut desenleri
# ---------------------------------------------------------------------------

DANGEROUS_PATTERNS = [
    (r'\brm\s+(-[^\s]*\s+)*/', "delete in root path"),
    (r'\brm\s+-[^\s]*r', "recursive delete"),
    (r'\brm\s+--recursive\b', "recursive delete (long flag)"),
    # GNU rm permutes options, so a recursive flag group may legally FOLLOW
    # the operands: `rm build/ -rf`, `rm build/ -r -f`, and `rm build/
    # --recursive --force` are all equivalent to the flags-first spellings the
    # two patterns above catch — without this rule they run with no approval
    # prompt at all. The operand run is tempered: it cannot cross a command
    # separator (`;`, `|`, `&`, newline — so a later pipeline segment's flags,
    # e.g. `rm foo | grep -r bar`, are not attributed to `rm`), cannot cross a
    # quote (so `git commit -m "rm x" --amend` style data can't bridge an `rm`
    # word to an unrelated dash token), and cannot cross a bare ` -- `
    # end-of-options separator (after `--`, POSIX rm treats `-rf` as a literal
    # filename, not flags; guarded both leading and mid-run). The flag token
    # itself must start right after whitespace so the `r` inside long options
    # like `--registry` (preceded by `-`, not whitespace) does not count.
    # Port of openai/codex#33464 ("recognize force options when they follow
    # operands").
    (r'\brm\s+(?!--(?:\s|$))(?:(?!\s--(?:\s|$))[^\n"\';|&])*\s'
     r'(?:-[a-z]*r[a-z]*\b|--recursive\b)',
     "recursive delete (flags after operands)"),
    # Windows shell front-ends have destructive built-ins that do not look like
    # Unix `rm`. Gate only when they are executed through cmd/powershell so
    # ordinary prose or filenames containing "del"/"rd" do not trip the guard.
    (r'\bcmd(?:\.exe)?\s+/(?:c|k)\s+.*\b(?:del|erase|rd|rmdir)\b', "Windows cmd destructive delete"),
    # PowerShell/pwsh: the destructive verb runs as the default positional
    # argument, so `powershell Remove-Item ...` needs NO explicit -Command.
    # Anchor the verb to the command position (right after the shell name,
    # after any leading `-Flag` switches, and optionally after -Command/-c)
    # so bare invocations are caught while a benign path arg containing
    # "del"/"rm" (e.g. `-File c:\del-logs\run.ps1`) is not.
    (r'\b(?:powershell|pwsh)(?:\.exe)?\b(?:\s+-\S+)*\s+(?:-(?:command|c)\s+)?["\']?(?:remove-item|rmdir|erase|del|rd|ri|rm)\b', "Windows PowerShell destructive delete"),
    (r'\b(?:powershell|pwsh)(?:\.exe)?\b.*\s-(?:encodedcommand|enc|e)\b', "PowerShell encoded command execution"),
    # ── Windows destructive tier (#69472) ────────────────────────────────
    # These are native Windows EXEs / cmdlets reachable from ANY the agent
    # terminal backend on a Windows host — including the default git-bash
    # backend (taskkill.exe, icacls.exe, reg.exe, vssadmin.exe, bcdedit.exe,
    # cipher.exe are ordinary PATH executables there). Detection input is
    # lowercased by the variant loop, so patterns are written lowercase.
    # Each pattern requires the destructive flag/verb so benign usage
    # (`taskkill /IM app.exe` graceful kill, `reg query`, `icacls file`)
    # does NOT prompt.
    # Bare PowerShell destructive delete: Remove-Item/ri with -Recurse or
    # -Force. The cmd/powershell-prefixed forms are covered above; this
    # catches the bare form (ACP clients, pwsh-default SSH hosts, or
    # `powershell` invoked earlier in a compound command).
    (r'\bremove-item\b[^\n;|&]*\s-(?:recurse|force)\b', "PowerShell destructive delete (Remove-Item)"),
    # cmd builtins with destructive switches, bare form: del/erase/rd/rmdir
    # with /s (recurse) or /q (quiet). Requires the switch so `del file.txt`
    # inside a cmd /c string stays covered by the prefixed rule only.
    (r'\b(?:del|erase|rd|rmdir)\s+(?:/[a-z]\s+)*/[sq]\b', "Windows destructive delete (recursive/quiet switch)"),
    # Remote content piped to Invoke-Expression — PowerShell's `curl | sh`.
    (r'\b(?:iwr|invoke-webrequest|invoke-restmethod|irm|curl|wget)\b[^\n]*\|\s*(?:iex|invoke-expression)\b', "pipe remote content to PowerShell (iwr | iex)"),
    (r'\b(?:iex|invoke-expression)\s*\(\s*(?:iwr|invoke-webrequest|invoke-restmethod|irm)\b', "execute remote content via Invoke-Expression"),
    # Force process kills — Windows analogue of pkill -9.
    (r'\btaskkill\b[^\n]*\s/f\b', "force kill processes (taskkill /F)"),
    (r'\bstop-process\b[^\n]*\s-force\b', "force kill processes (Stop-Process -Force)"),
    # Volume/disk destruction — Windows analogue of mkfs / dd.
    (r'\bformat-volume\b', "format filesystem (Format-Volume)"),
    (r'\bclear-disk\b', "wipe disk (Clear-Disk)"),
    (r'\bdiskpart\b', "disk partitioning (diskpart)"),
    (r'\bformat(?:\.com)?\s+[a-z]:', "format drive (format.com)"),
    (r'\bcipher\s+/w\b', "wipe free space (cipher /w)"),
    # ACL destruction — Windows analogue of chmod 777.
    (r'\bicacls\b[^\n]*\s/grant\b[^\n]*\b(?:everyone|todos|jeder|tout\s+le\s+monde|\*s-1-1-0)\b', "grant Everyone access (icacls)"),
    (r'\bicacls\b[^\n]*\s/reset\b', "reset ACLs recursively (icacls /reset)"),
    # Backup/recovery destruction — classic ransomware prep, no benign
    # agent use case.
    (r'\bvssadmin\b[^\n]*\bdelete\s+shadows\b', "delete volume shadow copies (vssadmin)"),
    (r'\bwbadmin\b[^\n]*\bdelete\b', "delete backups (wbadmin)"),
    (r'\bbcdedit\b[^\n]*\s/set\b', "modify boot configuration (bcdedit /set)"),
    # Registry deletion with force flag.
    (r'\breg(?:\.exe)?\s+delete\b', "registry delete (reg delete)"),
    (r'\bremove-itemproperty\b[^\n]*\s-force\b', "registry value delete (Remove-ItemProperty -Force)"),
    # Windows service/system stop — analogue of systemctl stop.
    (r'\bstop-service\b[^\n]*\s-force\b', "force stop service (Stop-Service -Force)"),
    (r'\bsc(?:\.exe)?\s+(?:stop|delete)\b', "stop/delete service (sc)"),
    # Credential/key paths in Windows form — the POSIX ~/.ssh patterns never
    # match drive-letter or backslash spellings. Match both separators.
    (r'\busers[\\/][^\\/\s]+[\\/]\.ssh\b', "access to SSH keys (Windows path)"),
    (r'\bappdata[\\/](?:local|roaming)[\\/]deerflow[^\n]*\.env\b', "access to the agent secrets (Windows path)"),
    # ─────────────────────────────────────────────────────────────────────
    (r'\bchmod\s+(-[^\s]*\s+)*(777|666|o\+[rwx]*w|a\+[rwx]*w)\b', "world/other-writable permissions"),
    (r'\bchmod\s+--recursive\b.*(777|666|o\+[rwx]*w|a\+[rwx]*w)', "recursive world/other-writable (long flag)"),
    (r'\bchown\s+(-[^\s]*)?R\s+root', "recursive chown to root"),
    (r'\bchown\s+--recur[a-z]*\b.*root', "recursive chown to root (long flag)"),
    (r'\bmkfs\b', "format filesystem"),
    (r'\bdd\s+.*if=', "disk copy"),
    (r'>\s*/dev/sd', "write to block device"),
    (r'\bDROP\s+(TABLE|DATABASE)\b', "SQL DROP"),
    # Use [^\n]* instead of .* so DOTALL mode does not cause a WHERE clause on the
    # *next* line to satisfy the negative lookahead, silently allowing DELETE without WHERE.
    (r'\bDELETE\s+FROM\b(?![^\n]*\bWHERE\b)', "SQL DELETE without WHERE"),
    (r'\bTRUNCATE\s+(TABLE)?\s*\w', "SQL TRUNCATE"),
    (rf'>\s*{_SYSTEM_CONFIG_PATH}', "overwrite system config"),
    (r'\bsystemctl\s+(-[^\s]+\s+)*(stop|restart|disable|mask)\b', "stop/restart system service"),
    (r'\bkill\s+-9\s+-1\b', "kill all processes"),
    (r'\bpkill\s+-9\b', "force kill processes"),
    # killall with SIGKILL (parallel to pkill -9). Catches -9 / -KILL /
    # -s KILL / -SIGKILL forms, and also `killall -r <regex>` broad sweeps
    # that can wipe out unrelated processes by accident.
    # Inspired by Claude Code 2.1.113 expanded deny rules.
    (r'\bkillall\s+(-[^\s]*\s+)*-(9|KILL|SIGKILL)\b', "force kill processes (killall -KILL)"),
    (r'\bkillall\s+(-[^\s]*\s+)*-s\s+(KILL|SIGKILL|9)\b', "force kill processes (killall -s KILL)"),
    (r'\bkillall\s+(-[^\s]*\s+)*-r\b', "kill processes by regex (killall -r)"),
    (r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:', "fork bomb"),
    # Shell -c is parsed structurally by _execution_flag_findings(). A regex
    # that merely searched a dash-token for "c" also matched --norc,
    # --rcfile, and --restricted.
    (r'\b(curl|wget)\b.*\|\s*(?:[/\w]*/)?(?:ba)?sh(?:\s|$|-c)', "pipe remote content to shell"),
    (r'\b(bash|sh|zsh|ksh)\s+<\s*<?\s*\(\s*(curl|wget)\b', "execute remote script via process substitution"),
    # Remote content executed via command substitution: eval/source/. $(curl ...)
    # or `wget ...`. Equivalent to piping remote content to a shell.
    (r'(?:\beval\b|\bsource\b|\.)\s*(?:\$\(\s*|`\s*)(?:curl|wget)\b', "execute remote content via command substitution"),
    # Decode-and-execute: encoded/transformed content piped to a shell. Without
    # these, `echo <base64> | base64 -d | bash` silently runs `rm -rf /` or any
    # other command because the raw text carries no dangerous keywords.
    (r'\b(base64|base32|base16)\s+(?:-[dD]|--decode)\b.*\|\s*\b(bash|sh|zsh|ksh|dash)\b',
     "pipe decoded content to shell (possible command obfuscation)"),
    # xxd reverse hex dump to shell (xxd uses -r for decode, not -d).
    (r'\bxxd\s+-r\b.*\|\s*\b(bash|sh|zsh|ksh|dash)\b',
     "pipe xxd-decoded content to shell (possible command obfuscation)"),
    # Character transformation via tr piped to shell:
    # `echo 'eq -pe v/' | tr 'eqv' 'rmf' | bash` decodes to `rm -rf /`.
    (r'\becho\b[^|]*\|\s*\btr\b[^|]*\|\s*\b(bash|sh|zsh|ksh|dash)\b',
     "pipe tr-transformed output to shell (possible command obfuscation)"),
    # openssl decode piped to shell:
    # `echo <base64> | openssl base64 -d | bash` decodes arbitrary commands.
    (r'\bopenssl\b.*\b(?:base64|enc)\b[^|]*\s+-[dD]\b[^|]*\|\s*\b(bash|sh|zsh|ksh|dash)\b',
     "pipe openssl-decoded content to shell (possible command obfuscation)"),
    (rf'\btee\b.*["\']?{_SENSITIVE_WRITE_TARGET}', "overwrite system file via tee"),
    (rf'>>?\s*["\']?{_SENSITIVE_WRITE_TARGET}', "overwrite system file via redirection"),
    (rf'\btee\b.*["\']?{_PROJECT_SENSITIVE_WRITE_TARGET}["\']?{_WRITE_TARGET_BOUNDARY}', "overwrite project env/config via tee"),
    (rf'>>?\s*["\']?{_PROJECT_SENSITIVE_WRITE_TARGET}["\']?{_WRITE_TARGET_BOUNDARY}', "overwrite project env/config via redirection"),
    (r'\bxargs\s+.*\brm\b', "xargs with rm"),
    # find -exec rm / -execdir rm — the -execdir variant (same semantics,
    # runs in the directory of each match) was previously missed. Claude
    # Code 2.1.113 tightened their equivalent find rule to stop auto-
    # approving -exec / -delete flags.
    (r'\bfind\b.*-exec(?:dir)?\s+(/\S*/)?rm\b', "find -exec/-execdir rm"),
    (r'\bfind\b.*-delete\b', "find -delete"),
    # Gateway lifecycle protection: prevent the agent from killing its own
    # gateway process.  These commands trigger a gateway restart/stop that
    # terminates all running agents mid-work.  Allow global flags between
    # `deerflow` and `gateway` (e.g. `deerflow -p ade gateway restart`) so a
    # profile flag can't slip the agent past the guard.
    (r'\bdeerflow\s+(?:-{1,2}\S+(?:\s+\S+)?\s+)*gateway\s+(stop|restart)\b', "stop/restart deerflow gateway (kills running agents)"),
    (r'\bdeerflow\s+update\b', "deerflow update (restarts gateway, kills running agents)"),
    # Docker container lifecycle — any user with docker.sock mounted (a common
    # Docker Compose pattern) gives the agent the ability to restart/stop/kill
    # containers without approval.  These are agent-initiated lifecycle operations
    # that should always require user consent, just like `deerflow gateway restart`
    # already does for the gateway process.
    # Docker/Podman daemon redirect — global flags or env prefixes that point
    # the CLI at a DIFFERENT daemon, often a remote host over ssh/tcp.  A
    # command that looks local (`docker -H ssh://prod stop app`) silently
    # operates on remote infrastructure, so any docker/podman invocation
    # carrying a redirect requires approval regardless of subcommand.  The
    # redirect flag must appear in the global-flag position (before the
    # subcommand) and -H/--host/--context must carry a value, which keeps
    # `docker -h` (help) and subcommand flags like `docker run -h <hostname>`
    # out of the deny.  Listed BEFORE the lifecycle rules so a redirected
    # lifecycle command surfaces the more specific "remote daemon" reason.
    # Inspired by Claude Code 2.1.214, which added permission prompts for
    # docker/podman commands carrying daemon-redirect flags (--url,
    # --connection, --identity, remote mode).
    (r'\bdocker\s+(?:-{1,2}\S+(?:[=\s]\S+)?\s+)*(?:-h|--host)[=\s]+\S+',
     "docker with remote daemon redirect (-H/--host)"),
    (r'\bdocker\s+(?:-{1,2}\S+(?:[=\s]\S+)?\s+)*(?:-c|--context)[=\s]+\S+',
     "docker with daemon redirect (--context: alternate daemon)"),
    (r'\bdocker\s+context\s+use\b',
     "docker context use (switches default daemon for future commands)"),
    (r'\bpodman\s+(?:-{1,2}\S+(?:[=\s]\S+)?\s+)*(?:--url|--connection|--identity)[=\s]+\S+',
     "podman with remote daemon redirect (--url/--connection/--identity)"),
    (r'\bpodman\s+(?:-{1,2}\S+(?:[=\s]\S+)?\s+)*(?:-r\b|--remote\b)',
     "podman remote mode (-r/--remote: remote daemon)"),
    (r'\b(?:docker_host|docker_context|container_host|container_connection)=\S+',
     "docker/podman daemon redirect via environment (DOCKER_HOST/CONTAINER_HOST)"),
    # Allow global flags between `docker`/`compose` and the verb (e.g.
    # `docker compose -f prod.yml down`, `docker --log-level debug stop app`)
    # and the legacy hyphenated `docker-compose` binary, so a flag can't slip
    # a lifecycle command past the guard — same treatment as the `deerflow ...
    # gateway` pattern above.
    (r'\bdocker(?:-compose|\s+compose)\s+(?:-{1,2}\S+(?:[=\s]\S+)?\s+)*(restart|stop|kill|down)\b',
     "docker compose restart/stop/kill/down (container lifecycle)"),
    (r'\bdocker\s+(?:-{1,2}\S+(?:[=\s]\S+)?\s+)*(restart|stop|kill)\b',
     "docker restart/stop/kill (container lifecycle)"),
    # Gateway protection: never start gateway outside systemd management
    (r'gateway\s+run\b.*(&\s*$|&\s*;|\bdisown\b|\bsetsid\b)', "start gateway outside systemd (use 'systemctl --user restart deerflow-gateway')"),
    (r'\bnohup\b.*gateway\s+run\b', "start gateway outside systemd (use 'systemctl --user restart deerflow-gateway')"),
    # Self-termination protection: prevent agent from killing its own process
    (r'\b(pkill|killall)\b.*\b(deerflow|gateway|cli\.py)\b', "kill deerflow/gateway process (self-termination)"),
    # Self-termination via kill + command substitution (pgrep/pidof).
    # The name-based pattern above catches `pkill deerflow` but not
    # `kill -9 $(pgrep -f deerflow)` because the substitution is opaque
    # to regex at detection time. Catch the structural pattern instead.
    # `pidof` is the BSD/Linux alternative to `pgrep` and is equally
    # opaque, so include it in the same alternation.
    (r'\bkill\b.*\$\(\s*(pgrep|pidof)\b', "kill process via pgrep/pidof expansion (self-termination)"),
    (r'\bkill\b.*`\s*(pgrep|pidof)\b', "kill process via backtick pgrep/pidof expansion (self-termination)"),
    # launchctl-driven gateway stop/restart on macOS. The agent can bypass
    # the `deerflow gateway stop|restart` pattern above by driving launchd
    # directly against the service label (commonly `ai.deerflow.gateway`).
    # Catch the operations that stop, restart, or unload it.
    (r'\blaunchctl\s+(stop|kickstart|bootout|unload|kill|disable|remove)\b.*\b(deerflow|ai\.deerflow)\b', "stop/restart deerflow launchd service (kills running agents)"),
    # File copy/move/edit into sensitive system paths (/etc/ and macOS
    # /private/etc/ mirror).
    (rf'\b(cp|mv|install)\b.*\s{_SYSTEM_CONFIG_PATH}', "copy/move file into system config path"),
    (rf'\b(cp|mv|install)\b.*\s["\']?{_PROJECT_SENSITIVE_WRITE_TARGET}["\']?{_COMMAND_TAIL}', "overwrite project env/config file"),
    # cp/mv/install OVERWRITING a sensitive credential/SSH/shell-rc/the agent file.
    # The tee/redirection patterns above already gate _SENSITIVE_WRITE_TARGET
    # (~/.ssh/*, ~/.netrc/.pgpass/.npmrc/.pypirc, shell rc files,
    # ~/.deerflow/config.yaml/.env), but cp/mv/install was only paired for /etc and
    # project-relative env/config — so `cp evil ~/.ssh/authorized_keys` (key
    # implant), `cp creds ~/.netrc`, and `cp evil ~/.bashrc` (login-time command
    # injection) slipped through with auto-approve. Same unpaired-door rationale
    # as #14639 / the sed-tee-redirect pairing on these targets.
    # Anchor the sensitive target to the command tail so this fires on the
    # DESTINATION (last arg) only — `cp evil ~/.ssh/authorized_keys` is gated,
    # but reading OUT of a sensitive path (`cp ~/.ssh/config /tmp/x`) stays safe.
    # The trailing `[^\s"\']*` consumes the rest of the destination filename
    # (e.g. `authorized_keys` after the `~/.ssh/` fragment).
    (rf'\b(cp|mv|install)\b.*\s["\']?{_SENSITIVE_WRITE_TARGET}[^\s"\']*["\']?{_COMMAND_TAIL}', "copy/move file into sensitive credential/SSH/shell-rc path"),
    # In-place edits mutate the target file directly, bypassing redirection,
    # tee, and copy/move/install coverage. Gate the same user-controlled
    # startup/credential files so `sed -i ... ~/.bashrc` and `perl -i ...
    # ~/.ssh/authorized_keys` cannot silently plant login commands or keys.
    (rf'\bsed\s+-[^\s]*i.*(?:{_USER_SENSITIVE_WRITE_TARGET})[^\s"\']*', "in-place edit of sensitive credential/SSH/shell-rc path"),
    (rf'\bsed\s+--in-place\b.*(?:{_USER_SENSITIVE_WRITE_TARGET})[^\s"\']*', "in-place edit of sensitive credential/SSH/shell-rc path (long flag)"),
    (rf'\b(?:perl|ruby)\b.*(?:^|\s)-[^\s]*i\b.*(?:{_USER_SENSITIVE_WRITE_TARGET})[^\s"\']*', "in-place edit of sensitive credential/SSH/shell-rc path (perl/ruby)"),
    (rf'\bsed\s+-[^\s]*i.*\s{_SYSTEM_CONFIG_PATH}', "in-place edit of system config"),
    (rf'\bsed\s+--in-place\b.*\s{_SYSTEM_CONFIG_PATH}', "in-place edit of system config (long flag)"),
    # In-place edit of a the agent-managed security file (~/.deerflow/config.yaml or
    # .env). sed -i bypasses the redirection/tee patterns above because it
    # mutates the file directly. Pairs the file_tools write_file/patch deny so
    # the terminal side is not an open door. See #14639.
    (rf'\bsed\s+-[^\s]*i.*(?:{_AGENT_CONFIG_PATH}|{_AGENT_ENV_PATH})', "in-place edit of the agent config/env"),
    (rf'\bsed\s+--in-place\b.*(?:{_AGENT_CONFIG_PATH}|{_AGENT_ENV_PATH})', "in-place edit of the agent config/env (long flag)"),
    # perl -i and ruby -i perform the same in-place mutation as sed -i but are
    # not caught by the -e/-c script-execution pattern above (which targets code
    # evaluation, not file mutation). Pairs the sed -i coverage from #14639.
    # The -i flag can appear as its own token after other flags
    # (`perl -p -i -e ... config.yaml`), combined (`perl -pi -e`), or with a
    # backup suffix (`perl -i.bak`). Match any flag token containing `i`
    # anywhere in the args, not just the first token — `perl -e '...'` (code
    # eval, no -i) does not trip because it has no `-...i` flag token.
    (rf'\b(?:perl|ruby)\b.*(?:^|\s)-[^\s]*i\b.*(?:{_AGENT_CONFIG_PATH}|{_AGENT_ENV_PATH})', "in-place edit of the agent config/env (perl/ruby)"),
    # Interpreter heredocs are handled by _execution_flag_findings() alongside
    # inline-exec flags; keep only shell heredocs regex-based here.
    # Shell execution via heredoc — `bash <<'EOF' ... EOF` runs arbitrary
    # shell commands without triggering the `bash -c` pattern above. The
    # inner commands may not individually match any dangerous pattern (e.g.
    # data-exfiltration pipelines using curl/cat) yet are still executed in
    # a full shell context.
    (r'\b(bash|sh|zsh|ksh)\s+<<', "shell execution via heredoc"),
    # Git destructive operations that can lose uncommitted work or rewrite
    # shared history. Not captured by rm/chmod/etc patterns.
    # `git reset --hard` accepts any unambiguous long-flag prefix (--h,
    # --ha, --har, --hard) because git's own option parser resolves
    # abbreviated long flags -- `--hard` is the only `git reset` mode
    # starting with "h" (siblings are --soft/--mixed/--merge/--keep), so
    # this cannot collide with another reset mode. It also does not match
    # `--help`, which git special-cases before mode resolution.
    (r'\bgit\s+reset\s+--h(?:a(?:r(?:d)?)?)?\b', "git reset --hard (destroys uncommitted changes)"),
    (r'\bgit\s+push\b.*--forc[a-z]*\b', "git force push (rewrites remote history)"),
    (r'\bgit\s+push\b.*-f\b', "git force push short flag (rewrites remote history)"),
    (r'\bgit\s+clean\s+-[^\s]*f', "git clean with force (deletes untracked files)"),
    (r'\bgit\s+branch\s+-D\b', "git branch force delete"),
    # `-D` is shorthand for `-d --force`; the long-flag spellings
    # (`--delete`, `--force`) are different tokens entirely, so they slip
    # past the `-D\b` pattern above even though `git branch -d --force`
    # and `git branch --delete --force` delete an unmerged branch exactly
    # like `-D` does. Match delete+force in either order, bounded to the
    # same command segment (not spanning `;`/`|`/`&`/newline) the same
    # way the sudo patterns below do, to avoid contaminating an unrelated
    # later command in the same script.
    (r'\bgit\s+branch\b[^;|&\n]*?(?:-d\b|--delete\b)[^;|&\n]*?(?:-f\b|--force\b)', "git branch force delete (long flags)"),
    (r'\bgit\s+branch\b[^;|&\n]*?(?:-f\b|--force\b)[^;|&\n]*?(?:-d\b|--delete\b)', "git branch force delete (long flags, force-first)"),
    # Script execution after chmod +x — catches the two-step pattern where
    # a script is first made executable then immediately run. The script
    # content may contain dangerous commands that individual patterns miss.
    (r'\bchmod\s+\+x\b.*[;&|]+\s*\./', "chmod +x followed by immediate execution"),
    # Sudo with stdin / askpass / shell / list-privs flags. An LLM-driven
    # agent has no TTY, so sudo invocations that succeed without human
    # interaction are those reading the password from stdin (-S/--stdin)
    # or via an askpass helper (-A/--askpass). The shell-launch (-s) and
    # list-privileges (-a) flags are also gated since they are
    # privilege-relevant invocations the agent can chain after acquiring
    # the password (e.g. read SUDO_PASSWORD from .env -> sudo -S -s ->
    # root shell). Plain `sudo cmd` (no flag) is TTY-bound and excluded.
    # `_normalize_command_for_detection` lowercases input before pattern
    # matching, so case variants of S/s and A/a collapse — both forms
    # are gated below. Lazy `[^;|&\n]*?` allows flag arguments (e.g.
    # `sudo -u root -S whoami`) without spanning command separators. See
    # #17873 category 4.
    # sudo's own option parser (like git's) resolves unambiguous
    # long-flag prefixes, so `sudo --stdi` runs identically to
    # `sudo --stdin` and `sudo --ask` to `sudo --askpass` -- confirmed
    # against a live sudo binary. `--st[a-z]*` and `--a[a-z]*` are safe
    # to match broadly: per `man sudo`, `--stdin` is the only long option
    # starting with "st" (siblings are --shell/--set-home) and
    # `--askpass` is the only one starting with "a" at all.
    (r'\bsudo\b[^;|&\n]*?\s+(?:-s\b|--st[a-z]*\b|-a\b|--a[a-z]*\b)',
     "sudo with privilege flag (stdin/askpass/shell/list)"),
    # Combined short-flag form: -nS, -ns, -sa, -las — sudo flags packed
    # into a single -X token. Catches the same threat class.
    (r'\bsudo\b[^;|&\n]*?\s+-[a-z]*[sa][a-z]*\b',
     "sudo with combined-flag privilege escalation"),
]

# Hermes ile ayni bayraklar. IGNORECASE olmadan buyuk harfle yazilmis desenler
# (ornegin SQL DROP) sessizce devre disi kalir.
_RE_FLAGS = re.IGNORECASE | re.DOTALL

DANGEROUS_PATTERNS_COMPILED: list[tuple[re.Pattern[str], str]] = [
    (re.compile(pattern, _RE_FLAGS), description)
    for pattern, description in DANGEROUS_PATTERNS
]
