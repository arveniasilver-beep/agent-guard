"""Taban katmani: asla otomatik onaylanmayacak komutlar.

HARDLINE_PATTERNS listesi ve yardimcilari Nous Research'un Hermes Agent
projesinden (MIT) uyarlanmistir. Atif icin THIRD_PARTY_NOTICES.md.

TASARIM: DANGEROUS_PATTERNS "kullaniciya sor" demektir; buradaki desenler
"her seferinde sor, kalici izin verilemez" demektir. Auto mod bu katmani
asla gecemez. Amac, otomatik onayin tek bir yanlis kararla diski silmesini
imkansiz kilmak.

Tirnak ve suslu parantez idiomlarina karsi _hardline_rm_path yardimcisi
kullanilir; `rm -rf "/"` ve `rm -rf ${HOME}` de yakalanir.
"""

from __future__ import annotations

import re

_HARDLINE_SYSTEM_DIRS = (
    r'/home|/home/\*|/root|/root/\*|/etc|/etc/\*|/usr|/usr/\*|'
    r'/var|/var/\*|/bin|/bin/\*|/sbin|/sbin/\*|/boot|/boot/\*|/lib|/lib/\*'
)

_CMDPOS = (
    # Real ;/&/| separators are converted to newlines by the quote-aware
    # _mark_command_starts pass. Keeping them in this flat regex mistakes
    # quoted regex/data (for example grep '(safe|rm -rf /)') for commands.
    r'(?:^|[\n`]|\$\()'            # start position
    r'\s*'                          # optional whitespace
    r'(?:sudo\s+(?:-[^\s]+\s+)*)?'  # optional sudo with flags
    r'(?:env\s+(?:\w+=\S*\s+)*)?'   # optional env with VAR=VAL pairs
    r'(?:(?:exec|nohup|setsid|time)\s+)*'  # optional wrapper commands
    r'\s*'
)

_RM_FLAG_PREFIX = _CMDPOS + r'rm\s+(-[^\s]*\s+)*'

def _hardline_rm_path(path_alt: str, tail: str = r'(?:\s|$|[)`;|&])') -> str:
    return rf'(?:["\'](?:{path_alt})["\']|(?:{path_alt}){tail})'

def _skip_shell_whitespace(command: str, pos: int) -> int:
    while pos < len(command) and command[pos].isspace():
        pos += 1
    return pos

def _scan_dollar_paren_end(command: str, start: int) -> int | None:
    """Return the offset after a balanced ``$(...)`` command substitution."""
    depth = 1
    quote: str | None = None
    i = start + 2
    while i < len(command):
        ch = command[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < len(command):
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "\\" and i + 1 < len(command):
            i += 2
            continue
        if command.startswith("$(", i):
            depth += 1
            i += 2
            continue
        if ch == ")":
            depth -= 1
            i += 1
            if depth == 0:
                return i
            continue
        i += 1
    return None

def _scan_backtick_end(command: str, start: int) -> int | None:
    i = start + 1
    while i < len(command):
        if command[i] == "\\" and i + 1 < len(command):
            i += 2
            continue
        if command[i] == "`":
            return i + 1
        i += 1
    return None

def _iter_shell_command_starts(command: str):
    starts = [0]

    def scan(start: int, end: int) -> None:
        quote: str | None = None
        i = start
        while i < end:
            ch = command[i]
            if quote == "'":
                if ch == "'":
                    quote = None
                i += 1
                continue
            if quote == '"':
                if ch == "\\" and i + 1 < end:
                    i += 2
                    continue
                if ch == '"':
                    quote = None
                    i += 1
                    continue
                if command.startswith("$(", i):
                    nested_end = _scan_dollar_paren_end(command, i)
                    starts.append(i + 2)
                    scan(i + 2, nested_end - 1 if nested_end is not None else end)
                    i = nested_end if nested_end is not None else end
                    continue
                if ch == "`":
                    nested_end = _scan_backtick_end(command, i)
                    starts.append(i + 1)
                    scan(i + 1, nested_end - 1 if nested_end is not None else end)
                    i = nested_end if nested_end is not None else end
                    continue
                i += 1
                continue
            if ch in ("'", '"'):
                quote = ch
                i += 1
                continue
            if ch == "\\" and i + 1 < end:
                i += 2
                continue
            if command.startswith("$(", i):
                nested_end = _scan_dollar_paren_end(command, i)
                starts.append(i + 2)
                scan(i + 2, nested_end - 1 if nested_end is not None else end)
                i = nested_end if nested_end is not None else end
                continue
            if ch == "`":
                nested_end = _scan_backtick_end(command, i)
                starts.append(i + 1)
                scan(i + 1, nested_end - 1 if nested_end is not None else end)
                i = nested_end if nested_end is not None else end
                continue
            if ch in ("(", "{"):
                starts.append(i + 1)
            elif ch in ";\n":
                starts.append(i + 1)
            elif ch in "&|":
                repeated = i + 1 < end and command[i + 1] == ch
                starts.append(i + 2 if repeated else i + 1)
                if repeated:
                    i += 1
            i += 1

    scan(0, len(command))

    seen: set[int] = set()
    for start in starts:
        start = _skip_shell_whitespace(command, start)
        if start < len(command) and start not in seen:
            seen.add(start)
            yield start

def _mark_command_starts(command: str) -> str:
    """Insert a newline before each real (quote-aware) command start.

    ``\\n`` is already a ``_CMDPOS`` separator, so this rewrites subshell
    ``(cmd)`` and brace-group ``{ cmd; }`` openers — which the flat pattern
    class deliberately omits — into a form the anchored hardline/dangerous
    patterns recognize, WITHOUT the quoted-prose false positives that adding
    ``(`` / ``{`` to ``_CMDPOS`` would cause. Starts inside quotes are never
    produced by ``_iter_shell_command_starts``, so quoted arguments such as
    ``--title "block (reboot)"`` are left exactly as-is.
    """
    # Collect the (whitespace-skipped) start offsets, drop 0 (already anchored
    # by ``^``), and splice a newline in front of each — right-to-left so the
    # earlier offsets stay valid as we mutate.
    offsets = sorted(o for o in _iter_shell_command_starts(command) if o > 0)
    if not offsets:
        return command
    # Build once instead of repeatedly slicing and copying the full command for
    # every segment (quadratic at 10k+ compound-command segments).
    parts: list[str] = []
    previous = 0
    for offset in offsets:
        parts.extend((command[previous:offset], "\n"))
        previous = offset
    parts.append(command[previous:])
    return "".join(parts)

HARDLINE_PATTERNS = [
    # rm recursive targeting the root filesystem or protected roots.
    # `${HOME}` brace form and quoted paths (`rm -rf "/"`, `rm -rf "$HOME"`)
    # are handled via _hardline_rm_path so the floor cannot be bypassed with
    # the ordinary quoting/brace shell idioms.
    #
    # The path token matches any root-anchored path whose components collapse
    # back to "/" in the shell: a bare "/", repeated slashes ("//"), and
    # "."/".." current/parent segments ("/.", "/./", "/..", "/../..") all
    # resolve to root, optionally followed by a trailing glob ("/*", "//*").
    # Each inter-slash segment must be exactly "." or "..", so a longer dot
    # run or any real name is a literal directory, NOT root — "/tmp", "/home",
    # "/.ssh", "/.config" and even "/..." (a dir literally named "...") fall
    # through to the softer DANGEROUS_PATTERNS / system-directory rules
    # instead of being unconditionally hardline-blocked. The explicit "/ \*"
    # alt preserves the slash-space-glob spelling (`rm -rf / *`, which the
    # shell sees as two args: "/" plus the "*" glob).
    (_RM_FLAG_PREFIX + _hardline_rm_path(r'/(?:(?:\.\.?)?/)*(?:\.\.?)?\**|/ \*'), "recursive delete of root filesystem"),
    (_RM_FLAG_PREFIX + _hardline_rm_path(_HARDLINE_SYSTEM_DIRS), "recursive delete of system directory"),
    (_RM_FLAG_PREFIX + _hardline_rm_path(r'(?:~|\$\{?HOME\}?)(?:/?|/\*)?'), "recursive delete of home directory"),
    # Filesystem format
    (r'\bmkfs(\.[a-z0-9]+)?\b', "format filesystem (mkfs)"),
    # Raw block device overwrites (dd + redirection)
    (r'\bdd\b[^\n]*\bof=/dev/(sd|nvme|hd|mmcblk|vd|xvd)[a-z0-9]*', "dd to raw block device"),
    (r'>\s*/dev/(sd|nvme|hd|mmcblk|vd|xvd)[a-z0-9]*\b', "redirect to raw block device"),
    # Fork bomb (classic shell form)
    (r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:', "fork bomb"),
    # Kill every process on the system
    (r'\bkill\s+(-[^\s]+\s+)*-1\b', "kill all processes"),
    # System shutdown / reboot — anchor to command position (start of line,
    # after a command separator, or after sudo/env wrappers) so we don't
    # false-positive on "echo reboot" or "grep 'shutdown' logs".
    # _CMDPOS matches start-of-command positions.
    (_CMDPOS + r'(shutdown|reboot|halt|poweroff)\b', "system shutdown/reboot"),
    (_CMDPOS + r'init\s+[06]\b', "init 0/6 (shutdown/reboot)"),
    (_CMDPOS + r'systemctl\s+(poweroff|reboot|halt|kexec)\b', "systemctl poweroff/reboot"),
    (_CMDPOS + r'telinit\s+[06]\b', "telinit 0/6 (shutdown/reboot)"),
]

_HARDLINE_RE_FLAGS = re.IGNORECASE | re.DOTALL

HARDLINE_PATTERNS_COMPILED: list[tuple[re.Pattern[str], str]] = [
    (re.compile(pattern, _HARDLINE_RE_FLAGS), description)
    for pattern, description in HARDLINE_PATTERNS
]


def is_hardline(command: str) -> str | None:
    """Komut taban katmanina giriyorsa aciklamasini, girmiyorsa None dondur."""
    if not command or not command.strip():
        return None
    for pattern, description in HARDLINE_PATTERNS_COMPILED:
        if pattern.search(command):
            return description
    return None
