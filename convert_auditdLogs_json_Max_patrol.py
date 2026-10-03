# Windows python .\convert_auditdLogs_json_Max_patrol.py .\audit_log_SUCCESS_copy_fail_copy.txt -o normalized.json

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

Convert raw Linux auditd records into the intermediate JSON format used by
Security-Experts-Community/open-xp-rules normalization tests.

Input:
  type=SYSCALL msg=audit(1556556343.052:28650): ...
  type=PATH    msg=audit(1556556343.052:28650): ...

Output:
{
  "eventid": "28650",
  "items": {
    "CWD": ["cwd=\"/root\""],
    "EOE": [""],
    "PATH": ["..."],
    "PROCTITLE": ["..."],
    "SYSCALL": ["..."]
  },
  "node": "debian-test",
  "timestamp": "1556556343",
  "timestampfractional": "052"
}

No third-party packages. Windows compatible.
"""
import argparse
import json
import re
import sys
from collections import OrderedDict

try:
    from datetime import datetime, timezone, timedelta
except ImportError:
    raise

# ---------------------------------------------------------------------------
# Identity mappings.
# Add your lab users/groups here when you want ausearch -i-like enrichment.
# ---------------------------------------------------------------------------
USER_MAP = {
    "0": "root",
    "1000": "user",
}
GROUP_MAP = {
    "0": "root",
    "1000": "user",
}

ARCH_MAP = {
    "c000003e": "c000003e",
    "40000003": "40000003",
    "x86_64": "c000003e",
    "amd64": "c000003e",
    "b64": "c000003e",
    "i386": "40000003",
    "i686": "40000003",
    "x86": "40000003",
    "b32": "40000003",
}

# Linux x86_64 syscall table. Includes the calls used by the Open-XP auditd
# formulas plus common calls, so symbolic ausearch -i input can be converted
# back to the numeric representation expected by the test fixtures.
X86_64_SYSCALLS = {
    "read":0,"write":1,"open":2,"close":3,"stat":4,"fstat":5,"lstat":6,
    "poll":7,"lseek":8,"mmap":9,"mprotect":10,"munmap":11,"brk":12,
    "rt_sigaction":13,"rt_sigprocmask":14,"rt_sigreturn":15,"ioctl":16,
    "pread64":17,"pwrite64":18,"readv":19,"writev":20,"access":21,"pipe":22,
    "select":23,"sched_yield":24,"mremap":25,"msync":26,"mincore":27,
    "madvise":28,"shmget":29,"shmat":30,"shmctl":31,"dup":32,"dup2":33,
    "pause":34,"nanosleep":35,"getitimer":36,"alarm":37,"setitimer":38,
    "getpid":39,"sendfile":40,"socket":41,"connect":42,"accept":43,"sendto":44,
    "recvfrom":45,"sendmsg":46,"recvmsg":47,"shutdown":48,"bind":49,
    "listen":50,"getsockname":51,"getpeername":52,"socketpair":53,
    "setsockopt":54,"getsockopt":55,"clone":56,"fork":57,"vfork":58,
    "execve":59,"exit":60,"wait4":61,"kill":62,"uname":63,"semget":64,
    "semop":65,"semctl":66,"shmdt":67,"msgget":68,"msgsnd":69,"msgrcv":70,
    "msgctl":71,"fcntl":72,"flock":73,"fsync":74,"fdatasync":75,
    "truncate":76,"ftruncate":77,"getdents":78,"getcwd":79,"chdir":80,
    "fchdir":81,"rename":82,"mkdir":83,"rmdir":84,"creat":85,"link":86,
    "unlink":87,"symlink":88,"readlink":89,"chmod":90,"fchmod":91,
    "chown":92,"fchown":93,"lchown":94,"umask":95,"gettimeofday":96,
    "getrlimit":97,"getrusage":98,"sysinfo":99,"times":100,"ptrace":101,
    "getuid":102,"syslog":103,"getgid":104,"setuid":105,"setgid":106,
    "geteuid":107,"getegid":108,"setpgid":109,"getppid":110,"getpgrp":111,
    "setsid":112,"setreuid":113,"setregid":114,"getgroups":115,"setgroups":116,
    "setresuid":117,"getresuid":118,"setresgid":119,"getresgid":120,
    "getpgid":121,"setfsuid":122,"setfsgid":123,"getsid":124,"capget":125,
    "capset":126,"rt_sigpending":127,"rt_sigtimedwait":128,
    "rt_sigqueueinfo":129,"rt_sigsuspend":130,"sigaltstack":131,
    "utime":132,"mknod":133,"uselib":134,"personality":135,"ustat":136,
    "statfs":137,"fstatfs":138,"sysfs":139,"getpriority":140,"setpriority":141,
    "sched_setparam":142,"sched_getparam":143,"sched_setscheduler":144,
    "sched_getscheduler":145,"sched_get_priority_max":146,
    "sched_get_priority_min":147,"sched_rr_get_interval":148,"mlock":149,
    "munlock":150,"mlockall":151,"munlockall":152,"vhangup":153,
    "modify_ldt":154,"pivot_root":155,"_sysctl":156,"prctl":157,
    "arch_prctl":158,"adjtimex":159,"setrlimit":160,"chroot":161,"sync":162,
    "acct":163,"settimeofday":164,"mount":165,"umount2":166,"swapon":167,
    "swapoff":168,"reboot":169,"sethostname":170,"setdomainname":171,
    "iopl":172,"ioperm":173,"create_module":174,"init_module":175,
    "delete_module":176,"get_kernel_syms":177,"query_module":178,
    "quotactl":179,"nfsservctl":180,"getpmsg":181,"putpmsg":182,
    "afs_syscall":183,"tuxcall":184,"security":185,"gettid":186,
    "readahead":187,"setxattr":188,"lsetxattr":189,"fsetxattr":190,
    "getxattr":191,"lgetxattr":192,"fgetxattr":193,"listxattr":194,
    "llistxattr":195,"flistxattr":196,"removexattr":197,"lremovexattr":198,
    "fremovexattr":199,"tkill":200,"time":201,"futex":202,
    "sched_setaffinity":203,"sched_getaffinity":204,"set_thread_area":205,
    "io_setup":206,"io_destroy":207,"io_getevents":208,"io_submit":209,
    "io_cancel":210,"get_thread_area":211,"lookup_dcookie":212,
    "epoll_create":213,"epoll_ctl_old":214,"epoll_wait_old":215,
    "remap_file_pages":216,"getdents64":217,"set_tid_address":218,
    "restart_syscall":219,"semtimedop":220,"fadvise64":221,
    "timer_create":222,"timer_settime":223,"timer_gettime":224,
    "timer_getoverrun":225,"timer_delete":226,"clock_settime":227,
    "clock_gettime":228,"clock_getres":229,"clock_nanosleep":230,
    "exit_group":231,"epoll_wait":232,"epoll_ctl":233,"tgkill":234,
    "utimes":235,"mbind":237,"set_mempolicy":238,"get_mempolicy":239,
    "mq_open":240,"mq_unlink":241,"mq_timedsend":242,"mq_timedreceive":243,
    "mq_notify":244,"mq_getsetattr":245,"kexec_load":246,"waitid":247,
    "add_key":248,"request_key":249,"keyctl":250,"ioprio_set":251,
    "ioprio_get":252,"inotify_init":253,"inotify_add_watch":254,
    "inotify_rm_watch":255,"migrate_pages":256,"openat":257,"mkdirat":258,
    "mknodat":259,"fchownat":260,"futimesat":261,"newfstatat":262,
    "unlinkat":263,"renameat":264,"linkat":265,"symlinkat":266,
    "readlinkat":267,"fchmodat":268,"faccessat":269,"pselect6":270,
    "ppoll":271,"unshare":272,"set_robust_list":273,"get_robust_list":274,
    "splice":275,"tee":276,"sync_file_range":277,"vmsplice":278,
    "move_pages":279,"utimensat":280,"epoll_pwait":281,"signalfd":282,
    "timerfd_create":283,"eventfd":284,"fallocate":285,"timerfd_settime":286,
    "timerfd_gettime":287,"accept4":288,"signalfd4":289,"eventfd2":290,
    "epoll_create1":291,"dup3":292,"pipe2":293,"inotify_init1":294,
    "preadv":295,"pwritev":296,"rt_tgsigqueueinfo":297,
    "perf_event_open":298,"recvmmsg":299,"fanotify_init":300,
    "fanotify_mark":301,"prlimit64":302,"name_to_handle_at":303,
    "open_by_handle_at":304,"clock_adjtime":305,"syncfs":306,"sendmmsg":307,
    "setns":308,"getcpu":309,"process_vm_readv":310,"process_vm_writev":311,
    "kcmp":312,"finit_module":313,"sched_setattr":314,"sched_getattr":315,
    "renameat2":316,"seccomp":317,"getrandom":318,"memfd_create":319,
    "kexec_file_load":320,"bpf":321,"execveat":322,"userfaultfd":323,
    "membarrier":324,"mlock2":325,"copy_file_range":326,"preadv2":327,
    "pwritev2":328,"pkey_mprotect":329,"pkey_alloc":330,"pkey_free":331,
    "statx":332,"io_pgetevents":333,"rseq":334,"pidfd_send_signal":424,
    "io_uring_setup":425,"io_uring_enter":426,"io_uring_register":427,
    "open_tree":428,"move_mount":429,"fsopen":430,"fsconfig":431,
    "fsmount":432,"fspick":433,"pidfd_open":434,"clone3":435,
    "close_range":436,"openat2":437,"pidfd_getfd":438,"faccessat2":439,
    "process_madvise":440,"epoll_pwait2":441,"mount_setattr":442,
    "quotactl_fd":443,"landlock_create_ruleset":444,"landlock_add_rule":445,
    "landlock_restrict_self":446,"memfd_secret":447,"process_mrelease":448,
    "futex_waitv":449,"set_mempolicy_home_node":450,
}

# i386 numbers used by the normalization package, plus common process calls.
I386_SYSCALLS = {
    "exit":1,"fork":2,"read":3,"write":4,"open":5,"close":6,"creat":8,
    "link":9,"unlink":10,"execve":11,"chdir":12,"chmod":15,"lchown":16,
    "setuid":23,"getuid":24,"setgid":46,"getgid":47,"geteuid":49,"getegid":50,
    "setreuid":70,"setregid":71,"getgroups":80,"setgroups":81,"getpgrp":65,
    "setsid":66,"setresuid":164,"getresuid":165,"setresgid":170,
    "getresgid":171,"capset":185,"ptrace":26,"rmdir":40,"rename":38,
    "mkdir":39,"symlink":83,"readlink":85,"fchmod":94,"fchown":95,
    "chown":182,"chown32":198,"fchown32":207,"lchown32":212,
    "fchmodat":306,"fchownat":298,"openat":295,
    "socket":359,"bind":361,"connect":362,"listen":363,"accept4":364,
    "socketcall":102,"execveat":358,
}

SYSCALLS = {"c000003e": X86_64_SYSCALLS, "40000003": I386_SYSCALLS}

FIELD_RE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)=")
HEADER_RE = re.compile(
    r"type=(?P<type>[A-Za-z0-9_]+)\s+msg=audit\((?P<stamp>[^)]+)\)\s*:\s*(?P<body>.*)$"
)
NODE_RE = re.compile(r"(?:^|\s)node=(?P<q>\"[^\"]*\"|'[^']*'|[^\s]+)")

# Fields for which the test fixtures normally contain a quoted value.
QUOTE_FIELDS = {
    "comm","exe","key","name","cwd","acct","hostname","terminal","addr",
    "filename","old","new","rule","id","acct","ouid","ogid"
}

def unquote(v):
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v

def quote(v):
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'

def scan_fields(body):
    """Parse audit key=value tokens, including quoted strings and {...} values."""
    out = []
    i, n = 0, len(body)
    while i < n:
        while i < n and body[i].isspace():
            i += 1
        if i >= n:
            break
        start = i
        while i < n and (body[i].isalnum() or body[i] in "_"):
            i += 1
        if i == start or i >= n or body[i] != "=":
            # Preserve a malformed/standalone fragment as a raw token.
            j = i
            while j < n and not body[j].isspace():
                j += 1
            out.append((None, body[start:j]))
            i = j
            continue
        key = body[start:i]
        i += 1
        if i >= n:
            out.append((key, ""))
            break
        if body[i] in "\"'":
            q = body[i]
            j = i + 1
            esc = False
            while j < n:
                c = body[j]
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == q:
                    j += 1
                    break
                j += 1
            val = body[i:j]
            i = j
        elif body[i] == "{":
            depth = 0
            j = i
            inq = None
            esc = False
            while j < n:
                c = body[j]
                if inq:
                    if esc:
                        esc = False
                    elif c == "\\":
                        esc = True
                    elif c == inq:
                        inq = None
                else:
                    if c in "\"'":
                        inq = c
                    elif c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                j += 1
            val = body[i:j]
            i = j
        else:
            j = i
            while j < n and not body[j].isspace():
                j += 1
            val = body[i:j]
            i = j
        out.append((key, val))
    return out

def fields_dict(fields):
    d = {}
    for k, v in fields:
        if k is not None:
            d[k] = v
    return d

def canonical_value(key, value):
    if value is None:
        return ""
    if key == "proctitle":
        # Both raw auditd HEX and interpreted/plain proctitle occur in the
        # repository fixtures. Preserve the representation supplied by input.
        return value
    return value

def canonical_record_body(record_type, body, arch_hint=None):
    fields = scan_fields(body)
    d = fields_dict(fields)

    if record_type == "SYSCALL":
        arch = d.get("arch")
        arch = ARCH_MAP.get(unquote(arch or ""), unquote(arch or ""))
        if arch:
            for idx, (k, v) in enumerate(fields):
                if k == "arch":
                    fields[idx] = (k, arch)
        syscall = d.get("syscall")
        if syscall:
            sv = unquote(syscall)
            if not sv.isdigit():
                num = SYSCALLS.get(arch, {}).get(sv.lower())
                if num is not None:
                    for idx, (k, v) in enumerate(fields):
                        if k == "syscall":
                            fields[idx] = (k, str(num))
                    syscall = str(num)

        # Values expected in the test fixture as interpreted/enriched fields.
        d = fields_dict(fields)
        derived = []
        arch_name = {"c000003e":"x86_64", "40000003":"i386"}.get(d.get("arch",""), None)
        if arch_name:
            derived.append(("ARCH", arch_name))
        if d.get("syscall"):
            n = unquote(d["syscall"])
            rev = {v:k for k,v in SYSCALLS.get(d.get("arch",""), {}).items()}
            derived.append(("SYSCALL", rev.get(int(n), n) if n.isdigit() else n))

        # The Open-XP test fixtures use names as supplemental AUID/UID/GID fields.
        identity = [
            ("auid","AUID"), ("uid","UID"), ("gid","GID"), ("euid","EUID"),
            ("suid","SUID"), ("fsuid","FSUID"), ("egid","EGID"),
            ("sgid","SGID"), ("fsgid","FSGID")
        ]
        for src, dst in identity:
            if src in d and not any(k == dst for k, _ in fields):
                raw = unquote(d[src])
                if src == "auid" and raw in {"4294967295","-1","unset"}:
                    name = "unset"
                else:
                    name = USER_MAP.get(raw) if src.endswith("uid") else GROUP_MAP.get(raw)
                    if name is None:
                        name = "unset" if raw in {"4294967295","-1"} else raw
                derived.append((dst, quote(name)))
        fields.extend(derived)

    elif record_type == "PATH":
        d = fields_dict(fields)
        if "ouid" in d and not any(k == "OUID" for k,_ in fields):
            raw = unquote(d["ouid"])
            fields.append(("OUID", quote(USER_MAP.get(raw, "unset" if raw in {"4294967295","-1"} else raw))))
        if "ogid" in d and not any(k == "OGID" for k,_ in fields):
            raw = unquote(d["ogid"])
            fields.append(("OGID", quote(GROUP_MAP.get(raw, "unset" if raw in {"4294967295","-1"} else raw))))

    elif record_type in {
        "USER_LOGIN","USER_START","USER_END","USER_AUTH","USER_ACCT",
        "USER_CMD","ADD_USER","DEL_USER","ADD_GROUP","DEL_GROUP","USER_MGMT",
        "GRP_MGMT","USER_ROLE_CHANGE","CRED_ACQ","CRED_DISP","CRED_REFR",
        "USER_AVC","USER_CHAUTHTOK","GRP_CHAUTHTOK"
    }:
        # Enrichment used by the normalization formulas/tests.
        d = fields_dict(fields)
        nested = {}
        if "msg" in d:
            nested = fields_dict(scan_fields(unquote(d["msg"])))
        for src, dst, mp in [
            ("uid","UID",USER_MAP), ("auid","AUID",USER_MAP),
            ("sauid","SAUID",USER_MAP)
        ]:
            if src in d and not any(k == dst for k,_ in fields):
                raw = unquote(d[src])
                name = "unset" if raw in {"4294967295","-1","unset"} else mp.get(raw, raw)
                fields.append((dst, quote(name)))

        # USER_LOGIN / ADD_USER and related records expose a translated ID
        # from the nested msg='...' section.
        if "id" in nested and not any(k == "ID" for k,_ in fields):
            raw = unquote(nested["id"])
            name = "unset" if raw in {"4294967295","-1","unset"} else USER_MAP.get(raw, raw)
            fields.append(("ID", quote(name)))

        # USER_AVC may carry sauid inside msg=.
        if "sauid" in nested and not any(k == "SAUID" for k,_ in fields):
            raw = unquote(nested["sauid"])
            name = "unset" if raw in {"4294967295","-1","unset"} else USER_MAP.get(raw, raw)
            fields.append(("SAUID", quote(name)))

    # Canonicalize only special values; preserve all unknown fields.
    rendered = []
    for k, v in fields:
        if k is None:
            rendered.append(v)
            continue
        rendered.append(k + "=" + canonical_value(k, v))
    return " ".join(rendered)

def parse_timestamp(stamp, date_order="dmy"):
    # epoch[.fraction]:serial
    base, serial = stamp.rsplit(":", 1)
    if re.fullmatch(r"\d+(?:\.\d+)?", base):
        if "." in base:
            sec, frac = base.split(".", 1)
        else:
            sec, frac = base, ""
        return sec, frac, serial

    # ausearch-style human timestamp.
    fmts = []
    if date_order == "dmy":
        fmts += ["%d/%m/%Y %H:%M:%S.%f", "%d/%m/%Y %H:%M:%S"]
    else:
        fmts += ["%m/%d/%Y %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S"]
    dt = None
    for fmt in fmts:
        try:
            dt = datetime.strptime(base, fmt)
            break
        except ValueError:
            pass
    if dt is None:
        raise ValueError("Unsupported audit timestamp: " + stamp)
    # Audit timestamps have no timezone in the text. For a deterministic
    # fixture use UTC; the important part for Open-XP raw JSON is epoch+fraction.
    epoch = int(dt.replace(tzinfo=timezone.utc).timestamp())
    frac = f"{dt.microsecond:06d}".rstrip("0")
    return str(epoch), frac, serial

def extract_node(line):
    m = NODE_RE.search(line)
    if not m:
        return ""
    return unquote(m.group("q"))

def remove_node_prefix(line):
    return NODE_RE.sub("", line, count=1).strip()

def parse_line(line, date_order="dmy"):
    line = line.strip()
    if not line:
        return None
    # Extract audit node before stripping a possible syslog wrapper.
    node = extract_node(line)
    pos = line.find("type=")
    if pos > 0:
        line = line[pos:]
    line_no_node = remove_node_prefix(line)
    m = HEADER_RE.match(line_no_node)
    if not m:
        return None
    typ = m.group("type")
    stamp = m.group("stamp")
    body = m.group("body")
    sec, frac, eventid = parse_timestamp(stamp, date_order)
    return {
        "type": typ,
        "body": body,
        "node": node,
        "timestamp": sec,
        "timestampfractional": frac,
        "eventid": eventid,
    }

def convert(text, node_override=None, date_order="dmy", add_eoe="never"):
    events = OrderedDict()
    for lineno, raw in enumerate(text.splitlines(), 1):
        rec = parse_line(raw, date_order=date_order)
        if rec is None:
            continue
        eid = rec["eventid"]
        if eid not in events:
            events[eid] = {
                "eventid": eid,
                "items": OrderedDict(),
                "node": node_override if node_override is not None else rec["node"],
                "timestamp": rec["timestamp"],
                "timestampfractional": rec["timestampfractional"],
            }
        ev = events[eid]
        if node_override is None and not ev["node"] and rec["node"]:
            ev["node"] = rec["node"]
        # Prefer the first record's timestamp; all records in one event share it.
        if rec["type"] == "EOE":
            body = ""
        else:
            body = canonical_record_body(rec["type"], rec["body"])
        ev["items"].setdefault(rec["type"], []).append(body)

    # The repository's tests contain EOE only where it is actually present.
    # Optional mode lets the user synthesize it for multi-record SYSCALL events.
    if add_eoe == "always":
        for ev in events.values():
            if "EOE" not in ev["items"]:
                ev["items"]["EOE"] = [""]
    elif add_eoe == "syscall":
        for ev in events.values():
            if "SYSCALL" in ev["items"] and "EOE" not in ev["items"]:
                ev["items"]["EOE"] = [""]

    # Match the test style: EOE first when present, then record types.
    for ev in events.values():
        items = ev["items"]
        if "EOE" in items:
            reordered = OrderedDict([("EOE", items["EOE"])])
            for k, v in items.items():
                if k != "EOE":
                    reordered[k] = v
            ev["items"] = reordered

    vals = list(events.values())
    if len(vals) == 1:
        return vals[0]
    return vals

def main():
    ap = argparse.ArgumentParser(description="Convert raw auditd logs to Open-XP raw JSON test format.")
    ap.add_argument("input", help="raw auditd log file; use - for stdin")
    ap.add_argument("-o","--output", default=None, help="output JSON file; default: stdout")
    ap.add_argument("--node", default=None, help="override top-level node")
    ap.add_argument("--date-order", choices=["dmy","mdy"], default="dmy",
                    help="order for human timestamps such as 10/03/2026; default dmy")
    ap.add_argument("--add-eoe", choices=["never","always","syscall"], default="never",
                    help="synthesize EOE; default never to match repository fixtures")
    ap.add_argument("--indent", type=int, default=2)
    args = ap.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        with open(args.input, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()

    result = convert(text, node_override=args.node, date_order=args.date_order, add_eoe=args.add_eoe)
    out = json.dumps(result, ensure_ascii=False, indent=args.indent)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(out)
            f.write("\n")
    else:
        print(out)

if __name__ == "__main__":
    main()
