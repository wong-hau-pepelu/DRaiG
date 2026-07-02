"""draig - reads one netflow capture and profiles whatever ip you point it at INSIDE that capture.

draig is not nmap. it does not scan, probe, or knock on anyone's door. you hand
it a csv of flows that already happened, name an ip that already shows up in
those flows, and it tells you the story of what that ip has been up to. the
packets are already dead; we're just the coroner.

    python draig.py flows.csv

you launch it with the csv, then it drops into an interactive prompt where you
type the target ip and any filters, one query at a time (nothing is baked into
the script, so you can re-question the same capture all day):

    flow> 198.51.100.23
    flow> 198.51.100.23 --port 22
    flow> --peer 203.0.113.29 -n 30
    flow> 198.51.100.23 --direction out
    flow> -h           (show this help again)
    flow> q            (quit)

two modes
---------
1. full report - give it just an ip and it prints the whole threat-hunting
   workup: overview & role, protocol mix, top peers (z-score outliers),
   client/server roles (read from the data if the columns exist, inferred
   otherwise), operator pivots, low-frequency talkers, ports (c2 flagging),
   tcp flags (syn-scan), beaconing (jitter verdicts), active hours + timezone
   guess, daily timeline (spike detection), and the high-volume victims.
   findings are tagged:
       [!]     statistical anomaly (ratio / z-score threshold crossed)
       [PIVOT] peer shares the target's /16 - possible shared infrastructure
       [C2]    behavioral c2 indicator (beaconing, persistence, known ports)
       [OP]    operator / management fingerprint (ssh, telnet, rdp, clickhouse)

       flow> 198.51.100.23

2. targeted query - pull the *specific rows* behind a finding. every query
   also prints the equivalent pandas commands so you can see (and steal) what
   it did, plus a top-peers breakdown of whatever matched. the ip is optional
   here: leave it out to slice the whole capture by port/peer/query.

       # all ssh flows for one ip
       flow> 198.51.100.23 --port 22

       # all ssh flows in the whole capture (no ip)
       flow> --port 22

       # only traffic the ip SENT (outbound), show 30 rows
       flow> 198.51.100.23 --direction out -n 30

       # everything between two hosts
       flow> 198.51.100.23 --peer 203.0.113.29

       # free-form pandas filter (learn df.query syntax)
       flow> --query "dst_port == 443 and num_octets > 100"

       # pick which columns to show
       flow> 198.51.100.23 --port 22 --columns start_time,src_ip_addr,dst_ip_addr,dst_port

sampling note (see intro_to_network_analysis_part5)
---------------------------------------------------
netflow collectors often keep only 1-in-N packets to save space. when a
`sample_interval` column is present and non-zero, each observed flow is really
standing in for roughly N flows, so raw byte/packet counts lie low by that
factor. draig works out `samp_mult`, `eff_octets`, and `eff_pkts` at load time
and uses the effective (un-sampled) volumes for every volume statistic, while
keeping the timing checks (beaconing, syn ratios) on the raw rows, because
sampling throws away whole flows and you cannot rebuild a beacon's heartbeat
from a recording full of holes.

options (typed at the flow> prompt):
    ip                  target ip (optional in query mode; required for a report)
    --direction         in | out | both   (default both)
    --peer              only flows between target and this peer ip
    --port              only flows where src_port OR dst_port == PORT
    -q / --query        a pandas df.query() expression applied on top
    -n / --head         number of rows to display (default 20)
    --columns           comma-separated columns to display
"""

import argparse
import shlex
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# tcp flag bitmask, the same one part 5 spells out (FIN1 SYN2 RST4 PSH8 ACK16 URG32)
FLAG_NAMES = [(32, "URG"), (16, "ACK"), (8, "PSH"), (4, "RST"), (2, "SYN"), (1, "FIN")]

# well-known ports so the report reads in english instead of just numbers.
WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP-Sub", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 3306: "MySQL", 3389: "RDP",
    5432: "Postgres", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8123: "ClickHouse-HTTP", 8443: "HTTPS-Alt", 9000: "HTTP/App",
    9009: "ClickHouse", 56777: "SSH-NonStd",
}

# ports that cheap off-the-shelf c2 / rat kits love to hardcode. lazy of them, handy for us.
C2_PORTS = {1234, 4444, 5555, 6666, 7777, 8888, 9001, 31337}

# management / analytics ports. when the target dials OUT to one of these it
# smells like an operator tending their box, not a victim getting milked.
OPERATOR_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC",
    3306: "MySQL", 5432: "Postgres", 6379: "Redis",
    8123: "ClickHouse-HTTP", 9000: "ClickHouse-App", 9009: "ClickHouse",
    56777: "SSH-NonStd",
}

# a port is "service-like" if it's a low registered port or a known service.
SERVICE_PORT_SET = set(WELL_KNOWN_PORTS) | set(OPERATOR_PORTS)

# parsed once per file so the prompt isn't re-reading the csv on every query.
_CACHE = {}


def decode_flags(value: int) -> str:
    try:
        value = int(value)
    except (TypeError, ValueError):
        return str(value)
    if value == 0:
        return "NULL"
    parts = [name for bit, name in FLAG_NAMES if value & bit]
    return "+".join(parts) if parts else "none"


def section(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def load(csv_file: Path) -> pd.DataFrame:
    key = str(csv_file)
    if key not in _CACHE:
        df = pd.read_csv(csv_file, low_memory=False)
        df["start_time"] = pd.to_datetime(df["start_time"], errors="coerce")

        # ---- sampling weight (intro_to_network_analysis_part5) ----
        # a 1-in-N sampled flow stands in for ~N flows, so raw octet/packet
        # counts need scaling by the interval before any volume stat is trusted.
        # sample_interval of 0 or missing means the flow wasn't sampled -> x1.
        if "sample_interval" in df.columns:
            mult = pd.to_numeric(df["sample_interval"], errors="coerce").fillna(0)
            mult = mult.where(mult > 0, 1)
        else:
            mult = pd.Series(1, index=df.index)
        df["samp_mult"] = mult

        # effective (un-sampled) volumes, used everywhere volume actually matters.
        if "num_octets" in df.columns:
            df["eff_octets"] = df["num_octets"] * mult
        if "num_pkts" in df.columns:
            df["eff_pkts"] = df["num_pkts"] * mult

        _CACHE[key] = df
    return _CACHE[key]


def has_cols(df: pd.DataFrame, *cols: str) -> bool:
    """true only if every named column exists. lets sections skip instead of crashing."""
    return all(c in df.columns for c in cols)


def sampled_rows(df: pd.DataFrame) -> int:
    """how many rows in this frame were sampled (samp_mult > 1)."""
    if "samp_mult" in df.columns:
        return int((df["samp_mult"] > 1).sum())
    return 0


def subnet16(ip: str):
    """first two octets + a trailing dot, e.g. '198.51.', i.e. the /16 prefix."""
    if not ip:
        return None
    parts = ip.split(".")
    return ".".join(parts[:2]) + "." if len(parts) >= 2 else None


def looks_like_ipv4(value: str) -> bool:
    """true only for a well-formed dotted-quad ipv4 (4 octets, each 0-255)."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def warn_if_bad_ip(label: str, value: str) -> bool:
    """warn about a malformed ip. returns true if it looked fine."""
    if value and not looks_like_ipv4(value):
        print(f"  [!] {label} {value!r} is not a valid IPv4 address "
              f"(check for a typo, e.g. a missing dot).")
        return False
    return True


def suggest_similar_ips(df: pd.DataFrame, value: str, limit: int = 5) -> None:
    """when an ip isn't in the file, suggest near-misses so one fat-fingered octet doesn't cost you ten minutes."""
    all_ips = pd.unique(pd.concat([df["src_ip_addr"], df["dst_ip_addr"]]))
    stripped = value.replace(".", "")
    # match on shared leading digits (dots ignored) to catch the obvious typos.
    near = sorted(
        (ip for ip in all_ips if isinstance(ip, str)),
        key=lambda ip: -_common_prefix_len(ip.replace(".", ""), stripped),
    )
    near = [ip for ip in near if _common_prefix_len(ip.replace(".", ""), stripped) >= 3][:limit]
    if near:
        print(f"  [i] {value!r} not found. Did you mean: {', '.join(near)} ?")
    else:
        print(f"  [i] {value!r} does not appear in this file.")


def _common_prefix_len(a: str, b: str) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def infer_role(df: pd.DataFrame, target_ip: str) -> pd.Series:
    """guess whether the target was client or server on each flow.

    used when the authoritative client_ip_addr / server_ip_addr columns aren't
    in the file (which is most real captures). grounded in parts 2 and 5:
      * a syn-only flow (tcp_flags == 2) travels client -> server, so whoever
        sent it is the client. this is the strongest signal and it wins.
      * otherwise the service end is the one holding the low / well-known port,
        while the client end holds a high ephemeral port (part 2 puts those
        roughly in the 10000-65535 range).
    returns a series of 'client' / 'server' / 'unknown', row-aligned to df.
    """
    is_src = df["src_ip_addr"] == target_ip
    src_port = pd.to_numeric(df.get("src_port"), errors="coerce")
    dst_port = pd.to_numeric(df.get("dst_port"), errors="coerce")

    target_port = src_port.where(is_src, dst_port)
    peer_port = dst_port.where(is_src, src_port)

    def is_service(p):
        return (p < 1024) | p.isin(SERVICE_PORT_SET)

    def is_ephemeral(p):
        return p >= 10000

    t_service, t_eph = is_service(target_port), is_ephemeral(target_port)
    p_service, p_eph = is_service(peer_port), is_ephemeral(peer_port)

    conditions = [
        t_service & p_eph,          # target holds service port -> server
        t_eph & p_service,          # target holds ephemeral port -> client
        target_port < peer_port,    # lower port -> server (fallback)
        peer_port < target_port,    # higher port -> client (fallback)
    ]
    choices = ["server", "client", "server", "client"]
    role = pd.Series(np.select(conditions, choices, default="unknown"),
                     index=df.index)

    # a lone syn only ever goes client -> server, so it overrides the port guess.
    if "tcp_flags" in df.columns:
        syn_only = pd.to_numeric(df["tcp_flags"], errors="coerce") == 2
        role = role.mask(syn_only & is_src, "client")
        role = role.mask(syn_only & ~is_src, "server")
    return role


# ----------------------------------------------------------------------
# mode 2: targeted query - pull the exact rows behind a finding + show the pandas
# ----------------------------------------------------------------------
def run_query(args: argparse.Namespace) -> None:
    csv_file = Path(args.file)
    df = load(csv_file)

    # sanity-check the ip inputs up front so typos surface before the query runs.
    warn_if_bad_ip("target IP", args.ip)
    if args.peer:
        warn_if_bad_ip("--peer", args.peer)

    # build the mask one step at a time, recording each pandas command so the
    # result is reproducible and you can lift the syntax for your own notebook.
    steps = [f"df = pd.read_csv({csv_file.name!r})"]

    if args.ip:
        if args.direction == "out":
            mask = df["src_ip_addr"] == args.ip
            steps.append(f"mask = df['src_ip_addr'] == {args.ip!r}")
        elif args.direction == "in":
            mask = df["dst_ip_addr"] == args.ip
            steps.append(f"mask = df['dst_ip_addr'] == {args.ip!r}")
        else:  # both
            mask = (df["src_ip_addr"] == args.ip) | (df["dst_ip_addr"] == args.ip)
            steps.append(
                f"mask = (df['src_ip_addr'] == {args.ip!r}) | (df['dst_ip_addr'] == {args.ip!r})"
            )
    else:
        # no ip given: start from every row and let the other filters narrow it.
        mask = pd.Series(True, index=df.index)
        steps.append("mask = pd.Series(True, index=df.index)  # no IP filter")

    if args.peer:
        mask &= (df["src_ip_addr"] == args.peer) | (df["dst_ip_addr"] == args.peer)
        steps.append(
            f"mask &= (df['src_ip_addr'] == {args.peer!r}) | (df['dst_ip_addr'] == {args.peer!r})"
        )

    if args.port is not None:
        mask &= (df["src_port"] == args.port) | (df["dst_port"] == args.port)
        steps.append(
            f"mask &= (df['src_port'] == {args.port}) | (df['dst_port'] == {args.port})"
        )

    sub = df[mask]
    steps.append("sub = df[mask]")

    if args.query:
        sub = sub.query(args.query)
        steps.append(f"sub = sub.query({args.query!r})")

    # print the recipe so the result is fully reproducible / teachable.
    section("PANDAS COMMANDS (copy these to reproduce)")
    print("import pandas as pd")
    for s in steps:
        print(s)

    # quick totals for the slice.
    section(f"RESULT - {len(sub):,} matching rows in {csv_file.name}")
    if sub.empty:
        # help the user recover: say which ip is missing and suggest fixes.
        print("No rows matched. Likely causes:")
        if args.ip:
            suggest_similar_ips(df, args.ip)
        if args.peer:
            suggest_similar_ips(df, args.peer)
        if args.port is not None:
            print(f"  [i] also check port {args.port} is correct.")
        return
    print(f"raw bytes:     {sub['num_octets'].sum():,}")
    print(f"raw packets:   {sub['num_pkts'].sum():,}")
    n_samp = sampled_rows(sub)
    if n_samp and has_cols(sub, "eff_octets", "eff_pkts"):
        print(f"eff. bytes:    {int(sub['eff_octets'].sum()):,}   "
              f"(sampling-adjusted; {n_samp:,} sampled rows)")
        print(f"eff. packets:  {int(sub['eff_pkts'].sum()):,}")
    print(f"time span:     {sub['start_time'].min()}  ->  {sub['start_time'].max()}")

    # top peers in this slice (the "other end" of each flow). only makes sense
    # when a target ip is anchoring one end of the flow.
    if not sub.empty and args.ip:
        section("TOP PEERS IN THIS SLICE (other end of the flow)")
        peer = sub["src_ip_addr"].where(sub["src_ip_addr"] != args.ip, sub["dst_ip_addr"])
        if has_cols(sub, "src_cc", "dst_cc"):
            peer_cc = sub["src_cc"].where(sub["src_ip_addr"] != args.ip, sub["dst_cc"])
            breakdown = pd.DataFrame({"peer": peer, "cc": peer_cc}).value_counts().head(15)
        else:
            breakdown = peer.value_counts().head(15)
        print(breakdown.to_string())

    # the actual rows (index = line position in the csv).
    cols = args.columns.split(",") if args.columns else None
    view = sub[cols] if cols else sub
    section(f"ROWS (showing up to {args.head})")
    with pd.option_context("display.max_columns", None, "display.width", 200):
        print(view.head(args.head).to_string(index=True))
    print(f"\n(row index numbers above are the line positions in {csv_file.name})")


# ----------------------------------------------------------------------
# mode 1: full report - the whole nfx-style workup in one pass
# ----------------------------------------------------------------------
def run_report(args: argparse.Namespace) -> None:
    target_ip = args.ip
    csv_file = Path(args.file)
    df = load(csv_file)

    if not warn_if_bad_ip("target IP", target_ip):
        return

    out = df[df["src_ip_addr"] == target_ip].copy()   # traffic FROM the ip
    inc = df[df["dst_ip_addr"] == target_ip].copy()   # traffic TO the ip
    both = pd.concat([out, inc])

    if both.empty:
        print(f"No flows found for {target_ip} in {csv_file.name}")
        suggest_similar_ips(df, target_ip)
        return

    subnet = subnet16(target_ip)
    has_cc = has_cols(df, "src_cc", "dst_cc")
    eff_ok = has_cols(both, "eff_octets")
    n_samp = sampled_rows(both)

    # call out any nfx-grade columns that are missing, so you know a section was
    # skipped on purpose rather than the tool quietly eating your data.
    missing = [c for c in ("proto", "client_ip_addr", "server_ip_addr") if c not in df.columns]
    if missing:
        print(f"  [i] columns not in this CSV: {', '.join(missing)} - "
              f"authoritative role section skipped, role will be inferred instead.")
    if n_samp:
        print(f"  [i] sampling detected: {n_samp:,} of {len(both):,} flows for this IP "
              f"are sampled. Volume figures below are sampling-adjusted (eff_*).")

    # ---- overview + first-pass role guess ----
    section(f"OVERVIEW for {target_ip}")
    print(f"file:          {csv_file.name}")
    print(f"total flows:   {len(both):,}  (out: {len(out):,}, in: {len(inc):,})")
    print(f"time span:     {both['start_time'].min()}  ->  {both['start_time'].max()}")
    if eff_ok and n_samp:
        print(f"bytes out:     raw {out['num_octets'].sum():,}   "
              f"eff {int(out['eff_octets'].sum()):,}   packets out (raw): {out['num_pkts'].sum():,}")
        print(f"bytes in:      raw {inc['num_octets'].sum():,}   "
              f"eff {int(inc['eff_octets'].sum()):,}   packets in (raw):  {inc['num_pkts'].sum():,}")
    else:
        print(f"bytes out:     {out['num_octets'].sum():,}   packets out: {out['num_pkts'].sum():,}")
        print(f"bytes in:      {inc['num_octets'].sum():,}   packets in:  {inc['num_pkts'].sum():,}")
    ratio = len(out) / max(len(inc), 1)
    print(f"out/in ratio:  {ratio:.2f}")
    if ratio > 2:
        print("  [!] target initiates far more than it receives - scanner / C2-controller behavior")
    elif ratio < 0.5:
        print("  [!] target receives far more than it sends - server / listening-infrastructure role")

    # ---- protocol breakdown (needs `proto`) ----
    if has_cols(both, "proto"):
        section("PROTOCOL BREAKDOWN")
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP"}
        counts = both["proto"].value_counts()
        for proto, c in counts.items():
            name = proto_map.get(proto, f"proto-{proto}")
            pct = c / len(both) * 100
            tag = "  [!] unexpected tunnel proto" if proto in (47, 50) else ""
            print(f"  {str(proto):<5} {name:<6} {c:>10,}  {pct:>5.1f}%{tag}")

    # ---- peers (z-score outliers flagged, volume on effective octets) ----
    section("TOP PEERS (remote IPs, z-score outliers flagged)")
    vol_col = "eff_octets" if eff_ok else "num_octets"
    peers = both.assign(
        peer=lambda d: d["src_ip_addr"].where(d["src_ip_addr"] != target_ip, d["dst_ip_addr"]),
    )
    if has_cc:
        peers = peers.assign(
            peer_cc=lambda d: d["src_cc"].where(d["src_ip_addr"] != target_ip, d["dst_cc"]),
        )
        group_keys = ["peer", "peer_cc"]
    else:
        group_keys = ["peer"]
    peer_stats = (
        peers.groupby(group_keys)
        .agg(flows=("peer", "size"), octets=(vol_col, "sum"), pkts=("num_pkts", "sum"))
        .sort_values("flows", ascending=False)
    )
    f_mean, f_std = peer_stats["flows"].mean(), peer_stats["flows"].std()
    b_mean, b_std = peer_stats["octets"].mean(), peer_stats["octets"].std()
    f_thr = f_mean + 2 * f_std if pd.notna(f_std) else None
    b_thr = b_mean + 2 * b_std if pd.notna(b_std) else None
    for keys, row in peer_stats.head(20).iterrows():
        peer_ip = keys[0] if isinstance(keys, tuple) else keys
        marks = []
        if f_thr is not None and row["flows"] > f_thr:
            marks.append("[!] flow-outlier")
        if b_thr is not None and row["octets"] > b_thr:
            marks.append("[!] volume-outlier")
        if subnet and isinstance(peer_ip, str) and peer_ip.startswith(subnet) and peer_ip != target_ip:
            marks.append("[PIVOT]")
        cc = f" {keys[1]:<3}" if isinstance(keys, tuple) and len(keys) > 1 else ""
        print(f"  {peer_ip:<18}{cc} flows={row['flows']:>6,} bytes={int(row['octets']):>12,} "
              f"pkts={row['pkts']:>9,} {' '.join(marks)}")
    if eff_ok and n_samp:
        print("  (bytes column is sampling-adjusted)")

    # ---- client/server role: authoritative if the columns exist, else inferred ----
    if has_cols(df, "client_ip_addr", "server_ip_addr"):
        section("CLIENT vs SERVER ROLE (authoritative)")
        as_client = df[df["client_ip_addr"] == target_ip]
        as_server = df[df["server_ip_addr"] == target_ip]
        print(f"target as CLIENT (initiator): {len(as_client):,} flows")
        print(f"target as SERVER (responder): {len(as_server):,} flows")
        if len(as_client):
            print("\n  connects OUT to (top 10):")
            top = as_client.groupby("server_ip_addr").size().sort_values(ascending=False).head(10)
            for ip, c in top.items():
                piv = " [PIVOT]" if subnet and str(ip).startswith(subnet) else ""
                print(f"    {ip:<18} {c:>8,} flows{piv}")
        if len(as_server):
            print("\n  receives IN from (top 10):")
            top = as_server.groupby("client_ip_addr").size().sort_values(ascending=False).head(10)
            for ip, c in top.items():
                piv = " [PIVOT]" if subnet and str(ip).startswith(subnet) else ""
                print(f"    {ip:<18} {c:>8,} flows{piv}")
    else:
        section("CLIENT vs SERVER ROLE (inferred from ports + SYN direction)")
        print("no authoritative client/server columns - inferring per flow "
              "(SYN direction first, then service vs ephemeral port).\n")
        role = infer_role(both, target_ip)
        counts = role.value_counts()
        print(f"target as CLIENT (initiator): {int(counts.get('client', 0)):,} flows")
        print(f"target as SERVER (responder): {int(counts.get('server', 0)):,} flows")
        print(f"undetermined:                 {int(counts.get('unknown', 0)):,} flows")

        peer_all = both["src_ip_addr"].where(both["src_ip_addr"] != target_ip, both["dst_ip_addr"])
        client_mask = (role == "client").values
        server_mask = (role == "server").values
        if client_mask.any():
            print("\n  connects OUT to as client (top 10):")
            top = peer_all[client_mask].value_counts().head(10)
            for ip, c in top.items():
                piv = " [PIVOT]" if subnet and str(ip).startswith(subnet) else ""
                print(f"    {str(ip):<18} {c:>8,} flows{piv}")
        if server_mask.any():
            print("\n  receives IN from as server (top 10):")
            top = peer_all[server_mask].value_counts().head(10)
            for ip, c in top.items():
                piv = " [PIVOT]" if subnet and str(ip).startswith(subnet) else ""
                print(f"    {str(ip):<18} {c:>8,} flows{piv}")

    # ---- operator pivot: target dialing OUT on management / analytics ports ----
    # loud victims are easy; the quiet admin session is where the human is.
    if len(out):
        op_out = out[out["dst_port"].isin(OPERATOR_PORTS)]
        section("OPERATOR PIVOT (target connects OUT on management ports)")
        if op_out.empty:
            print("  none - target did not initiate SSH/Telnet/RDP/ClickHouse/DB "
                  "connections in this capture.")
        else:
            print("outbound management sessions suggest operator hop points, not victims.\n")
            grp = op_out.groupby("dst_ip_addr")
            summary = grp.agg(
                flows=("dst_port", "size"),
                ports=("dst_port", lambda s: sorted(set(s))),
                first=("start_time", "min"),
                last=("start_time", "max"),
            ).sort_values("flows", ascending=False)
            for ip, row in summary.head(15).iterrows():
                labelled = ",".join(f"{p}/{OPERATOR_PORTS.get(p, '?')}" for p in row["ports"])
                cc = ""
                if has_cc:
                    ccv = out.loc[out["dst_ip_addr"] == ip, "dst_cc"].dropna()
                    cc = f" {ccv.iloc[0]:<3}" if len(ccv) else ""
                piv = " [PIVOT]" if subnet and str(ip).startswith(subnet) else ""
                print(f"  [OP] {str(ip):<18}{cc} flows={row['flows']:>5,} "
                      f"ports={labelled:<24} {row['first']} -> {row['last']}{piv}")

    # ---- low-frequency talkers (operator fingerprint candidates) ----
    section("LOW-FREQUENCY COMMUNICATORS (operator fingerprint candidates)")
    print("peers with very few flows stand out from a noisy victim pool. "
          "operators log in rarely; victims beacon constantly.\n")
    lf = peer_stats[peer_stats["flows"] <= 5].sort_values("flows")
    if lf.empty:
        print("  none under the 5-flow threshold.")
    else:
        shown = 0
        for keys, row in lf.iterrows():
            peer_ip = keys[0] if isinstance(keys, tuple) else keys
            # what ports did this quiet peer touch? a management port here is a tell.
            pmask = (both["src_ip_addr"] == peer_ip) | (both["dst_ip_addr"] == peer_ip)
            ports = pd.concat([both.loc[pmask, "src_port"], both.loc[pmask, "dst_port"]])
            svc_ports = sorted({int(p) for p in ports.dropna() if int(p) in SERVICE_PORT_SET})
            tag = ""
            if any(p in OPERATOR_PORTS for p in svc_ports):
                tag = " [OP] management port"
            cc = f" {keys[1]:<3}" if isinstance(keys, tuple) and len(keys) > 1 else ""
            plist = ",".join(str(p) for p in svc_ports) if svc_ports else "-"
            print(f"  {str(peer_ip):<18}{cc} flows={int(row['flows']):>3} "
                  f"svc_ports={plist:<18}{tag}")
            shown += 1
            if shown >= 20:
                break

    # ---- ports ----
    section("DESTINATION PORTS (services being reached)")
    for port, c in both["dst_port"].value_counts().head(15).items():
        svc = WELL_KNOWN_PORTS.get(port, "unknown")
        print(f"  {str(port):<7} {svc:<16} {c:>8,}")

    if len(out):
        section("OUTBOUND DESTINATION PORTS (where target connects TO)")
        for port, c in out["dst_port"].value_counts().head(15).items():
            svc = WELL_KNOWN_PORTS.get(port, "unknown")
            tag = ""
            if port in C2_PORTS:
                tag = "  [C2] known framework port"
            elif port in OPERATOR_PORTS:
                tag = "  [OP] management port"
            print(f"  {str(port):<7} {svc:<16} {c:>8,}{tag}")

    section("SOURCE PORTS")
    print(both["src_port"].value_counts().head(15).to_string())

    # ---- tcp flags + syn-scan detection ----
    if has_cols(both, "tcp_flags"):
        section("TCP FLAGS")
        print("note: a netflow flags value is the UNION of flags over the packets "
              "aggregated into that flow (Part 5), so e.g. 18 need not be a single\n"
              "clean SYN+ACK. Single-packet flows (num_pkts == 1) are unambiguous.\n")
        tcp = both[both["proto"] == 6] if has_cols(both, "proto") else both
        flag_summary = tcp["tcp_flags"].apply(decode_flags).value_counts()
        print(flag_summary.to_string())
        n_tcp = len(tcp)
        if n_tcp:
            syn_only = tcp[tcp["tcp_flags"] == 2]
            syn_ratio = len(syn_only) / n_tcp * 100
            print(f"\nSYN-only: {len(syn_only):,} of {n_tcp:,} TCP flows ({syn_ratio:.1f}%)")
            if syn_ratio > 20:
                print("  [!] high SYN-only ratio - possible SYN scanning / flood")
            syn_from = syn_only[syn_only["src_ip_addr"] == target_ip]
            if len(syn_from) > 100:
                print(f"  [!] target sent {len(syn_from):,} SYN-only - ACTIVE SCANNING. Top targets:")
                for ip, c in syn_from["dst_ip_addr"].value_counts().head(5).items():
                    print(f"      {ip}: {c:,}")
            # multi-packet syn-only = retransmitted syns = nobody answered.
            # the far end was filtered, dead, or simply ghosting the handshake.
            if has_cols(syn_only, "num_pkts"):
                retrans = syn_only[syn_only["num_pkts"] > 1]
                if len(retrans):
                    print(f"  [!] {len(retrans):,} SYN-only flows carried >1 packet "
                          f"(retransmitted SYNs - handshake not completing / dead space).")
            rst = tcp[tcp["tcp_flags"].isin([4, 20])]
            if len(rst):
                rst_from = rst[rst["src_ip_addr"] == target_ip]
                print(f"RST/RST+ACK: {len(rst):,} ({len(rst_from):,} from target - rejecting connections)")

    # ---- activity by hour + timezone guess ----
    section("ACTIVITY BY HOUR (UTC) + TIMEZONE INFERENCE")
    hours = both["start_time"].dropna().dt.hour
    if len(hours):
        hourly = hours.value_counts().reindex(range(24), fill_value=0)
        peak = max(hourly.max(), 1)
        for h in range(24):
            bar = "#" * int(hourly[h] / peak * 30)
            print(f"  {h:>2}h {hourly[h]:>7,} {bar}")
        peak_hours = hourly.nlargest(6).index.tolist()
        avg_peak = sum(peak_hours) / len(peak_hours)
        offset = 14 - avg_peak  # assume the busy hours sit around 14:00 local
        if -2 <= offset <= 4:
            region = "Europe (UTC+0..+3)"
        elif 5 <= offset <= 9:
            region = "Americas (UTC-5..-9)"
        elif -5 <= offset <= -3:
            region = "East Asia (UTC+5..+8)"
        else:
            region = f"uncertain (~UTC{offset:+.0f})"
        print(f"\n  peak UTC hours: {sorted(peak_hours)}")
        print(f"  [!] inferred operator timezone: {region}  (low confidence)")

        dow = both["start_time"].dropna().dt.day_name().value_counts()
        print("\n  activity by day of week:")
        for day in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]:
            print(f"    {day:<10} {int(dow.get(day, 0)):>8,}")

    # ---- daily timeline + spike detection (volume on effective octets) ----
    section("DAILY TIMELINE (2-sigma spikes flagged)")
    vol_col = "eff_octets" if eff_ok else "num_octets"
    daily = both.assign(date=both["start_time"].dt.date).groupby("date").agg(
        flows=("num_pkts", "size"),
        pkts=("num_pkts", "sum"),
        octets=(vol_col, "sum"),
        uniq=("src_ip_addr", "nunique"),
    )
    if len(daily):
        d_mean, d_std = daily["flows"].mean(), daily["flows"].std()
        d_thr = d_mean + 2 * d_std if pd.notna(d_std) else None
        peak = max(daily["flows"].max(), 1)
        for date, row in daily.iterrows():
            bar = "#" * int(row["flows"] / peak * 20)
            spike = "  [!] SPIKE" if d_thr is not None and row["flows"] > d_thr else ""
            mb = row["octets"] / (1024 * 1024)
            print(f"  {str(date):<12} flows={row['flows']:>7,} {mb:>8.1f}MB "
                  f"uniq={row['uniq']:>5,} {bar}{spike}")
        if eff_ok and n_samp:
            print("  (MB column is sampling-adjusted)")

    # ---- beaconing + jitter verdicts (cadence stays on RAW rows) ----
    # malware keeps a schedule in a way humans never do; low jitter is the tell.
    section("BEACONING / C2 CHECK (interval regularity per peer)")
    print("jitter = std/mean of inter-arrival gaps; low + short interval => automated beacon.")
    if n_samp:
        print("caution: sampled peers have missing flows, so their intervals are unreliable.")
    print()
    beacon_candidates = []
    rows = []
    for peer_ip, grp in peers.groupby("peer"):
        times = grp["start_time"].dropna().sort_values()
        if len(times) < 4:
            continue
        deltas = times.diff().dropna().dt.total_seconds()
        mean = deltas.mean()
        std = deltas.std()
        if not mean or pd.isna(mean):
            continue
        jitter = (std / mean) * 100 if pd.notna(std) else float("nan")
        peer_sampled = bool((grp.get("samp_mult", pd.Series([1])) > 1).any())
        verdict = ""
        if peer_sampled:
            verdict = "[i] sampled - interval unreliable"
        elif pd.notna(jitter) and jitter < 40 and mean < 7200:
            verdict = "[C2] LIKELY beacon"
            beacon_candidates.append(peer_ip)
        elif pd.notna(jitter) and jitter < 60 and mean < 3600:
            verdict = "[C2] POSSIBLE beacon"
            beacon_candidates.append(peer_ip)
        elif len(times) > 100:
            verdict = "[!] high frequency"
        rows.append((peer_ip, len(times), mean, std, jitter, verdict))
    # beacon candidates first, then everyone else by flow count.
    rows.sort(key=lambda r: (r[5] == "", -r[1]))
    for peer_ip, n, mean, std, jitter, verdict in rows[:20]:
        jstr = f"{jitter:>5.0f}%" if pd.notna(jitter) else "   -"
        print(f"  {peer_ip:<18} n={n:>5} mean={mean:>8.1f}s std={std:>8.1f}s "
              f"jitter={jstr} {verdict}")

    # ---- high-volume victims: the inbound outliers, i.e. who's bleeding data ----
    if len(inc):
        section("POTENTIAL VICTIMS (inbound z-score outliers)")
        vcol = "eff_octets" if eff_ok else "num_octets"
        agg = {
            "flows": ("num_pkts", "size"),
            "pkts": ("num_pkts", "sum"),
            "octets": (vcol, "sum"),
            "first": ("start_time", "min"),
            "last": ("start_time", "max"),
        }
        victims = inc.groupby("src_ip_addr").agg(**agg)
        vb_mean, vb_std = victims["octets"].mean(), victims["octets"].std()
        vf_mean, vf_std = victims["flows"].mean(), victims["flows"].std()
        if pd.notna(vb_std) and pd.notna(vf_std):
            flagged = victims[
                (victims["octets"] > vb_mean + 2 * vb_std)
                | (victims["flows"] > vf_mean + 2 * vf_std)
            ].sort_values("octets", ascending=False)
            print(f"thresholds: bytes>{vb_mean + 2*vb_std:,.0f}  flows>{vf_mean + 2*vf_std:,.0f}")
            print(f"IPs over threshold: {len(flagged)}\n")
            for ip, row in flagged.head(20).iterrows():
                marks = []
                if row["octets"] > vb_mean + 3 * vb_std:
                    marks.append("[!] EXTREME-VOL")
                if row["flows"] > vf_mean + 3 * vf_std:
                    marks.append("[!] EXTREME-FREQ")
                if subnet and str(ip).startswith(subnet):
                    marks.append("[PIVOT]")
                days = (row["last"] - row["first"]).days
                if days >= 14 and row["flows"] >= 50:
                    marks.append("[C2] PERSISTENT")
                mb = row["octets"] / (1024 * 1024)
                print(f"  {ip:<18} flows={row['flows']:>6,} {mb:>9.2f}MB "
                      f"dur={days:>3}d {' '.join(marks)}")
        else:
            print("  [i] too few inbound peers for a stable z-score.")
        if has_cc:
            print("\n  source-country distribution (inbound):")
            for cc, c in inc["src_cc"].value_counts().head(15).items():
                print(f"    {str(cc):<4} {c:>7,}")

    # ---- summary / marker legend ----
    section("SUMMARY")
    print(f"target:              {target_ip}")
    print(f"observation window:  {both['start_time'].min()}  ->  {both['start_time'].max()}")
    print(f"beacon candidates:   {len(beacon_candidates)}")
    if n_samp:
        print(f"sampled flows:       {n_samp:,} (volume figures sampling-adjusted)")
    print("markers: [!] statistical anomaly  [PIVOT] /16 infra link  "
          "[C2] behavioral C2 indicator  [OP] operator/management fingerprint")


def build_query_parser() -> argparse.ArgumentParser:
    """parser for what you type at the flow> prompt (the file is already loaded)."""
    p = argparse.ArgumentParser(
        prog="flow",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    p.add_argument("ip", nargs="?", default=None, help="target IP (optional)")
    p.add_argument("--direction", choices=["in", "out", "both"], default="both",
                   help="filter by traffic direction relative to target IP")
    p.add_argument("--peer", help="only flows between target and this peer IP")
    p.add_argument("--port", type=int, help="only flows where src_port OR dst_port == PORT")
    p.add_argument("-q", "--query", help="extra pandas df.query() expression")
    p.add_argument("-n", "--head", type=int, default=20, help="rows to display in query mode")
    p.add_argument("--columns", help="comma-separated columns to display in query mode")
    return p


def dispatch(args: argparse.Namespace) -> None:
    """route one parsed query to the right mode."""
    filters = args.peer or args.port is not None or args.query or args.direction != "both"
    if filters:
        run_query(args)
    elif args.ip:
        run_report(args)
    else:
        print("  [i] Give a target IP (e.g. 198.51.100.23) for a full report, "
              "or a filter like --port 22 / --peer <ip> / --query \"...\".")


def main() -> None:
    launch = argparse.ArgumentParser(
        description="draig - point it at one netflow csv; it profiles whatever ip lives inside.",
    )
    launch.add_argument("file", help="netflow CSV file to investigate")
    # anything after the filename is treated as an immediate first query.
    known, rest = launch.parse_known_args()

    csv_file = Path(known.file)
    if not csv_file.exists():
        print(f"file not found: {csv_file}")
        sys.exit(1)

    qp = build_query_parser()

    # optional one-shot: `draig.py flows.csv 198.51.100.23 --port 22`
    if rest:
        try:
            args = qp.parse_args(rest)
            args.file = str(csv_file)
            dispatch(args)
        except SystemExit:
            pass

    interactive_loop(csv_file)


def interactive_loop(csv_file: Path) -> None:
    """stay open and take more queries against the loaded file.

    type new args (e.g. '198.51.100.23 --port 443', '--peer 203.0.113.10 -n 30',
    or just an ip). hit enter on an empty line, or type 'q'/'quit', to bail out.
    """
    parser = build_query_parser()
    print(f"\nDraiG loaded: {csv_file.name}")
    print("Interactive mode - type query args (e.g. '198.51.100.23', '--port 443', "
          "'--peer <ip>'), '-h' for options, or 'q' to quit.")
    while True:
        try:
            line = input("\nflow> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line or line.lower() in {"q", "quit", "exit"}:
            break
        try:
            args = parser.parse_args(shlex.split(line))
        except SystemExit:
            # argparse calls sys.exit() on bad input; swallow it so the loop lives.
            continue
        args.file = str(csv_file)
        dispatch(args)


if __name__ == "__main__":
    main()
