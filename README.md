# DRaiG

DRaiG is a tiny, slightly boring, but genuinely helpful NetFlow investigator that I built for the kind of threat hunting where you already have a suspicious IP and now you need to figure out what it has actually been doing all day. You point it at one NetFlow CSV, type a target IP at the `flow>` prompt, and it hands you a full behavioral workup on that host, or, if you would rather trust nothing, the exact rows sitting behind any finding so you can check the tool's homework insetad of taking its word for it. Nothing about the target is baked into the script, so you can keep interrogating the same capture over and over without paying to re-read the file every single time.

The whole point is that a capture has a story buried in it, and most of that story lives in the shape of the traffic rather than in any one row. A box that quietly pushes far more data out than it takes back in, while a crowd of little connections keep dialing into it, is usually not some polite client checking its email; more often it is a server handing payloads and tasking down to a pool of victims. DRaiG exists to surface that shape fast so you can spend your actual brain on the intersting part.

## What it does when you give it an IP

Hand DRaiG just an IP and it runs the full report top to bottom: an overview with the out to in ratio and a first guess at whether youre looking at a client, a server, or something noisier; the protocol mix; the top peers with the statistical outliers flagged; a client versus server split; an operator pivot section; the quiet low frequency talkers; the ports; the TCP flag story including SYN scanning; an hour by hour activity chart with a very humble timezone guess; a daily timeline that flags spikes; a per peer beaconing check; and finally the inbound heavy hitters that look like victims. It is a lot of sections, I know, but they print in the order I actually read a capture, so you can bail out the second the picture gets clear.

## What it does when you add a filter

The moment you add `--port`, `--peer`, `--query`, or `--direction`, DRaiG flips into query mode and pulls the specific rows instead of the summary. It also prints the exact pandas commands it used to get there, partly so the result is reproducible and partly because I kept forgetting my own filter sytnax and wanted the tool to just teach it back to me. You can leave the IP out completely and slice the whole capture by port or peer, which is lovely when you want every SSH flow in the file rather than one host's worth.

## Quick start

```bash
python draig.py flows.csv
```

Then at the prompt:

```
flow> 198.51.100.23              # full report on an IP
flow> 198.51.100.23 --port 22    # just the SSH rows for that IP
flow> --port 443                 # every HTTPS flow in the capture
flow> --peer 203.0.113.10 -n 30  # all flows between target and this peer
flow> -h                         # help
flow> q                          # quit
```

The target IP itself usually falls out of a threat intel source, and an `ip:port` IOC lookup on ThreatFox is a solid way to pick one, ideally somewhere away from the giant cloud ASNs so you actually get some flow volume worth staring at. Every address in these examples comes from the RFC 5737 documentaton ranges, so none of them point at a real host and you can copy paste them freely without accidentally aiming the tool at your neighbour.

## The markers

Scattered through the report youll see little tags in square brackets. They exist so your eye can jump straight to the bits that matter withuot reading every single line:

| Marker | Meaning |
|--------|---------|
| `[!]` | Statistical anomaly (a ratio or z-score threshold got crossed) |
| `[PIVOT]` | Peer shares the target's /16, so it may be sibling infrastructure |
| `[C2]` | Behavioral C2 indicator (beaconing, persistence, known framework port) |
| `[OP]` | Operator or management fingerprint (SSH, Telnet, RDP, ClickHouse, DB) |

## The CSV it expects

DRaiG reads a flat NetFlow CSV and tries pretty hard not to fall over when a column is missing. The columns it is happiest with are:

```
start_time, src_ip_addr, src_cc, dst_ip_addr, dst_cc, proto,
src_port, dst_port, tcp_flags, num_pkts, num_octets,
sample_algo, sample_interval
```

If your file also carries `client_ip_addr` and `server_ip_addr`, DRaiG will trust those for the role split, which is the properly accurate way to do it. If they are missing, and in a lot of real captures they are, it quietly falls back to inferring the role and tells you plainly that it did so rather than pretending it knew all along. The country code columns get pulled in for enrichment whenver they happen to be present.

## What I changed in this version

This is where most of the recent effort went, mostly because the first cut of DRaiG assumed a much tidier file than the ones that actually land on my disk.

### Sampling actually counts now

Collectors love to keep only one packet in every N to save space, and if you ignore that you end up comparing a whole apple to a single thin slice of one. When a flow carries a sample_interval of 4096, that one row is really standing in for roughly four thousand flows, so the raw byte and packet numbers come out laughably low. DRaiG now works out the multiplier at load time and builds effective byte and packet columns from it, then uses those effective figures everywhere volume matters, while deliberately leaving the timing checks on the raw rows. The reason for that split is simple enough: sampling throws away whole flows, and you cannot rebuild a beacon's heartbeat from a recording thats full of holes.

### It guesses client versus server when it has to

Plenty of captures turn up without the authoritative client and server columns, so DRaiG infers the roles from whatever evidance it does have. A lone SYN travels from client to server, so whoever fired it is the client, and that signal wins outright. When there is no SYN to lean on it falls back to the ports, because the low well known port is almost always the service while the big number up in the ephemeral range belongs to whoever dialed in. It is a heuristic and not scripture, but it agrees with reality often enough to earn its keep, and it stays honest about the handful of flows it could not confidently call.

### Operator pivots get their own section

Victims are loud and operators are quiet, and that whole asymmetry is basically the game. This section pulls out every host the target reached out to on a managment or analytics port, so your SSH, Telnet, RDP, plus the ClickHouse and database ports, because an outbound admin session is far more likely to be an operator hop point than some victim. Those are exactly the IPs you want to feed into VirusTotal and Shodan next, so the tool rounds them up in one place instead of making you scroll for them.

### Low frequency talkers get surfaced too

Because the victim pool tends to bury everything under sheer volume, the interesting operator style connections often hide down in the long tail with only a handful of flows each. DRaiG lists the quiet peers and flags any that touched a management port, which leaves you with a short, human sized list of operator fingerprint candidates to chase instead of the entire firehsoe.

### The TCP flags come with a health warning

A NetFlow flags value is the union of every flag seen across the packets that got squashed into that one flow, which means a value like 18 is not automatically a clean SYN plus ACK once more than one packet is in play. The report says as much out loud, and it separately calls out SYN only flows that somehow carried more than one packet, since that usually means retransmitted SYNs where the handshkae never finished, which is the polite way of saying the far end was filtered, dead, or simply never home.

## How the sections line up with an actual hunt

Rougly the order I work in, which is also roughly the order the report prints:

1. Skim the port sections to see what the host exposes and what it reaches for.
2. Read beaconing and victims to size the pool and feel out any C2 rhythm.
3. Scan the low frequency talkers for operator candidates.
4. Pull SSH, Telnet, and ClickHouse hop points from the operator pivot section.
5. Take those pivots into VirusTotal, Shodan, and ThreatFox for enrichment.
6. Build the infrastructure map from cert reuse, passive DNS, and /16 clustering.

## A few honest limits

The timezone guess is a rough heuristic and the report labels it low confidence, so please treat it as a lead and not a fact. Beaconing verdicts on sampled peers get marked unreliable, because their intervals have gaps punched through them. DRaiG only ever reads metadata, it never touches payloads, and it makes no outbound connections of its own, wich is very much on purpose. Everything runs locally against a single CSV, so bring your own capture.

## Requirements

Python 3.9 or newer, plus pandas and numpy.

```bash
pip install pandas numpy
```

Thats the whole thing. If it saves you ten minutes of squinting at a spreadsheet, it has done its job.
