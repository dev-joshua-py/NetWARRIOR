# Defending Against These Techniques

NetWARRIOR exists so defenders can see what each attack looks like on the wire and
practise stopping it. This file pairs every attack category in the tool with
**how to detect it** and **how to mitigate it**. Ready-to-load Suricata rules that
fire on this tool's specific signatures are in [`detection/netwarrior.rules`](detection/netwarrior.rules).

If you only do three things: enable **BCP38/uRPF egress filtering** so your
network cannot source spoofed packets, put **SYN cookies + connection limits** in
front of every TCP service, and turn on the **Layer-2 guards** (DAI, DHCP
snooping, BPDU guard, RA Guard) on your access switches.

---

## 1. Volumetric floods — SYN / ACK / RST / FIN / XMAS / NULL / UDP / ICMP / zero-window

**On the wire:** a high packet rate from many source addresses (often randomised
and spoofed), tiny packets, TCP flag combinations that never occur in real
traffic (SYN+FIN, FIN+PSH+URG, no flags), or a flood of ACK/RST that match no
existing connection. SYN floods leave a growing pile of half-open connections.

**Detect**
- `netstat -ant | grep SYN_RECV | wc -l` climbing; `nstat -az TcpExtListenOverflows TcpExtListenDrops`.
- NetFlow/IPFIX: packets-per-flow ≈ 1, bytes-per-packet ≈ 40–60, fan-in to one dst.
- Suricata `stream` events, `flow` anomaly, or the rules in this repo.
- Interface counters: `rx_packets` rate ≫ normal while `rx_bytes` stays low.

**Mitigate**
- `net.ipv4.tcp_syncookies=1`; raise `tcp_max_syn_backlog`; lower `tcp_synack_retries`.
- conntrack rate limits: `iptables -A INPUT -p tcp --syn -m hashlimit --hashlimit-name syn --hashlimit-above 50/sec --hashlimit-mode srcip -j DROP`.
- Drop invalid state early: `-m conntrack --ctstate INVALID -j DROP` (kills stray ACK/RST/FIN floods).
- Drop nonsense flag combos: `iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP`, `--tcp-flags ALL ALL -j DROP`, `--tcp-flags ALL FIN,PSH,URG -j DROP`.
- Upstream: remote-triggered black hole (RTBH) / flowspec, or a scrubbing provider for anything above your link capacity.

---

## 2. Reflection & amplification — DNS / NTP / SNMP / memcached / SSDP / CHARGEN

**On the wire:** inbound UDP from **source port 53 / 123 / 161 / 11211 / 1900 / 19**
that your hosts never queried, with responses far larger than any request. The
victim is the *spoofed source*; you may be either the reflector (your open
service is being abused) or the target (you are drowning in replies).

**Detect**
- Reflector: outbound UDP spikes from 53/123/161/11211/1900/19 with no matching
  inbound query; `memcached` stats/`get` requests from the internet on 11211.
- Target: inbound UDP from those source ports with no prior outbound flow (stateful
  firewall logs, NetFlow asymmetry), response:request byte ratio > 10.
- Suricata rules in this repo match the exact NTP `monlist` (`17 00 03 2a`),
  SNMP GetBulk, memcached `stats`, and SSDP `M-SEARCH` payloads NetWARRIOR sends.

**Mitigate**
- **BCP38 / uRPF** on every edge so spoofed source packets can't leave — this is
  what makes reflection impossible in the first place.
- Don't run these services on the internet. If you must: bind to localhost,
  firewall UDP 11211/19/1900/161, disable NTP `monlist` (`disable monitor` / NTP ≥ 4.2.8),
  restrict SNMP to a management VLAN with SNMPv3.
- On your resolvers: enable **Response Rate Limiting (RRL)** and refuse `ANY`.
- As a target: rate-limit / drop UDP from those source ports at the edge; ask
  your transit provider or a scrubbing service to filter.

---

## 3. Layer 2 — ARP poison, MAC/CAM flood, VLAN double-tag, CDP/LLDP/STP flood, DHCP starvation

**On the wire:** gratuitous ARP replies rebinding the gateway IP to a new MAC;
thousands of frames with random source MACs (CAM-table overflow → the switch
floods); frames with two 802.1Q tags; a burst of CDP/LLDP/BPDU frames; a flood of
DHCP `DISCOVER`s from random MACs draining the pool.

**Detect**
- `arpwatch` / `arping -D`, or DAI drop counters (`show ip arp inspection statistics`).
- Switch: `show mac address-table count` near the limit; port-security violation logs.
- BPDU Guard / Root Guard syslog; `%SPANTREE-2-BLOCK_BPDUGUARD`.
- DHCP snooping binding-table churn; `%DHCP_SNOOPING-5-DHCP_SNOOPING_...`.
- Host side: default-gateway MAC changing (`ip neigh`), duplicate-address-detected events.

**Mitigate**
- **Dynamic ARP Inspection** + **DHCP Snooping** on all access ports (trust only uplinks).
- **Port-security**: `switchport port-security maximum 2` + `violation restrict`.
- **BPDU Guard** + **Root Guard** on access ports; disable STP only where safe.
- Kill double-tagging: put access ports in `switchport mode access`, disable DTP
  (`switchport nonegotiate`), and never use the native VLAN for user traffic.
- Disable CDP/LLDP on edge ports that don't need it.
- On the host: static ARP for the gateway on critical machines.

---

## 4. IPv6 Neighbor Discovery — Rogue RA / NA / NS floods

**On the wire:** a stream of Router Advertisements (often with random source MACs)
to `ff02::1`, or NA/NS floods thrashing every host's neighbour cache.

**Detect**
- **RA Guard** drop counters; `radvd`/`rdisc6` unexpected-router alerts.
- Host: `ip -6 route` gaining a default via an unknown link-local; ND cache full
  (`ip -6 neigh | wc -l`).

**Mitigate**
- **IPv6 RA Guard** and **ND Inspection** on access switches (or `DHCPv6-Guard`).
- `net.ipv6.conf.<iface>.accept_ra=0` on servers with static addressing.
- Cap the neighbour table: `net.ipv6.neigh.default.gc_thresh{1,2,3}`.
- SEND (RFC 3971) where the platform supports it.

---

## 5. Name-resolution poisoning — LLMNR / NBT-NS / mDNS

**On the wire:** unsolicited answers on **UDP 5355 (LLMNR) / 137 (NBT-NS) /
5353 (mDNS)** claiming to resolve names like `wpad`, mapping them to an attacker
IP so victims send credentials (this is what Responder does).

**Detect**
- Any host answering LLMNR/NBT-NS that isn't a legitimate service.
- Sudden `wpad` / `wpad.dat` lookups; NTLM auth to an unexpected internal IP.
- Suricata rules in this repo flag LLMNR/mDNS answers for `wpad`.
- Deploy an "injected" honey-name and alert if anything ever answers it.

**Mitigate**
- Disable LLMNR (GPO: *Turn off multicast name resolution*), disable NetBIOS over
  TCP/IP on DHCP scopes, disable mDNS where unused.
- Create a real DNS `wpad` record (or block it) so clients stop broadcasting.
- Enable SMB signing and *Extended Protection for Authentication*; require NTLMv2
  or move to Kerberos-only.
- Segment client VLANs so multicast can't reach across the org.

---

## 6. Wireless — deauthentication flood, beacon flood, WPA handshake capture

**On the wire:** 802.11 deauth/disassoc frames (NetWARRIOR uses `reason 7`) sent
to broadcast or a specific client; dozens of beacons for fake SSIDs
(`FreeWiFi`, `Guest`, `Public`, …) from random BSSIDs; a listener parking on a
channel waiting for the 4-way EAPOL handshake.

**Detect**
- WIDS/WIPS deauth-flood and beacon-flood signatures; management-frame rate per BSSID.
- `iw event` / `hostapd` logs showing mass client drops; unknown BSSIDs advertising your ESSID.

**Mitigate**
- **802.11w (Protected Management Frames)** — makes deauth/disassoc floods
  ineffective. Require it (WPA3 does).
- WPA2/WPA3 with a strong PSK or 802.1X (so a captured handshake isn't crackable);
  rotate PSKs.
- A managed WIPS to locate and contain rogue APs / evil twins.

---

## 7. Application layer — Slowloris, RUDY, Slow Read, HTTP flood, HTTP/2 rapid reset, WebSocket flood

**On the wire / in logs:** many concurrent connections from few IPs that send
headers/body one byte at a time and never finish; `X-a:` drip headers or a
lowercase `Accept-language` header (NetWARRIOR's fingerprint); high request rate
to cheap-to-serve paths; for HTTP/2, a storm of `HEADERS` immediately followed by
`RST_STREAM` (CVE-2023-44487).

**Detect**
- `ss -tn state established '( dport = :443 )' | wc -l` per source IP.
- Access log: many `408`/`499`, requests with `$request_time` seconds-long but tiny `$body_bytes_sent`.
- Rising `nginx` `reading`/`waiting` connection states; Apache `mod_status` scoreboard full of `R`.
- HTTP/2: `http2_rst_stream` rate per connection.

**Mitigate**
- Terminate at a **buffering reverse proxy** (nginx buffers the full request
  before touching the backend — Slowloris/RUDY die here).
- `nginx`: `client_header_timeout 5s; client_body_timeout 5s; send_timeout 5s; limit_conn addr 20; limit_req`.
- `apache`: `mod_reqtimeout` (`RequestReadTimeout header=5 body=10`), `mod_qos` / `mod_evasive`.
- HTTP/2: cap concurrent streams (`http2_max_concurrent_streams 128`) and patch
  for rapid-reset; consider `keepalive_requests` limits.
- A WAF / CDN with rate-limiting and bot management for L7 volumetrics.

---

## 8. Legacy / spoofing — LAND, Smurf, Teardrop, Ping of Death, GRE spoof, PCAP replay

Mostly museum pieces (patched since the late 1990s), but worth confirming:

**Mitigate**
- `net.ipv4.icmp_echo_ignore_broadcasts=1` and drop directed broadcasts on routers (Smurf).
- Anti-spoofing ACLs / uRPF drop `src == dst` (LAND) and packets whose source is
  yours arriving from outside.
- Keep kernels current (Teardrop/PoD reassembly bugs); firewall unexpected
  protocol 47 (GRE).
- Egress filtering again — a replayed capture with your source addresses should
  never leave a neighbouring network.

---

## 9. Reconnaissance — port scan, OS fingerprint, SSDP discovery, ARP/ICMP sweep

**Detect**
- Connection attempts to many ports / many hosts in a short window (Suricata
  `stream-events`, Zeek `scan.log`, or firewall "half-open" counters).
- Honeypot / darknet hits — nothing legitimate scans unused space.
- Sudden SSDP `M-SEARCH` from a single internal host.

**Mitigate**
- Default-deny firewalls; minimise exposed ports; put management behind a VPN.
- Rate-limit new connections per source; tarpit or drop after N port hits.
- Don't leak version banners you don't need to.

---

## 10. Credential attacks — SSH / FTP / HTTP Basic brute force, `sshexec`

**Detect**
- Auth-failure rate per source/account (`/var/log/auth.log`, `lastb`, web `401` rate).
- `fail2ban` / `sshguard` / `wtmp` anomalies; impossible-travel logins; success
  immediately after a burst of failures.
- FTP `530` storms; repeated HTTP `401` then a `200` from the same IP.

**Mitigate**
- SSH: key-only (`PasswordAuthentication no`), non-default account names, `AllowUsers`,
  `MaxAuthTries 3`, `fail2ban`, and ideally behind a bastion / port-knock / VPN.
- FTP: retire it for SFTP/FTPS; disable anonymous; lock accounts after N failures.
- HTTP: rate-limit `/login`, account lockout with backoff, CAPTCHA on failure,
  **MFA**, and alert on credential-stuffing patterns.
- Everywhere: unique strong passwords + a breached-password check.

---

## 11. Phishing simulation server

NetWARRIOR's harvester serves a login page and POSTs credentials to `/login`.

**Detect**
- Newly registered look-alike domains (dnstwist, urlscan, CT-log monitoring for
  your brand).
- Outbound POSTs to unknown hosts carrying `username`/`password` form fields
  (DLP / proxy).
- Users reporting a login page that "looked off".

**Mitigate**
- DMARC (`p=reject`), SPF, DKIM; external-sender banners.
- URL rewriting / time-of-click scanning at the mail gateway; block newly seen domains.
- FIDO2 / WebAuthn — phishing-resistant by design.
- Regular user training and an easy "report phish" button.

---

## Using the Suricata rules

```bash
cp detection/netwarrior.rules /etc/suricata/rules/
# add to suricata.yaml:  rule-files: [ ..., netwarrior.rules ]
suricata -T -c /etc/suricata/suricata.yaml    # validate
systemctl reload suricata
```

The rules use the `900xxxx` SID range (local/experimental). They are tuned to
this tool's exact payloads and default strings, so they are precise but not
exhaustive — treat them as a starting point and pair them with the rate-based
detection above.
