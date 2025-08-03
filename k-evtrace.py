#!/usr/bin/env python3

"""
k-evtrace - Python tool that applies Sigma rules to Kaspersky EVTX logs,
extracting detections, and IOCs. Saves the results in Hayabusa-compatible
format.

---

MIT License

Copyright (c) 2025 Cristian Souza

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
import sys
import csv
import re
import json
import time
import argparse
import concurrent.futures
import xml.etree.ElementTree as ET
from pathlib import Path
from multiprocessing import cpu_count
from datetime import datetime, timezone
from collections import defaultdict, Counter

import yaml
import requests
from functools import lru_cache
from Evtx.Evtx import Evtx
from tqdm import tqdm
from tabulate import tabulate

VERSION = "0.0.1"
RULE_DEFS = None

VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
OPENTIP_API_URL = "https://opentip.kaspersky.com/api/v1/search/hash?request={hash}"


def color_text(text, level):
    """
    Applies ANSI color codes to text based on severity level.
    """
    color_map = {
        'emerg': '\033[91m',
        'crit': '\033[91m',
        'high': '\033[33m',
        'med': '\033[93m',
        'low': '\033[92m',
        'info': '',
    }
    reset = '\033[0m'
    color = color_map.get(level, '')
    return f"{color}{text}{reset}" if color else text


def init_worker(rule_defs):
    """
    Initializes the global rule definition for each process worker.
    """
    global RULE_DEFS
    RULE_DEFS = rule_defs


@lru_cache(maxsize=1024)
def lookup_vt(hash_value, api_key):
    """Fetch VT stats for a hash; return 'malicious/total' or 'N/A'."""
    try:
        r = requests.get(
            VT_API_URL.format(hash=hash_value),
            headers={"x-apikey": api_key},
            timeout=15
        )
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        det = stats.get("malicious", 0) + stats.get("suspicious", 0)
        tot = sum(stats.get(k, 0) for k in stats)
        return f"{det}/{tot}"
    except requests.HTTPError as e:
        if e.response and e.response.status_code == 404:
            return "N/A"
    except Exception:
        pass
    return ""


@lru_cache(maxsize=1024)
def lookup_opentip(hash_value, api_key):
    """Fetch OpenTIP status for a hash; return status or 'N/A'."""
    try:
        r = requests.get(
            OPENTIP_API_URL.format(hash=hash_value),
            headers={"x-api-key": api_key},
            timeout=15
        )
        r.raise_for_status()
        data = r.json()
        return data.get("FileGeneralInfo", {}).get("FileStatus", "N/A")
    except requests.HTTPError as e:
        if e.response and e.response.status_code == 404:
            return "N/A"
    except Exception:
        pass
    return ""


def build_tests(block_dict):
    """
    Constructs a list of lambda functions representing Sigma field tests.
    """
    tests = []
    for key_op, want in block_dict.items():
        if '|' in key_op:
            field, op = key_op.split('|', 1)
        else:
            field, op = key_op, '=='
        vals = want if isinstance(want, list) else [want]
        if op in ('==', '='):
            sv = [str(v) for v in vals]
            tests.append(lambda r, f=field, sv=sv: r.get(f) in sv)
        elif op == '!=':
            sv = [str(v) for v in vals]
            tests.append(lambda r, f=field, sv=sv: r.get(f) not in sv)
        elif op == 'in':
            tests.append(lambda r, f=field, lv=vals: r.get(f) in lv)
        elif op == 'contains':
            pats = [str(v) for v in vals]
            tests.append(lambda r, f=field, pats=pats: any(p in r.get(f, '') for p in pats))
        elif op == 'startswith':
            prefs = [str(v) for v in vals]
            tests.append(lambda r, f=field, prefs=prefs: any(r.get(f, '').startswith(p) for p in prefs))
        elif op == 'endswith':
            sufs = [str(v) for v in vals]
            tests.append(lambda r, f=field, sufs=sufs: any(r.get(f, '').endswith(s) for s in sufs))
        elif op == 'regex':
            regs = [re.compile(v) for v in vals]
            tests.append(lambda r, f=field, regs=regs: any(rx.search(r.get(f, '')) for rx in regs))
        else:
            raise ValueError(f"Unsupported operator '{op}'")
    return tests


def flatten_event(root):
    """
    Flattens a Windows Event XML tree into a dictionary of fields.
    """
    rec = {}
    sys_node = root.find('.//{*}System')
    if sys_node is not None:
        for e in sys_node:
            tag = e.tag.split('}', 1)[1] if '}' in e.tag else e.tag
            if tag == 'Provider':
                rec['Provider_Name'] = e.attrib.get('Name', '')
            else:
                rec[tag] = e.text or ''
    texts = [d.text.strip() for d in root.findall('.//{*}EventData/{*}Data') if d.text]
    rec['Data'] = ' '.join(texts)
    return rec


def parse_evtx_file(evtx_path):
    """
    Parses an EVTX file and applies Sigma rules to identify matching events.
    """
    rule_engines = []
    for meta, blocks, cond_str in RULE_DEFS:
        tests_by_block = {n: build_tests(b) for n, b in blocks.items()}
        cond_code = compile(cond_str, '<cond>', 'eval')
        rule_engines.append((meta, blocks, tests_by_block, cond_code))

    hits = []

    with Evtx(evtx_path) as log:
        records = list(log.records())
        for rec in tqdm(records, desc=os.path.basename(evtx_path), position=0, leave=True):
            xml = rec.xml()
            root = ET.fromstring(xml)
            rd = flatten_event(root)

            for meta, blocks, tests_by_block, cond_code in rule_engines:
                results = {blk: all(t(rd) for t in tests) for blk, tests in tests_by_block.items()}
                if not eval(cond_code, {}, results):
                    continue

                syst = root.find('.//{*}System')
                ts_node = syst.find('{*}TimeCreated') if syst is not None else None
                ts_raw = ts_node.attrib.get('SystemTime', '') if ts_node is not None else ''

                try:
                    ts = datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
                    ts = ts.astimezone(timezone.utc)
                    ts_str = ts.strftime('%Y-%m-%d %H:%M:%S.%f %z')
                    ts_str = ts_str[:-2] + ":" + ts_str[-2:]
                except Exception:
                    ts_str = ts_raw

                comp = (syst.find('{*}Computer').text or '') if syst is not None and syst.find('{*}Computer') is not None else ''
                chan = (syst.find('{*}Channel').text or '') if syst is not None and syst.find('{*}Channel') is not None else ''
                chan = chan[:24]
                eid = (syst.find('{*}EventID').text or '') if syst is not None and syst.find('{*}EventID') is not None else ''
                rid = (syst.find('{*}EventRecordID').text or '') if syst is not None and syst.find('{*}EventRecordID') is not None else ''

                data_nodes = root.findall('.//{*}EventData/{*}Data')
                data_texts = [d.text.strip() for d in data_nodes if d.text and d.text.strip()]
                msg = f'Data[1]: {data_texts[0]}' if data_texts else 'Data: -'

                extra = ''
                if 'hash_match' in blocks:
                    for pats in blocks['hash_match'].values():
                        for p in pats:
                            if p in rd.get('Data', ''):
                                extra += p + ';'
                    extra = extra.rstrip(';') or "-"

                level_map = {
                    'critical': 'crit',
                    'high': 'high',
                    'medium': 'med',
                    'low': 'low',
                    'informational': 'info',
                    'emergency': 'emerg'
                }
                lvl = meta['level'].lower()
                lvl = level_map.get(lvl, lvl)

                hits.append({
                    'Timestamp':      ts_str,
                    'RuleTitle':      meta['title'],
                    'Level':          lvl,
                    'Computer':       comp,
                    'Channel':        chan,
                    'EventID':        eid,
                    'RecordID':       rid,
                    'Details':        msg,
                    'ExtraFieldInfo': extra,
                    'RuleID':         meta['id'],
                })
    return hits


def load_rule(yml_path):
    """
    Loads a Sigma rule from a YAML file.
    """
    with open(yml_path, 'r', encoding='utf-8') as f:
        rule = yaml.safe_load(f)
    meta = {
        'title': rule.get('title', ''),
        'id': rule.get('id', ''),
        'level': rule.get('level', ''),
    }
    det = rule.get('detection', {}) or {}
    blocks = {n: b for n, b in det.items() if n != 'condition'}
    condition = det.get('condition', ' and '.join(blocks.keys()))
    return meta, blocks, condition


def write_csv(rows, out_fp):
    """
    Writes a list of event dictionaries to CSV format.
    """
    cols = ['Timestamp', 'RuleTitle', 'Level', 'Computer',
            'Channel', 'EventID', 'RecordID', 'Details',
            'ExtraFieldInfo', 'RuleID']
    w = csv.DictWriter(out_fp, fieldnames=cols, quoting=csv.QUOTE_ALL)
    w.writeheader()
    for r in rows:
        clean_row = {k: (v.replace('\n', ' ').replace('\r', ' ') if isinstance(v, str) else v)
                     for k, v in r.items()}
        w.writerow(clean_row)


def extract_iocs(hits):
    """
    Extracts IOCs (indicators of compromise) from matched event details.
    """
    patterns = {
        "hashes": re.compile(r"\b[a-fA-F0-9]{64}\b"),
        "ips": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "urls": re.compile(r"\bhttps?://[^\s\"<]+"),
        "domains": re.compile(
            r"\b(?:[a-zA-Z0-9-]+\.)+(?:"
            r"com|net|org|edu|gov|mil|int|info|biz|br|us|uk|co|io|me|ai|app|xyz|tech|store|site|online|dev|cloud|pro|live|news|club|email|tv|ca|de|fr|in|au|nl|ru|ch|it|es|"
            r"tk|ml|ga|cf|gq|top|buzz|support|fit|date|review|click|work|men|loan|cam|cyou|monster|space"
            r")\b"
        ),
        "executables": re.compile(
            r"\b[\w\-\\/:.]*?[^\\/:*?\"<>|\r\n\s]\.(?:exe|dll|sys|bat|cmd|vbs|js|ps1|sh|py)\b",
            re.IGNORECASE
        ),
        "documents": re.compile(
            r"\b[\w\-\\/:.]*?[^\\/:*?\"<>|\r\n\s]\.(?:docx?|xlsx?|pptx?|rtf|pdf)\b",
            re.IGNORECASE
        )
    }

    iocs = {key: set() for key in patterns}

    for hit in hits:
        line = hit.get("Details", "")
        for kind, rx in patterns.items():
            for match in rx.findall(line):
                # Clean up XML tailing tag if present
                cleaned = re.sub(r"</string>$", "", match)
                iocs[kind].add(cleaned)

    return iocs


def vt_check_hashes(hashes, api_key):
    """
    Checks SHA-256 hashes against the VirusTotal API.
    """
    url = "https://www.virustotal.com/api/v3/files/"
    headers = {"x-apikey": api_key}
    results = {}
    for h in tqdm(hashes, desc="VirusTotal Lookup", unit="hash"):
        r = requests.get(url + h, headers=headers)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            results[h] = f"{stats.get('malicious', 0)} malicious"
        else:
            results[h] = "File not found"
    return results


def main():
    """
    Main CLI entry point. Handles argument parsing, rule and log loading,
    parallel Sigma evaluation, result exporting (CSV), IOC extraction,
    optional VirusTotal/OpenTIP lookups, and terminal statistics printing.
    """
    start_time = time.time()

    p = argparse.ArgumentParser(
        description="Python tool that applies Sigma rules to Kaspersky EVTX logs."
    )
    p.add_argument('-V', '--version', action='version',
                   version=f"k-evtrace {VERSION} by Cristian Souza")
    grp_r = p.add_mutually_exclusive_group()
    grp_r.add_argument('--rules', help="Directory of Sigma rules")
    grp_r.add_argument('--rule', help="Single Sigma rule file")
    grp_l = p.add_mutually_exclusive_group(required=True)
    grp_l.add_argument('--logs', help="Directory of EVTX logs")
    grp_l.add_argument('--log', help="Single EVTX log file")
    p.add_argument('--csv', help="CSV output file")
    p.add_argument('--levels', help="Comma-separated list of severity levels to apply (e.g. emerg,crit,info)")
    grp_api = p.add_mutually_exclusive_group()
    grp_api.add_argument('--vt', action='store_true',
                         help="Check matched hashes on VirusTotal (requires VT_API_KEY)")
    grp_api.add_argument('--opentip', action='store_true',
                         help="Check matched hashes on Kaspersky OpenTIP (requires OPENTIP_API_KEY)")
    p.add_argument('--ioc-dump', help="Extract IOCs and save to JSON")
    args = p.parse_args()

    # Validate API keys
    if args.vt:
        if not os.getenv("VT_API_KEY"):
            sys.exit("[ERROR] VT_API_KEY environment variable not set")
    if args.opentip:
        if not os.getenv("OPENTIP_API_KEY"):
            sys.exit("[ERROR] OPENTIP_API_KEY environment variable not set")

    # Use default rules directory if none specified
    if not args.rule and not args.rules:
        default_rules_dir = './rules'
        if not os.path.exists(default_rules_dir):
            sys.exit("[ERROR] No rule or rules directory specified, and default './rules' not found.")
        args.rules = default_rules_dir
        print(f"[*] No rule specified. Using default rules directory: {default_rules_dir}")

    # File checks
    for attr in ['rule', 'rules', 'log', 'logs']:
        val = getattr(args, attr)
        if val and not os.path.exists(val):
            sys.exit(f"[ERROR] {attr} path not found: {val}")

    if args.csv and os.path.exists(args.csv):
        answer = input(f"[?] Output file '{args.csv}' already exists. Overwrite? [y/N]: ").strip().lower()
        if answer not in ('y', 'yes'):
            print("Aborted.")
            sys.exit(0)

    if args.ioc_dump and os.path.exists(args.ioc_dump):
        answer = input(f"[?] IOC dump file '{args.ioc_dump}' already exists. Overwrite? [y/N]: ").strip().lower()
        if answer not in ('y', 'yes'):
            print("Aborted.")
            sys.exit(0)

    # Load rules
    rule_files = [args.rule] if args.rule else [
        os.path.join(args.rules, f) for f in os.listdir(args.rules) if f.endswith(('.yml', 'yaml'))
    ]
    rule_defs = [load_rule(rf) for rf in rule_files]

    if args.levels:
        allowed = {x.strip().lower() for x in args.levels.split(',')}
        level_map = {
            'critical': 'crit',
            'high': 'high',
            'medium': 'med',
            'low': 'low',
            'informational': 'info',
            'emergency': 'emerg'
        }
        rule_defs = [
            r for r in rule_defs
            if level_map.get(r[0].get('level', '').lower(), '').lower() in allowed
        ]
        if not rule_defs:
            sys.exit(f"[ERROR] No rules matched selected levels.")

    # Load logs
    evtx_files = [args.log] if args.log else [
        os.path.join(args.logs, f) for f in os.listdir(args.logs) if f.endswith('.evtx')
    ]
    if not evtx_files:
        sys.exit("[ERROR] No EVTX files found.")

    # Process logs
    all_hits = []
    with concurrent.futures.ProcessPoolExecutor(
            max_workers=cpu_count(),
            initializer=init_worker,
            initargs=(rule_defs,)
    ) as pool:
        for hits in pool.map(parse_evtx_file, evtx_files):
            all_hits.extend(hits)

    all_hits.sort(key=lambda x: x['Timestamp'])

    # Write CSV
    if args.csv:
        with open(args.csv, 'w', newline='', encoding='utf-8') as f:
            write_csv(all_hits, f)
    else:
        write_csv(all_hits, sys.stdout)

    # Extract IOCs
    if args.ioc_dump:
        iocs = extract_iocs(all_hits)
        if args.vt:
            vt_api_key = os.getenv("VT_API_KEY")
            vt_results = {h: lookup_vt(h, vt_api_key) for h in iocs.get("hashes", [])}
            iocs["vt_results"] = vt_results
        if args.opentip:
            ot_api_key = os.getenv("OPENTIP_API_KEY")
            ot_results = {h: lookup_opentip(h, ot_api_key) for h in iocs.get("hashes", [])}
            iocs["ot_results"] = ot_results
        with open(args.ioc_dump, 'w', encoding='utf-8') as f:
            json.dump({k: list(v) if isinstance(v, set) else v for k, v in iocs.items()}, f, indent=2)
        print(f"[+] IOCs saved to {args.ioc_dump}")

    # Print statistics
    stats = {lvl: 0 for lvl in ['emerg', 'crit', 'high', 'med', 'low', 'info']}
    per_level_titles = defaultdict(list)
    per_level_dates = defaultdict(list)
    per_level_computers = defaultdict(list)
    timestamps = []

    for e in all_hits:
        lvl = e['Level'].lower()
        if lvl in stats:
            stats[lvl] += 1
            per_level_titles[lvl].append(e['RuleTitle'])
            per_level_dates[lvl].append(e['Timestamp'][:10])
            per_level_computers[lvl].append(e['Computer'])
            timestamps.append(e['Timestamp'])

    if timestamps:
        print(f"\nFirst Timestamp: {timestamps[0]}")
        print(f"Last Timestamp:  {timestamps[-1]}")

    print("\nDates with most total detections:")
    colored_dates = []
    for lvl in stats:
        if not per_level_dates[lvl]:
            text = f"{lvl}: n/a"
        else:
            top_date, top_count = Counter(per_level_dates[lvl]).most_common(1)[0]
            text = f"{lvl}: {top_date} ({top_count})"
        colored_dates.append(color_text(text, lvl))
    print(", ".join(colored_dates))

    print("\nTop 5 computers with most unique detections:")
    for lvl in stats:
        if not per_level_computers[lvl]:
            text = f"{lvl}: n/a"
        else:
            top_host, count = Counter(per_level_computers[lvl]).most_common(1)[0]
            text = f"{lvl}: {top_host} ({count})"
        print(color_text(text, lvl))

    summary_table = [(color_text(lvl.capitalize(), lvl), stats[lvl]) for lvl in stats]
    print("\nStatistics:")
    print(tabulate(summary_table, headers=["Level", "Count"], tablefmt="grid"))

    print("\nTop 5 rules per severity:\n")
    unified_top_rows = []
    for lvl in stats:
        titles = per_level_titles.get(lvl, [])
        if titles:
            counter = Counter(titles).most_common(5)
            for title, count in counter:
                unified_top_rows.append((color_text(lvl.capitalize(), lvl),
                                         color_text(title, lvl), count))

    print(tabulate(unified_top_rows, headers=["Severity", "Rule Title", "Count"], tablefmt="grid"))

    if args.csv and os.path.exists(args.csv):
        size_kb = Path(args.csv).stat().st_size / 1024
        print(f"\nSaved file: {args.csv} ({size_kb:.1f} KiB)")

    elapsed = time.time() - start_time
    print(f"\nElapsed time: {elapsed:.3f} seconds")


if __name__ == "__main__":
    """
    Calls the main function, gracefully stops if CTRL+C is pressed.
    """
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[91m[!] Interrupted by user.\033[0m")
        sys.exit(130)
