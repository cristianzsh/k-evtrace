# k-evtrace

A EVTX log analyzer that uses Sigma rules to scan Kaspersky logs, extracting security detections, IOCs, and generating reports in Hayabusa-compatible CSV format.

# Features

* Sigma Rule Support: Parses `.yml` rules with conditions, multiple blocks, and advanced operators.
* IOC Extraction: Extracts hashes, IPs, URLs, domains, executables, and document names.
* VirusTotal/OpenTIP Integration: Optional live VT/OpenTIP lookup for matched hashes via API key.
* Hayabusa-Compatible CSV Output: Clean, structured, and easily parsable.

# Requirements

* Python 3.7 or higher
* `pyyaml`
* `requests`
* `python_evtx`
* `tqdm`
* `tabulate`

Install dependencies via `pip`:

```
pip3 install -r requirements.txt
```

# Installation

```
git clone https://github.com/cristianzsh/k-evtrace.git
cd k-evtrace
pip3 install -r requirements.txt
```

# Usage

```
python3 k-evtrace.py --rules ./rules/ --logs ./evtx_logs/ --csv output.csv --levels crit,high,med --vt --ioc-dump iocs.json
```

## Options

| Flag           | Description                                                                    |
| ---------------| ------------------------------------------------------------------------------ |
| `--rule`       | Path to a single Sigma rule file                                               |
| `--rules`      | Directory containing multiple `.yml` Sigma rules                               |
| `--log`        | Single `.evtx` file                                                            |
| `--logs`       | Directory containing `.evtx` logs                                              |
| `--csv`        | Output CSV path                                                                |
| `--levels`     | Comma-separated severity filter: `emerg`, `crit`, `high`, `med`, `low`, `info` |
| `--vt`         | Enable VirusTotal lookups (requires `VT_API_KEY` env variable)                 |
| `--ioc-dump`   | Save extracted IOCs (JSON format)                                              |

# Examples

Scan a single log with one rule:

```
python3 k-evtrace.py --rule rules/rule1.yml --log logs/event.evtx --csv result.csv
```

Bulk scan with severity filter and IOC output:

```
python3 k-evtrace.py --rules rules/ --logs logs/ --levels high,crit --csv result.csv --ioc-dump iocs.json
```
## Environment variables

* `VT_API_KEY`: Your VirusTotal API key used for file hash lookups.
* `OPENTIP_API_KEY`: Your Kaspersky OpenTIP API key used for file hash lookups.

## Building executables

This project provides scripts to generate standalone binaries using `Nuitka` (`pip3 install nuitka`) for both Linux and Windows.

To build a Linux executable:
```
chmod +x build_linux.sh
./build_linux.sh
```

On Windows, simply double-click the `build_win.bat` file.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
