import argparse
import ast
import csv
import os
import re
import sys
import traceback
from contextlib import AbstractContextManager
from datetime import datetime
from time import sleep

import requests
from openpyxl import Workbook
from getpass import getpass
from sg_iamaas import CachingTokenGenerator

from config import OSC_API_URL
from config import PCE_LIST

FINAL_STATES = {"failed", "success"}
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')
OSC_API_URL_CHOICES = ["PARIS", "NORTH", "AMER", "ASIA"]
RESOLVED_OSC_API_URL = OSC_API_URL if isinstance(OSC_API_URL, str) else ""


class TeeStdout:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            stream.write(data)
            stream.flush()
        return len(data)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def _build_log_path(input_path: str) -> str:
    base_name = os.path.splitext(os.path.basename(input_path))[0]
    return os.path.join(os.path.dirname(input_path), f"{base_name}.log")


def _build_xlsx_output_path(output_csv_path: str) -> str:
    return f"{os.path.splitext(output_csv_path)[0]}.xlsx"


def _write_xlsx_output(output_csv_path: str, delimiter: str, result_column: str):
    rows, _ = _read_csv_rows_with_auto_delimiter(output_csv_path)
    headers = rows[0] + ["Started at", "Finished at", "Operation result"]
    wb = Workbook()
    ws = wb.active
    ws.title = "results"
    ws.append(headers)

    status_idx = rows[0].index(result_column) if result_column in rows[0] else None
    for row in rows[1:]:
        status_value = ''
        if status_idx is not None and status_idx < len(row):
            status_value = row[status_idx]
        operation_result = "OK" if str(status_value).lower() in ("success", "ok") else "KO"
        ws.append(row + ["", "", operation_result])

    xlsx_path = _build_xlsx_output_path(output_csv_path)
    wb.save(xlsx_path)
    return xlsx_path


class OscTokenManager:
    def __init__(self, token_gen: CachingTokenGenerator):
        self.token_gen = token_gen
        self._ctx: AbstractContextManager | None = None
        self.token = None

    def __enter__(self):
        self.refresh()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def refresh(self):
        self.close()
        self._ctx = self.token_gen.generate()
        self.token = self._ctx.__enter__()
        return self.token

    def close(self):
        if self._ctx is not None:
            self._ctx.__exit__(None, None, None)
            self._ctx = None
            self.token = None


def _is_invalid_token_response(status_code: int, response_text: str) -> bool:
    return status_code == 401 and "token is not valid" in (response_text or "").lower()


def request_with_token_refresh(token_manager: OscTokenManager, request_fn):
    response = request_fn(token_manager.token)
    if _is_invalid_token_response(response.status_code, response.text):
        print("[TOKEN] Invalid OSC token detected (401). Refreshing token and retrying request...")
        token_manager.refresh()
        response = request_fn(token_manager.token)
    return response


def _resolve_osc_api_url(osc_api_url_choice: str) -> str:
    if isinstance(OSC_API_URL, dict):
        value = OSC_API_URL.get(osc_api_url_choice)
        if not value:
            print(f"Error: OSC_API_URL missing key '{osc_api_url_choice}' in config.")
            sys.exit(1)
        return value
    if osc_api_url_choice:
        print("Error: --osc-api-url requires OSC_API_URL to be configured as a dict in config.py.")
        sys.exit(1)
    return OSC_API_URL


def _read_csv_rows_with_auto_delimiter(input_path: str):
    try:
        with open(input_path, newline='', encoding='utf-8-sig') as infile:
            sample = infile.read(4096)
            infile.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=';,\t')
                delimiter = dialect.delimiter
            except Exception:
                delimiter = ';'
            reader = csv.reader(infile, delimiter=delimiter)
            return list(reader), delimiter
    except Exception as exc:
        print(f"Error: Unable to read input file '{input_path}': {exc}")
        sys.exit(1)


def create_output_csv_with_extra_columns(input_path: str) -> tuple[str, str]:
    input_dir = os.path.dirname(input_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"{timestamp}_gen2_precheck_result.csv"
    output_path = os.path.join(input_dir, output_filename)

    required_columns = ["server_id", "account_id"]
    rows, delimiter = _read_csv_rows_with_auto_delimiter(input_path)
    if not rows:
        print("Error: Input CSV is empty.")
        sys.exit(1)

    cleaned_headers = [col.strip().lstrip('*').strip() for col in rows[0]]
    for col in required_columns:
        if col not in cleaned_headers:
            print(f"Error: Input CSV missing required column '{col}'.")
            sys.exit(1)

    headers = rows[0] + [
        "error", "precheck_job_id", "precheck_status", "1_os_check", "2_disk_space",
        "3_dns_resolution", "4_ping", "5_port_access", "6_docker_chain",
        "7_docker_ruleset", "8_podman", "9_podman_network", "10_podman_docker_cli",
        "11_nat_iptable", "12_nat_nftable", "precheck_result", "precheck_retries"
    ]

    with open(output_path, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile, delimiter=delimiter)
        writer.writerow(headers)
        for row in rows[1:]:
            writer.writerow(row + [""] * 17)

    return output_path, delimiter


def run_precheck_puppet_module(server_id: str, account_id: str, token_manager: OscTokenManager) -> object:
    try:
        url = f"{RESOLVED_OSC_API_URL.rstrip('/')}/nodes/{server_id}/jobs/run-puppet"
        headers = {
            "Content-Type": "application/json",
                        "X-Target-Account-Id": f"{account_id}"
        }
        payload = {"osType": "linux", "skipTags": [], "tags": ["sg_illumio_ven::precheck_output"]}
        response = request_with_token_refresh(
            token_manager,
            lambda token: requests.post(
                url,
                json=payload,
                headers={**headers, "Authorization": f"{token.authorization_header}"},
            ),
        )
        if response.status_code != 202:
            return {'error': f"{response.status_code}: {response.text}"}
        job_id = response.json().get("job", {}).get("id", "")
        return job_id if job_id else {'error': "No job id returned by API"}
    except Exception as exc:
        return {'error': str(exc)}


def associate_puppet_module_with_server(server_id: str, account_id: str, token_manager: OscTokenManager) -> dict:
    try:
        url = f"{RESOLVED_OSC_API_URL.rstrip('/')}/nodes/{server_id}/modules"
        headers = {
            "Content-Type": "application/json",
                        "X-Target-Account-Id": f"{account_id}"
        }
        payload = {"modules": [{"name": "sg_illumio_ven::precheck", "params": {}}]}
        response = request_with_token_refresh(
            token_manager,
            lambda token: requests.patch(
                url,
                json=payload,
                headers={**headers, "Authorization": f"{token.authorization_header}"},
            ),
        )
        return {} if response.status_code == 202 else {'error': f"{response.status_code}: {response.text}"}
    except Exception as exc:
        return {'error': str(exc)}


def dissociate_puppet_module_from_server(server_id: str, account_id: str, token_manager: OscTokenManager) -> None:
    if not server_id:
        return
    try:
        url = f"{RESOLVED_OSC_API_URL.rstrip('/')}/nodes/{server_id}/modules/sg_illumio_ven::precheck"
        headers = {
                        "X-Target-Account-Id": f"{account_id}"
        }
        request_with_token_refresh(
            token_manager,
            lambda token: requests.delete(
                url,
                headers={**headers, "Authorization": f"{token.authorization_header}"},
            ),
        )
    except Exception:
        pass


def change_server_puppet_environments(server_id: str, environment: str, account_id: str, token_manager: OscTokenManager) -> dict:
    try:
        url = f"{RESOLVED_OSC_API_URL.rstrip('/')}/nodes/{server_id}/environments"
        headers = {
            "Content-Type": "application/json",
                        "X-Target-Account-Id": f"{account_id}"
        }
        response = request_with_token_refresh(
            token_manager,
            lambda token: requests.put(
                url,
                json={"environment": environment},
                headers={**headers, "Authorization": f"{token.authorization_header}"},
            ),
        )
        return {} if response.status_code == 200 else {'error': f"{response.status_code}: {response.text}"}
    except Exception as exc:
        return {'error': str(exc)}


def _parse_precheck_reason(row, idxs, reason: str, pce_fqdn: str):
    if not reason:
        return
    try:
        lines = ast.literal_eval(reason)
    except Exception:
        return
    clean_lines = [ANSI_ESCAPE.sub('', line).strip() for line in lines if str(line).strip()]
    for line in clean_lines:
        m = re.match(r'^(\d+)\..*(?:-|:|\()\s*(OK|KO)\)?$', line)
        if m:
            step, value = m.group(1), m.group(2)
            mapping = {
                '1': '1_os_check', '2': '2_disk_space', '6': '6_docker_chain', '7': '7_docker_ruleset',
                '8': '8_podman', '9': '9_podman_network', '10': '10_podman_docker_cli',
                '11': '11_nat_iptable', '12': '12_nat_nftable'
            }
            if step in mapping:
                row[idxs[mapping[step]]] = value
            continue
        if line.startswith("DNS for") and pce_fqdn in line:
            row[idxs['3_dns_resolution']] = 'OK' if 'OK' in line else 'KO'
        if line.startswith("Ping to") and pce_fqdn in line:
            row[idxs['4_ping']] = 'OK' if 'OK' in line else 'KO'
        if line.startswith("Connection to") and pce_fqdn in line:
            row[idxs['5_port_access']] = 'OK' if 'OK' in line else 'KO'


def _compute_final_result(row, idxs):
    keys = ['1_os_check', '2_disk_space', '3_dns_resolution', '4_ping', '5_port_access', '6_docker_chain', '7_docker_ruleset',
            '8_podman', '9_podman_network', '10_podman_docker_cli', '11_nat_iptable', '12_nat_nftable']
    row[idxs['precheck_result']] = 'OK' if all(row[idxs[k]] == 'OK' for k in keys) else 'KO'


def main():
    global RESOLVED_OSC_API_URL
    parser = argparse.ArgumentParser(description="Run + monitor Gen2 prechecks from one CSV.")
    parser.add_argument('-f', '--file-path', type=str, required=True)
    parser.add_argument('--pce', type=str, choices=['dev', 'uat', 'prd', 'prd_critapps'], required=True)
    parser.add_argument('--osc-client-id', type=str, required=True)
    parser.add_argument('--osc-client-secret', type=str, required=False)
    parser.add_argument('--osc-account-id', type=str, required=True)
    parser.add_argument('--osc-api-url', type=str, choices=OSC_API_URL_CHOICES, required=False)
    parser.add_argument('--batch-size', type=int, default=5)
    parser.add_argument('--poll-interval', type=int, default=20)
    parser.add_argument('--max-retries', type=int, default=None,
                        help="Max number of monitoring checks per job. If set, it overrides default infinite monitoring.")
    parser.add_argument('--skip-unstable-switch', action='store_true',
                        help="Skip switching puppet environment to unstable/stable during precheck.")
    args = parser.parse_args()

    original_stdout = sys.stdout
    log_file = None
    try:
        log_path = _build_log_path(args.file_path)
        log_file = open(log_path, "a", encoding="utf-8")
        sys.stdout = TeeStdout(original_stdout, log_file)
        print(f"[LOG] Output is also written to: {log_path}")

        RESOLVED_OSC_API_URL = _resolve_osc_api_url(args.osc_api_url)
        if not args.osc_client_secret:
            args.osc_client_secret = getpass(prompt='Osconfig Client secret: ')

        output_csv, delimiter = create_output_csv_with_extra_columns(args.file_path)
        rows, _ = _read_csv_rows_with_auto_delimiter(output_csv)
        headers, data_rows = rows[0], rows[1:]
        idxs = {h.strip().lstrip('*').strip(): i for i, h in enumerate(headers)}

        step_columns = ["1_os_check", "2_disk_space", "3_dns_resolution", "4_ping", "5_port_access", "6_docker_chain", "7_docker_ruleset", "8_podman", "9_podman_network", "10_podman_docker_cli", "11_nat_iptable", "12_nat_nftable", "precheck_result"]
        for c in step_columns:
            idxs[c] = headers.index(c)

        scopes = ["osc:read", "osc:write"]
        acl_token_generator = CachingTokenGenerator(args.osc_client_id, args.osc_client_secret, args.osc_account_id, scopes)
        pce_fqdn = "ilu-prd.fr.world.socgen" if args.pce == "prd" else PCE_LIST.get(args.pce, {}).get("fqdn", "")

        total_servers = len(data_rows)
        for start in range(0, total_servers, args.batch_size):
            batch = data_rows[start:start + args.batch_size]
            batch_no = start // args.batch_size + 1
            print(f"\n=== Batch {batch_no} | servers {start + 1}-{start + len(batch)} / {total_servers} ===")
            running = []
            status_tracker = {}
            with OscTokenManager(acl_token_generator) as token_manager:
                for row in batch:
                    sid = row[idxs['server_id']]
                    aid = row[idxs['account_id']]
                    print(f"  -> {sid}: associate module + launch job")
                    if not args.skip_unstable_switch:
                        print(f"     switching {sid} puppet env to unstable")
                        res = change_server_puppet_environments(sid, "unstable", aid, token_manager)
                        if 'error' in res:
                            row[idxs['error']] = res['error']
                            continue
                    res = associate_puppet_module_with_server(sid, aid, token_manager)
                    if 'error' in res:
                        row[idxs['error']] = res['error']
                        continue
                    if row[idxs['error']]:
                        continue
                    precheck = run_precheck_puppet_module(sid, aid, token_manager)
                    if isinstance(precheck, dict):
                        row[idxs['error']] = precheck['error']
                        print(f"  [ERROR] launch precheck server={sid}: {row[idxs['error']]}")
                        continue
                    row[idxs['precheck_job_id']] = precheck
                    row[idxs['precheck_status']] = 'running'
                    running.append(row)
                    print(f"  [OK] job launched server={sid} job_id={precheck}")

                while running:
                    print(f"[MONITOR] {len(running)} precheck job(s) running...")
                    remaining = []
                    for row in running:
                        sid, aid = row[idxs['server_id']], row[idxs['account_id']]
                        job_id = row[idxs['precheck_job_id']]
                        retries_count = int(row[idxs['precheck_retries']]) if row[idxs['precheck_retries']] else 0
                        url = f"{RESOLVED_OSC_API_URL.rstrip('/')}/jobs/{job_id}"
                        resp = request_with_token_refresh(
                            token_manager,
                            lambda token: requests.get(
                                url,
                                headers={"Authorization": token.authorization_header, "X-Target-Account-Id": aid},
                            ),
                        )
                        retries_count += 1
                        row[idxs['precheck_retries']] = str(retries_count)
                        if resp.status_code != 200:
                            row[idxs['error']] = f"{resp.status_code}: {resp.text}"
                            row[idxs['precheck_status']] = 'error'
                            print(f"  [ERROR] server={sid} job={job_id}: {row[idxs['error']]}")
                            continue
                        job = resp.json().get('job', {})
                        status = (job.get('status') or '').lower()
                        row[idxs['precheck_status']] = status
                        created_at = job.get('createdAt') or job.get('created_at') or '-'
                        updated_at = job.get('updatedAt') or job.get('updated_at') or '-'
                        message = (job.get('message') or '').strip()
                        reason = (job.get('reason') or '').strip()
                        print(f"  [STATUS] server={sid} job={job_id} -> {status} (retry={retries_count})")
                        _parse_precheck_reason(row, idxs, reason, pce_fqdn)

                        previous_status, same_status_count = status_tracker.get(job_id, ("", 0))
                        same_status_count = same_status_count + 1 if status == previous_status else 1
                        status_tracker[job_id] = (status, same_status_count)

                        if message:
                            print(f"    [JOB_MESSAGE] server={sid} job={job_id}: {message}")
                        if status == "running" and (retries_count % 5 == 0 or same_status_count >= 5):
                            print(f"    [RUNNING_DIAG] server={sid} job={job_id} still running | created_at={created_at} updated_at={updated_at} same_status_count={same_status_count}")
                            if reason:
                                print(f"    [RUNNING_REASON] server={sid} job={job_id}: {reason}")
                        if status in FINAL_STATES:
                            _compute_final_result(row, idxs)
                            dissociate_puppet_module_from_server(sid, aid, token_manager)
                            if not args.skip_unstable_switch:
                                change_server_puppet_environments(sid, 'stable', aid, token_manager)
                        elif args.max_retries is not None and retries_count >= args.max_retries:
                            row[idxs['error']] = f"Max retries reached ({args.max_retries}) for job_id {job_id}"
                            row[idxs['precheck_status']] = 'timeout'
                            dissociate_puppet_module_from_server(sid, aid, token_manager)
                            if not args.skip_unstable_switch:
                                change_server_puppet_environments(sid, 'stable', aid, token_manager)
                        else:
                            remaining.append(row)
                    running = remaining
                    if running:
                        sleep(args.poll_interval)

                print(f"  Cleanup batch {batch_no}: dissociate module for processed servers...")
                for row in batch:
                    sid = row[idxs['server_id']]
                    aid = row[idxs['account_id']]
                    dissociate_puppet_module_from_server(sid, aid, token_manager)

        with open(output_csv, 'w', newline='', encoding='utf-8') as out:
            writer = csv.writer(out, delimiter=delimiter)
            writer.writerow(headers)
            writer.writerows(data_rows)

        output_xlsx = _write_xlsx_output(output_csv, delimiter, "precheck_result")
        print(f"\nEND: precheck completed. Output CSV: {output_csv}")
        print(f"END: precheck completed. Output XLSX: {output_xlsx}")
    finally:
        sys.stdout = original_stdout
        if log_file:
            log_file.close()

if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(traceback.format_exc())
        sys.exit(1)
