import argparse
import csv
import os
import sys
import traceback
from contextlib import AbstractContextManager
from datetime import datetime
from getpass import getpass
from time import sleep

import requests
from openpyxl import Workbook
from illumio import PairingProfile, PolicyComputeEngine  # type: ignore
from sg_iamaas import CachingTokenGenerator

from config import OSC_API_URL
from utils import get_pce_connection

FINAL_STATES = {"failed", "success"}
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


def create_output_csv_with_extra_columns(input_path: str, pce_name: str) -> tuple[str, str]:
    input_dir = os.path.dirname(input_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"{timestamp}_{pce_name}_gen2_bulk_install_result.csv"
    output_path = os.path.join(input_dir, output_filename)

    required_columns = [
        "server_id", "account_id", "pairing_profile_name", "application_label_href",
        "env_label_href", "location_label_href", "role_label_href", "os_label_href",
        "enforcement_mode"
    ]
    rows, delimiter = _read_csv_rows_with_auto_delimiter(input_path)
    if not rows:
        print("Error: Input CSV is empty.")
        sys.exit(1)

    cleaned_headers = [col.strip().lstrip('*').strip() for col in rows[0]]
    for col in required_columns:
        if col not in cleaned_headers:
            print(f"Error: Input CSV missing required column '{col}'.")
            sys.exit(1)

    headers = rows[0] + ["error", "install_job_id", "install_status", "seen_in_pce"]
    with open(output_path, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile, delimiter=delimiter)
        writer.writerow(headers)
        for row in rows[1:]:
            writer.writerow(row + ["", "", "", ""])

    return output_path, delimiter


def get_or_create_pairing_profile(pce: 'PolicyComputeEngine', pairing_profile_name: str, enforcement_mode: str, labels: list, cache: dict):
    try:
        if pairing_profile_name in cache:
            return cache[pairing_profile_name]
        profiles = pce.pairing_profiles.get(params={'name': pairing_profile_name})
        if profiles:
            cache[pairing_profile_name] = profiles[0]
            return profiles[0]
        profile = PairingProfile(
            name=pairing_profile_name,
            enabled=True,
            description=f"Pairing Profile for {pairing_profile_name}",
            enforcement_mode=enforcement_mode,
            allowed_uses_per_key=1,
            key_lifespan=3600,
            labels=labels,
            role_label_lock=True,
            app_label_lock=True,
            env_label_lock=True,
            loc_label_lock=True,
            external_data_set="generated_by_automation",
            external_data_reference=pairing_profile_name,
        )
        created = pce.pairing_profiles.create(profile)
        cache[pairing_profile_name] = created
        return created
    except Exception as exc:
        status_code = getattr(exc, 'status_code', None)
        return {'error': f"{status_code or 'Could not get Pairing Profile'}: {str(exc)}"}


def build_osc_association_payload(profile_id: int, ac: str, pce_name: str):
    return {
        "modules": [{
            "name": "sg_illumio_ven",
            "params": {
                "ensure": "present",
                "profile_id": profile_id,
                "ac": ac,
                "v1": "true",
                "env_type": pce_name,
            },
        }]
    }


def get_osc_association_payload(pce: 'PolicyComputeEngine', pairing_profile_href: str, pce_name: str):
    try:
        profile_id = int(pairing_profile_href.split("/")[-1])
        pairing_key = pce.generate_pairing_key(pairing_profile_href)
        return build_osc_association_payload(profile_id, pairing_key, pce_name)
    except Exception as exc:
        status_code = getattr(exc, 'status_code', None)
        return {'error': f"{status_code or 'Could not get association payload'}: {str(exc)}"}


def associate_module(server_id: str, account_id: str, payload: dict, token_manager: OscTokenManager):
    try:
        url = f"{RESOLVED_OSC_API_URL.rstrip('/')}/nodes/{server_id}/modules"
        headers = {
            "Content-Type": "application/json",
                        "X-Target-Account-Id": account_id,
        }
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


def run_install(server_id: str, account_id: str, os_type: str, token_manager: OscTokenManager):
    try:
        url = f"{RESOLVED_OSC_API_URL.rstrip('/')}/nodes/{server_id}/jobs/run-puppet"
        headers = {
            "Content-Type": "application/json",
                        "X-Target-Account-Id": account_id,
        }
        payload = {"osType": os_type, "skipTags": [], "tags": ["sg_illumio_ven"]}
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
        return job_id if job_id else {'error': "No install job id returned by API"}
    except Exception as exc:
        return {'error': str(exc)}


def get_job_status(job_id: str, account_id: str, token_manager: OscTokenManager):
    url = f"{RESOLVED_OSC_API_URL.rstrip('/')}/jobs/{job_id}"
    response = request_with_token_refresh(
        token_manager,
        lambda token: requests.get(
            url,
            headers={"Authorization": token.authorization_header, "X-Target-Account-Id": account_id},
        ),
    )
    if response.status_code != 200:
        return {'error': f"{response.status_code}: {response.text}"}
    return response.json().get("job", {})


def dissociate_module(server_id: str, account_id: str, token_manager: OscTokenManager):
    try:
        url = f"{RESOLVED_OSC_API_URL.rstrip('/')}/nodes/{server_id}/modules/sg_illumio_ven"
        headers = {"X-Target-Account-Id": account_id}
        response = request_with_token_refresh(
            token_manager,
            lambda token: requests.delete(
                url,
                headers={**headers, "Authorization": token.authorization_header},
            ),
        )
        return {} if response.status_code == 204 else {'error': f"{response.status_code}: {response.text}"}
    except Exception as exc:
        return {'error': str(exc)}


def check_workload_in_pce(pce: 'PolicyComputeEngine', hostname: str, ip_address: str) -> bool:
    try:
        workloads = pce.workloads.get(params={"hostname": hostname, "ip_address": ip_address, "managed": True})
        return bool(workloads)
    except Exception:
        return False


def main():
    global RESOLVED_OSC_API_URL
    parser = argparse.ArgumentParser(description="Bulk install + monitor Illumio agents by batches of 5.")
    parser.add_argument('-f', '--file-path', type=str, required=True)
    parser.add_argument('--pce', type=str, choices=['dev', 'uat', 'prd', 'prd_critapps'], required=True)
    parser.add_argument('--pce-username', type=str, required=False,
                        help='Illumio API username (required unless --force-profile-id/--force-ac is used)')
    parser.add_argument('--pce-password', type=str, required=False,
                        help='Illumio API password (required unless --force-profile-id/--force-ac is used)')
    parser.add_argument('--osc-client-id', type=str, required=True)
    parser.add_argument('--osc-client-secret', type=str, required=False)
    parser.add_argument('--osc-account-id', type=str, required=True)
    parser.add_argument('--osc-api-url', type=str, choices=OSC_API_URL_CHOICES, required=False)
    parser.add_argument('--batch-size', type=int, default=5)
    parser.add_argument('--poll-interval', type=int, default=20)
    parser.add_argument('--force-profile-id', type=int, required=False,
                        help='Force profile_id in OSC payload and skip pairing profile generation on PCE (must be used with --force-ac)')
    parser.add_argument('--force-ac', type=str, required=False,
                        help='Force pairing key (ac) in OSC payload and skip pairing key generation on PCE (must be used with --force-profile-id)')
    args = parser.parse_args()

    original_stdout = sys.stdout
    log_file = None
    try:
        log_path = _build_log_path(args.file_path)
        log_file = open(log_path, "a", encoding="utf-8")
        sys.stdout = TeeStdout(original_stdout, log_file)
        print(f"[LOG] Output is also written to: {log_path}")

        RESOLVED_OSC_API_URL = _resolve_osc_api_url(args.osc_api_url)
        forced_mode = args.force_profile_id is not None or bool(args.force_ac)
        if forced_mode and not (args.force_profile_id is not None and bool(args.force_ac)):
            print('Error: --force-profile-id and --force-ac must be provided together.')
            sys.exit(1)

        if not forced_mode and not args.pce_username:
            print('Error: --pce-username is required unless force mode is used.')
            sys.exit(1)

        if not forced_mode and not args.pce_password:
            args.pce_password = getpass(prompt='Illumio API password: ')
        if not args.osc_client_secret:
            args.osc_client_secret = getpass(prompt='Osconfig Client secret: ')

        output_csv, delimiter = create_output_csv_with_extra_columns(args.file_path, args.pce)
        pce = None
        if not forced_mode:
            pce = get_pce_connection(args.pce, args.pce_username, args.pce_password)

        rows, _ = _read_csv_rows_with_auto_delimiter(output_csv)
        headers, data_rows = rows[0], rows[1:]
        idx = {h.strip().lstrip('*').strip(): i for i, h in enumerate(headers)}
        scopes = ["osc:read", "osc:write"]
        token_gen = CachingTokenGenerator(args.osc_client_id, args.osc_client_secret, args.osc_account_id, scopes)

        profile_cache = {}
        total = len(data_rows)

        with OscTokenManager(token_gen) as token_manager:
            for start in range(0, total, args.batch_size):
                batch = data_rows[start:start + args.batch_size]
                batch_no = start // args.batch_size + 1
                print(f"\n=== Batch {batch_no} | servers {start + 1}-{start + len(batch)} / {total} ===")
                running = []

                for row in batch:
                    server_id = row[idx['server_id']]
                    account_id = row[idx['account_id']]
                    profile_name = row[idx['pairing_profile_name']]
                    enforcement_mode = row[idx['enforcement_mode']]
                    print(f"[START] server={server_id} account={account_id} profile={profile_name}")

                    labels = [
                        {"href": row[idx["role_label_href"]]},
                        {"href": row[idx["application_label_href"]]},
                        {"href": row[idx["env_label_href"]]},
                        {"href": row[idx["location_label_href"]]},
                        {"href": row[idx["os_label_href"]]},
                    ]
                    if forced_mode:
                        payload = build_osc_association_payload(args.force_profile_id, args.force_ac, args.pce)
                        print(f"  [FORCED] profile_id={args.force_profile_id} ac=<provided>")
                    else:
                        profile = get_or_create_pairing_profile(pce, profile_name, enforcement_mode, labels, profile_cache)
                        if isinstance(profile, dict):
                            row[idx['error']] = profile['error']
                            print(f"  [ERROR] pairing profile: {row[idx['error']]}")
                            continue

                        payload = get_osc_association_payload(pce, profile.href, args.pce)
                        if isinstance(payload, dict) and 'error' in payload:
                            row[idx['error']] = payload['error']
                            print(f"  [ERROR] payload: {row[idx['error']]}")
                            continue

                    assoc = associate_module(server_id, account_id, payload, token_manager)
                    if 'error' in assoc:
                        row[idx['error']] = assoc['error']
                        print(f"  [ERROR] association: {row[idx['error']]}")
                        continue

                    os_type = "windows" if profile_name.lower().endswith("windows") else "linux"
                    job_res = run_install(server_id, account_id, os_type, token_manager)
                    if isinstance(job_res, dict):
                        row[idx['error']] = job_res['error']
                        print(f"  [ERROR] run install: {row[idx['error']]}")
                        continue

                    row[idx['install_job_id']] = job_res
                    row[idx['install_status']] = 'running'
                    running.append(row)
                    print(f"  [OK] job launched job_id={job_res} os_type={os_type}")

                while running:
                    print(f"[MONITOR] {len(running)} job(s) en cours...")
                    remaining = []
                    for row in running:
                        server_id = row[idx['server_id']]
                        account_id = row[idx['account_id']]
                        job_id = row[idx['install_job_id']]
                        status_obj = get_job_status(job_id, account_id, token_manager)
                        if isinstance(status_obj, dict) and 'error' in status_obj:
                            row[idx['error']] = status_obj['error']
                            row[idx['install_status']] = 'error'
                            print(f"  [ERROR] server={server_id} job={job_id}: {row[idx['error']]}")
                            continue

                        status = (status_obj.get('status') or '').lower()
                        reason = status_obj.get('reason') or ''
                        message = status_obj.get('message') or ''
                        row[idx['install_status']] = status
                        if reason:
                            row[idx['error']] = f"{message}: {reason}" if message else reason
                        print(f"  [STATUS] server={server_id} job={job_id} -> {status}")

                        if status in FINAL_STATES:
                            dis = dissociate_module(server_id, account_id, token_manager)
                            if 'error' in dis:
                                row[idx['error']] = f"{row[idx['error']]} | dissociation: {dis['error']}".strip(" |")
                                print(f"  [WARN] dissociation failed server={server_id}: {dis['error']}")
                            else:
                                print(f"  [CLEANUP] module dissociated server={server_id}")
                            if status == 'success' and pce is not None and 'hostname' in idx and 'ip_address' in idx:
                                hostname = row[idx['hostname']].strip()
                                ip_address = row[idx['ip_address']].strip()
                                if hostname and ip_address:
                                    seen = check_workload_in_pce(pce, hostname, ip_address)
                                    row[idx['seen_in_pce']] = 'yes' if seen else 'no'
                                    print(f"  [PCE] server={server_id} seen_in_pce={row[idx['seen_in_pce']]}")
                        else:
                            remaining.append(row)
                    running = remaining
                    if running:
                        sleep(args.poll_interval)

                print(f"[BATCH DONE] Batch {batch_no} terminé.")

        with open(output_csv, 'w', newline='', encoding='utf-8') as outfile:
            writer = csv.writer(outfile, delimiter=delimiter)
            writer.writerow(headers)
            writer.writerows(data_rows)

        output_xlsx = _write_xlsx_output(output_csv, delimiter, "install_status")
        print(f"\nEND: installation terminée. Résultats CSV: {output_csv}")
        print(f"END: installation terminée. Résultats XLSX: {output_xlsx}")
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
