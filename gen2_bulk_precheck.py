import argparse
import csv
import os
from datetime import datetime
import sys
import traceback
import requests
from sg_iamaas import CachingTokenGenerator
from config import OSC_API_URL
from getpass import getpass


def _read_csv_rows_with_auto_delimiter(input_path: str):
    """Read CSV rows, auto-detecting delimiter and handling UTF-8 BOM."""
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
            rows = list(reader)
            return rows, delimiter
    except Exception as exc:
        print(f"Error: Unable to read input file '{input_path}': {exc}")
        sys.exit(1)


def create_output_csv_with_extra_columns(input_path: str) -> str:
    """
    Create a copy of the input CSV file, appending 'error' and 'install_job_id'
    columns. The output file is saved in the same directory as the input file,
    with the name formatted as '%Y%m%d_%H%M%S_gen2_precheck_exec.csv'.

    Args:
        input_path (str): Path to the input CSV file.

    Returns:
        str: Path to the newly created output CSV file.

    Raises:
        SystemExit: If the input file cannot be read or does not respect the
        required structure.
    """
    input_dir = os.path.dirname(input_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"{timestamp}_gen2_precheck_exec.csv"
    output_path = os.path.join(input_dir, output_filename)

    required_columns = ["server_id", "account_id"]
    rows, delimiter = _read_csv_rows_with_auto_delimiter(input_path)

    if not rows:
        print("Error: Input CSV is empty.")
        sys.exit(1)

    header = [col.strip().lstrip('*').strip() for col in rows[0]]

    for col in required_columns:
        if col not in header:
            print(
                f"Error: Input CSV missing required column '{col}'.\n"
                "Expected header: *server_id, *account_id"
            )
            sys.exit(1)

    col_indices = {col: header.index(col) for col in required_columns}
    for i, row in enumerate(rows[1:], start=2):
        for col, idx in col_indices.items():
            if idx >= len(row) or not row[idx].strip():
                print(
                    f"Error: Row {i} is missing a value for required column "
                    f"'{col}'."
                )
                sys.exit(1)

    headers = rows[0] + ["error", "precheck_job_id"]
    data_rows = rows[1:]

    with open(output_path, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile, delimiter=delimiter)
        writer.writerow(headers)
        for row in data_rows:
            writer.writerow(row + ["", ""])

    return output_path


def run_precheck_puppet_module(
    osc_api_url: str,
    server_id: str,
    account_id: str,
    access_control_token
) -> object:
    try:
        url = f"{osc_api_url.rstrip('/')}/nodes/{server_id}/jobs/run-puppet"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"{access_control_token.authorization_header}",
            "X-Target-Account-Id": f"{account_id}"
        }
        payload = {
            "osType": "linux",
            "skipTags": [],
            "tags": ["sg_illumio_ven::precheck"]
        }
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code != 202:
            return {
                'error': f"{response.status_code or 'OS Configuration agent install puppet run error :'}: {response.text}"
            }
        try:
            resp_json = response.json()
        except Exception as exc:
            return {
                'error': f"OS Configuration agent install puppet run error : Invalid JSON response: {str(exc)}"
            }
        job = resp_json.get("job", {})
        job_id = job.get("id", "")
        status = job.get("status", "")
        reason = job.get("reason", "")
        if job_id:
            return job_id
        return {
            'error': f"OS Configuration agent install puppet run error : job_id:[{job_id}] status:{status} reason:{reason}"
        }
    except Exception as exc:
        status_code = getattr(exc, 'status_code', None)
        return {
            'error': f"{status_code or 'OS Configuration agent install puppet run error :'}: {str(exc)}"
        }


def associate_puppet_module_with_server(
    osc_api_url: str,
    server_id: str,
    association_payload: dict,
    account_id: str,
    access_control_token
) -> dict:
    try:
        if not osc_api_url or not server_id or not association_payload or not access_control_token:
            return {'error': 'OS Configuration puppet module association error: Missing required parameters'}
        url = f"{osc_api_url.rstrip('/')}/nodes/{server_id}/modules"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"{access_control_token.authorization_header}",
            "X-Target-Account-Id": f"{account_id}"
        }

        response = requests.patch(url, json=association_payload, headers=headers)
        if response.status_code == 202:
            return {}
        return {
            'error': f"OS Configuration puppet module association error : {response.status_code}: {response.text}"
        }
    except Exception as exc:
        status_code = getattr(exc, 'status_code', None)
        return {
            'error': f"{status_code or 'OS Configuration puppet module association error'}: {str(exc)}"
        }


def change_server_puppet_environments(
    osc_api_url: str,
    server_id: str,
    environment: str,
    account_id: str,
    access_control_token
) -> dict:
    try:
        if not osc_api_url or not server_id or not environment or not access_control_token:
            return {'error': 'OS Configuration puppet module association error: Missing required parameters'}
        url = f"{osc_api_url.rstrip('/')}/nodes/{server_id}/environments"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"{access_control_token.authorization_header}",
            "X-Target-Account-Id": f"{account_id}"
        }

        response = requests.put(url, json={"environment": environment}, headers=headers)
        if response.status_code == 200:
            return {}
        return {
            'error': f"OS Configuration puppet module association error : {response.status_code}: {response.text}"
        }
    except Exception as exc:
        status_code = getattr(exc, 'status_code', None)
        return {
            'error': f"{status_code or 'OS Configuration puppet module association error'}: {str(exc)}"
        }


def main():
    parser = argparse.ArgumentParser(
        description="Bulk precheck on servers from a CSV file."
    )
    parser.add_argument('-f', '--file-path', type=str, required=True, help='Server list csv file path')
    parser.add_argument('--osc-client-id', type=str, required=True, help='Client ID with OSConfiguration privileges')
    parser.add_argument('--osc-client-secret', type=str, required=False, help='Client secret with OSConfiguration privileges')
    parser.add_argument('--osc-account-id', type=str, required=True, help='Account ID with OSConfiguration privileges')

    args = parser.parse_args()
    if not args.osc_client_secret:
        args.osc_client_secret = getpass(prompt='Osconfig Client secret: ')

    output_csv = create_output_csv_with_extra_columns(args.file_path)

    processed_rows = []

    with open(output_csv, newline='', encoding='utf-8-sig') as infile:
        sample = infile.read(4096)
        infile.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=';,\t')
            delimiter = dialect.delimiter
        except Exception:
            delimiter = ';'
        reader = csv.reader(infile, delimiter=delimiter)
        headers = next(reader)
        rows = list(reader)

    header_map = {h.strip().lstrip('*').strip(): i for i, h in enumerate(headers)}
    error_idx = len(headers) - 2
    job_id_idx = len(headers) - 1
    scopes = ["osc:read", "osc:write"]
    acl_token_generator = CachingTokenGenerator(args.osc_client_id, args.osc_client_secret, args.osc_account_id, scopes)

    for row in rows:
        print('.')
        try:
            row_data = {h.strip().lstrip('*').strip(): row[idx] for h, idx in header_map.items() if idx < len(row)}

            with acl_token_generator.generate() as token:
                environment_result = change_server_puppet_environments(
                    osc_api_url=OSC_API_URL,
                    server_id=row_data["server_id"],
                    environment="unstable",
                    account_id=row_data["account_id"],
                    access_control_token=token
                )
                if isinstance(environment_result, dict) and 'error' in environment_result:
                    row[error_idx] = environment_result['error']
                    processed_rows.append(row)
                    continue

                association_payload = {
                    "modules": [
                        {
                            "name": "sg_illumio_ven::precheck",
                            "params": {}
                        }
                    ]
                }
                association_result = associate_puppet_module_with_server(
                    osc_api_url=OSC_API_URL,
                    server_id=row_data["server_id"],
                    association_payload=association_payload,
                    account_id=row_data["account_id"],
                    access_control_token=token
                )
                if isinstance(association_result, dict) and 'error' in association_result:
                    row[error_idx] = association_result['error']
                    processed_rows.append(row)
                    continue

                precheck_call_result = run_precheck_puppet_module(
                    osc_api_url=OSC_API_URL,
                    server_id=row_data["server_id"],
                    account_id=row_data["account_id"],
                    access_control_token=token
                )
                if isinstance(precheck_call_result, dict) and 'error' in precheck_call_result:
                    row[error_idx] = precheck_call_result['error']
                elif isinstance(precheck_call_result, str):
                    row[job_id_idx] = precheck_call_result
                processed_rows.append(row)
        except Exception as e:
            if "Missing Client ID or Secret" in str(e):
                print("Error to get Access Control Token for OS Configuration API: Check osc_client_id/osc_client_secret/osc_account_id")
                sys.exit(1)
            row[error_idx] = traceback.format_exc()
            processed_rows.append(row)
            continue

    with open(output_csv, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile, delimiter=delimiter)
        writer.writerow(headers)
        writer.writerows(processed_rows)

    print("END: check the output file.")


if __name__ == "__main__":
    main()
