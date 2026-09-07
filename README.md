# gen2_install

Bulk installation and removal of the Illumio agent through OSC/Puppet.

## Uninstall

Add `--uninstall` to the usual command. In this mode the script:

1. associates `sg_illumio_ven` with `ensure=absent`;
2. starts and monitors the Puppet job;
3. always attempts to dissociate `sg_illumio_ven` after a terminal job result, or
   after a job launch/status error;
4. records the Puppet and dissociation outcomes separately in the CSV, XLSX and log.

Only `server_id`, `account_id` and `osc_api_url` are required in an uninstall input
file. The `--pce` argument is retained for command-line compatibility and output
naming; PCE credentials and pairing-profile fields are not required.

```bash
python gen2_bulk_install.py \
  --uninstall \
  --file-path servers.csv \
  --pce prd \
  --osc-client-id "$OSC_CLIENT_ID" \
  --osc-client-secret "$OSC_CLIENT_SECRET" \
  --osc-account-id "$OSC_ACCOUNT_ID"
```

Empty or whitespace-only CSV records are ignored for both install and uninstall
operations and are not copied to result files.
