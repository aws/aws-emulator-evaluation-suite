"""backup-vault-access-policy-malformed-rejected."""
from __future__ import annotations

import json

import botocore.exceptions

from behavioral_harness import tags

CHECK = "backup-vault-access-policy-malformed-rejected"
GROUP = "overly-permissive"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A malformed access-policy document is rejected and does not clobber the valid policy."""
    backup = ctx.client("backup")
    vault_name = ctx.unique_name("sim2real-behav-vapneg-")

    backup.create_backup_vault(BackupVaultName=vault_name)
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    # Positive control: a syntactically valid policy is accepted and readable back.
    valid_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "sim2realValid",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "backup:CopyIntoBackupVault",
                    "Resource": "*",
                }
            ],
        }
    )
    backup.put_backup_vault_access_policy(BackupVaultName=vault_name, Policy=valid_policy)
    got = backup.get_backup_vault_access_policy(BackupVaultName=vault_name)
    got_sid = json.loads(got["Policy"])["Statement"][0]["Sid"]
    assert got_sid == "sim2realValid", f"expected positive control Sid sim2realValid, got {got_sid!r}"

    # Negative: a malformed (non-JSON) policy document is rejected.
    code, message = _error(
        lambda: backup.put_backup_vault_access_policy(
            BackupVaultName=vault_name, Policy="{not-valid-json"
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for malformed policy, got {code!r}"
    )
    assert message == (
        "Provided Policy is not valid. Please input a valid policy and retry the request."
    ), f"actual_message={message!r}"

    # Effect is absent: the previously-valid policy is still in place, unchanged.
    still = backup.get_backup_vault_access_policy(BackupVaultName=vault_name)
    still_sid = json.loads(still["Policy"])["Statement"][0]["Sid"]
    assert still_sid == "sim2realValid", (
        f"malformed policy clobbered the previously-valid policy: expected Sid sim2realValid, got {still_sid!r}"
    )


def _error(fn):
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected malformed policy to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
