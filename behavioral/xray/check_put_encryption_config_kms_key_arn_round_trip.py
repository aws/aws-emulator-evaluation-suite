"""put-encryption-config-kms-key-arn-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-encryption-config-kms-key-arn-round-trip"
GROUP = "representation"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:xray-encryption")
def run(ctx) -> None:
    """A KMS key ARN set via PutEncryptionConfig is echoed with Type KMS in the response and read
    back unchanged by GetEncryptionConfig, with Status UPDATING or ACTIVE."""
    xray = ctx.client("xray")
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    original = xray.get_encryption_config()["EncryptionConfig"]

    account_id = sts.get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableIAMUserPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowXRayUse",
                "Effect": "Allow",
                "Principal": {"Service": "xray.amazonaws.com"},
                "Action": [
                    "kms:Decrypt",
                    "kms:GenerateDataKey",
                    "kms:DescribeKey",
                    "kms:CreateGrant",
                ],
                "Resource": "*",
            },
        ],
    }
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-xray-key-"),
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    key_id = key["KeyId"]
    # LIFO cleanup: restore the config before the key is scheduled for deletion.
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    ctx.on_cleanup(lambda: _restore_encryption_config(xray, original))

    put_resp = _put_encryption_config_with_retry(xray, key_arn)
    put_config = put_resp["EncryptionConfig"]
    assert put_config["Type"] == "KMS", f"expected Type 'KMS', got {put_config['Type']!r}"
    assert put_config["KeyId"] == key_arn, f"expected KeyId {key_arn!r}, got {put_config['KeyId']!r}"

    # Poll briefly for propagation; a new CMK can sit in UPDATING for a long time.
    deadline = time.monotonic() + 60.0
    config = xray.get_encryption_config()["EncryptionConfig"]
    while config.get("KeyId") != key_arn and time.monotonic() < deadline:
        time.sleep(5.0)
        config = xray.get_encryption_config()["EncryptionConfig"]
    assert config["Type"] == "KMS", f"expected Type 'KMS', got {config['Type']!r}"
    assert config["KeyId"] == key_arn, f"expected KeyId {key_arn!r}, got {config.get('KeyId')!r}"
    assert config.get("Status") in ("UPDATING", "ACTIVE"), f"unexpected status: {config.get('Status')!r}"


def _put_encryption_config_with_retry(xray, key_arn: str, timeout_s: float = 20.0, interval_s: float = 5.0) -> dict:
    """Retry past a transient AccessDeniedException while a new CMK's key policy propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return xray.put_encryption_config(Type="KMS", KeyId=key_arn)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _restore_encryption_config(xray, original: dict) -> None:
    """Teardown: restore the original config, retrying every 2 s while a previous change applies."""
    if original.get("Type") == "KMS" and original.get("KeyId"):
        kwargs = {"Type": "KMS", "KeyId": original["KeyId"]}
    else:
        kwargs = {"Type": "NONE"}
    deadline = time.monotonic() + 840.0  # the suite's 900 s cleanup budget minus a margin
    while True:
        try:
            xray.put_encryption_config(**kwargs)
            return
        except xray.exceptions.InvalidRequestException as exc:
            if "A previous change is currently being applied" not in str(exc):
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

