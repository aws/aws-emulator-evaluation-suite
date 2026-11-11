"""associate-dataset-kms-key-caller-missing-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-dataset-kms-key-caller-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


def _key_policy(account_id: str, caller_principal_arn: str, deny_caller_decrypt: bool) -> dict:
    statements = [
        {
            "Sid": "EnableRootPermissions",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "kms:*",
            "Resource": "*",
        },
        {
            "Sid": "AllowCloudWatchDatasetEncryption",
            "Effect": "Allow",
            "Principal": {"Service": "cloudwatch.amazonaws.com"},
            "Action": [
                "kms:DescribeKey",
                "kms:GenerateDataKey",
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
            ],
            "Resource": "*",
        },
    ]
    if deny_caller_decrypt:
        statements.append(
            {
                "Sid": "DenyCallerDecrypt",
                "Effect": "Deny",
                "Principal": {"AWS": caller_principal_arn},
                "Action": "kms:Decrypt",
                "Resource": "*",
            }
        )
    return {"Version": "2012-10-17", "Statement": statements}


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateDatasetKmsKey fails with AccessDenied (403) when the caller is denied kms:Decrypt
    even though the service principal is allowed; removing the Deny lets the same call succeed.
    """
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    caller_principal_arn = _to_principal_arn(identity["Arn"], account_id)

    original = cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")

    def _restore() -> None:
        try:
            if original:
                cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=original)
            else:
                cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_restore)

    created = kms.create_key(
        Description=ctx.unique_name("sim2real-cw-callerdeny-key-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Policy=json.dumps(_key_policy(account_id, caller_principal_arn, deny_caller_decrypt=True)),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id, key_arn = created["KeyId"], created["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # Real AWS returns generic AccessDenied, not the modeled KmsAccessDeniedException.
    code, message, status = _error(lambda: cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn))
    # message varies: per-request authorization id (it ends with the request id of CloudWatch's
    # internal KMS call, which the response does not expose anywhere else).
    assert code == "AccessDenied", f"expected AccessDenied, got {code}: {message}"
    assert status == 403, f"expected HTTP 403 for AccessDenied, got {status}"
    # The text before the KMS request id is stable and asserted exactly.
    assert message.partition(" KMS request id: ")[0] == (
        f"Caller lacks kms:Decrypt permission on KMS key {key_arn}. "
        "Update your IAM policy to include kms:Decrypt on this key."
    ), message
    assert message.partition(" KMS request id: ")[2].endswith("."), message

    dataset = cw.get_dataset(DatasetIdentifier="default")
    assert dataset.get("KmsKeyArn") == original, (
        f"dataset must still reference {original!r} after the rejected call, got {dataset.get('KmsKeyArn')!r}"
    )

    # KMS policy changes take a few seconds to propagate, hence the bounded retry.
    kms.put_key_policy(
        KeyId=key_id,
        PolicyName="default",
        Policy=json.dumps(_key_policy(account_id, caller_principal_arn, deny_caller_decrypt=False)),
    )
    last_err = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn)
            last_err = None
            break
        except ClientError as exc:
            last_err = exc.response["Error"]["Code"]
            time.sleep(3.0)
    assert last_err is None, f"expected success once Deny removed, got {last_err}"
    restored = cw.get_dataset(DatasetIdentifier="default")["KmsKeyArn"]
    assert restored == key_arn, f"expected dataset to reflect {key_arn!r} after the retry, got {restored!r}"


# ===== helpers =====
def _to_principal_arn(caller_arn, account_id):
    """Map an STS assumed-role session ARN to its IAM role ARN, as key policy principals require."""
    if ":assumed-role/" in caller_arn:
        role_name = caller_arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
        return f"arn:aws:iam::{account_id}:role/{role_name}"
    return caller_arn


def _error(fn):
    """(code, message, HTTP status) of the ClientError fn() raises. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""),
                exc.response["ResponseMetadata"]["HTTPStatusCode"])
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
