"""associate-dataset-kms-key-access-denied-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-dataset-kms-key-access-denied-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateDatasetKmsKey with a key whose policy denies the caller kms:Decrypt fails with HTTP
    403 AccessDenied "Caller lacks kms:Decrypt permission on KMS key <arn>. ..." and leaves the
    dataset's key unchanged; once the caller's Deny is lifted, the same call associates the key."""
    sts = ctx.client("sts")
    kms = ctx.client("kms")
    cw = ctx.client("cloudwatch")

    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    caller_principal = _caller_principal_arn(identity["Arn"], account_id)

    def _policy(deny_caller_decrypt: bool) -> str:
        statements = [
            {
                "Sid": "EnableRootAccountAdmin",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCloudWatchServicePrincipal",
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
                    "Principal": {"AWS": caller_principal},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            )
        return json.dumps({"Version": "2012-10-17", "Statement": statements})

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-cw-dataset-denied-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Policy=_policy(deny_caller_decrypt=True),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    original_kms_key_arn = cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")

    def _restore_dataset() -> None:
        try:
            if original_kms_key_arn:
                cw.associate_dataset_kms_key(
                    DatasetIdentifier="default", KmsKeyArn=original_kms_key_arn
                )
            else:
                cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "KmsKeyNotFoundException",
                "ResourceNotFoundException",
            ):
                raise

    ctx.on_cleanup(_restore_dataset)

    code, message, status = _error(
        lambda: cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn)
    )
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

    # effect absent: the rejected call must not have mutated the dataset's KMS association.
    rejected_state = cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")
    assert rejected_state == original_kms_key_arn, (
        f"dataset KMS key association changed despite a rejected call: "
        f"expected {original_kms_key_arn!r}, got {rejected_state!r}"
    )

    # positive control: lift the caller's own Deny and retry the identical call -- it must
    # now succeed, isolating the caller's missing kms:Decrypt as the specific cause of the
    # rejection above rather than the key or the dataset being universally unusable.
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=_policy(deny_caller_decrypt=False))
    deadline = time.monotonic() + 30.0
    last_code = None
    while time.monotonic() < deadline:
        try:
            cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn)
            last_code = None
            break
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
        time.sleep(3.0)
    assert last_code is None, f"expected success once the caller's Deny was lifted, got {last_code}"
    confirmed_state = cw.get_dataset(DatasetIdentifier="default")["KmsKeyArn"]
    assert confirmed_state == key_arn, (
        f"expected the dataset to now be associated with {key_arn!r}, got {confirmed_state!r}"
    )


def _caller_principal_arn(arn: str, account_id: str) -> str:
    if ":assumed-role/" in arn:
        role_name = arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
        return f"arn:aws:iam::{account_id}:role/{role_name}"
    return arn


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
