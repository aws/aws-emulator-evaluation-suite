"""disassociate-dataset-kms-key-not-associated-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-dataset-kms-key-not-associated-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With a real key associated, DisassociateDatasetKmsKey clears it; called again with nothing
    associated it fails with ResourceNotFoundException "No CMK association found for dataset
    default." and the dataset gains no key."""
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # The "default" dataset is implicit for every account/region. Make sure it is in the
    # "no key associated" state the check needs before probing it.
    _safe_disassociate(cw)
    assert "KmsKeyArn" not in cw.get_dataset(DatasetIdentifier="default"), (
        "dataset unexpectedly still has a KMS key associated"
    )

    key_arn = _create_cw_ready_kms_key(ctx, kms, account_id)

    # Positive control: the identical call succeeds once a real key is associated, and an
    # independent read confirms the association is actually cleared.
    _associate_until_ready(cw, key_arn)
    # Registered after the key's cleanup: LIFO restores the dataset before the key's deletion.
    ctx.on_cleanup(lambda: _safe_disassociate(cw))
    cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    controlled = cw.get_dataset(DatasetIdentifier="default")
    assert "KmsKeyArn" not in controlled, "positive-control disassociate did not clear the key"

    # Negative: disassociating again, with nothing currently associated, must fail
    # specifically, not silently succeed as a no-op.
    code, message = _failure(lambda: cw.disassociate_dataset_kms_key(DatasetIdentifier="default"))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "No CMK association found for dataset default.", (
        f"expected the no-association message, got {message!r}"
    )

    # Effect-absent: an independent read shows the rejected call caused no mutation.
    after = cw.get_dataset(DatasetIdentifier="default")
    assert "KmsKeyArn" not in after, "dataset unexpectedly gained a KmsKeyArn from a rejected disassociation"


def _safe_disassociate(cw) -> None:
    try:
        cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _associate_until_ready(cw, key_arn: str, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn)
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(3.0)
    raise AssertionError(f"setup AssociateDatasetKmsKey never succeeded: {last_err}")


def _cw_ready_key_policy(account_id: str) -> str:
    root_arn = f"arn:aws:iam::{account_id}:root"
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableIAMUserPermissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": root_arn},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowCloudWatchServiceToUseKey",
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
            ],
        }
    )


def _create_cw_ready_kms_key(ctx, kms, account_id: str) -> str:
    resp = kms.create_key(
        Description=ctx.unique_name("sim2real-cw-dataset-key-"),
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Policy=_cw_ready_key_policy(account_id),
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = resp["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return resp["Arn"]


def _failure(fn) -> tuple:
    """Call fn(); return the (code, message) it fails with. An unexpected SUCCESS raises, so an
    over-permissive target's acceptance is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
