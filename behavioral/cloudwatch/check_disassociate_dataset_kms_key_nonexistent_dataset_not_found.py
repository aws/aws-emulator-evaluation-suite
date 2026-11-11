"""disassociate-dataset-kms-key-nonexistent-dataset-not-found."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "disassociate-dataset-kms-key-nonexistent-dataset-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateDatasetKmsKey with no key associated fails with ResourceNotFoundException "No CMK
    association found for dataset default."; after a key is associated it succeeds and clears the
    key, and a second call fails the same way without changing the dataset."""
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    _safe_disassociate(cw)  # normalize: ensure no CMK is currently associated

    code, message = _client_error(lambda: cw.disassociate_dataset_kms_key(DatasetIdentifier="default"))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = "No CMK association found for dataset default."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    key_arn = _create_cw_ready_kms_key(ctx, kms, account_id)
    cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn)
    # Registered after the key's cleanup: LIFO restores the dataset before the key's deletion.
    ctx.on_cleanup(lambda: _safe_disassociate(cw))
    ds = cw.get_dataset(DatasetIdentifier="default")
    assert ds.get("KmsKeyArn") == key_arn, f"expected KmsKeyArn={key_arn!r} after association, got {ds.get('KmsKeyArn')!r}"

    cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    ds2 = cw.get_dataset(DatasetIdentifier="default")
    assert ds2.get("KmsKeyArn") is None, "dataset must revert to AWS-owned key encryption after disassociation"

    code2, message2 = _client_error(lambda: cw.disassociate_dataset_kms_key(DatasetIdentifier="default"))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException again, got {code2!r}"
    assert message2 == expected_message, f"expected message {expected_message!r} again, got {message2!r}"

    ds3 = cw.get_dataset(DatasetIdentifier="default")
    assert ds3.get("KmsKeyArn") is None, "rejected disassociate must not have any effect on the dataset's key state"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_disassociate(cw) -> None:
    from botocore.exceptions import ClientError

    try:
        cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _cw_ready_key_policy(account_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCloudWatchService",
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


def _create_cw_ready_kms_key(ctx, kms, account_id: str) -> str:
    policy = _cw_ready_key_policy(account_id)
    resp = kms.create_key(
        Policy=json.dumps(policy),
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Description=ctx.unique_name("sim2real-behav-cw-dataset-kms-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "cloudwatch-behavioral"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    key_arn = resp["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
