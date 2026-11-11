"""disassociate-dataset-kms-key-without-association-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-dataset-kms-key-without-association-conflict"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


def _kms_key_policy(account_id: str) -> str:
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateDatasetKmsKey with no current association fails with ResourceNotFoundException.

    A positive control (disassociating right after a real association) is exercised first to
    prove the same call succeeds when the precondition (an existing association) holds.
    """
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Baseline: make sure the dataset starts unassociated for this test.
    try:
        cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    except ClientError:
        pass

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-cw-dataset-key-"),
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Policy=_kms_key_policy(account_id),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    last_err = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn)
            last_err = None
            break
        except ClientError as e:
            last_err = e
            time.sleep(3.0)
    if last_err is not None:
        raise AssertionError(f"setup AssociateDatasetKmsKey never succeeded: {last_err}")

    # Positive control: disassociating a dataset that IS currently associated succeeds cleanly.
    cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    after_control = cw.get_dataset(DatasetIdentifier="default")
    assert "KmsKeyArn" not in after_control, (
        f"positive-control disassociate reported success but KmsKeyArn is still {after_control.get('KmsKeyArn')!r}"
    )

    # Negative: disassociating again, with no association present, must fail specifically.
    try:
        result = cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
    else:
        raise AssertionError(f"expected ResourceNotFoundException on second disassociate, got success: {result!r}")
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "No CMK association found for dataset default.", f"unexpected ResourceNotFoundException message {message!r}"

    # The forbidden effect (a spurious mutation/association) did not happen.
    after_negative = cw.get_dataset(DatasetIdentifier="default")
    assert "KmsKeyArn" not in after_negative, (
        f"rejected disassociate must not mutate state, but KmsKeyArn is {after_negative.get('KmsKeyArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
