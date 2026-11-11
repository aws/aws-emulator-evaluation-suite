"""associate-dataset-kms-key-access-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-dataset-kms-key-access-denied"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


def _key_policy(account_id: str, deny_caller_decrypt: bool) -> str:
    root_arn = f"arn:aws:iam::{account_id}:root"
    statements = [
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
    ]
    if deny_caller_decrypt:
        # An explicit Deny on the account root ARN blocks kms:Decrypt for every principal in the
        # account (regardless of any identity-based IAM policy), which is exactly the condition
        # AssociateDatasetKmsKey's caller-decrypt dry run needs to fail against.
        statements.append(
            {
                "Sid": "DenyEveryoneInAccountDecrypt",
                "Effect": "Deny",
                "Principal": {"AWS": root_arn},
                "Action": "kms:Decrypt",
                "Resource": "*",
            }
        )
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDatasetKmsKey with a key the caller cannot kms:Decrypt fails with AccessDenied (403).

    Removing the explicit Deny and retrying the identical call succeeds (positive control).
    """
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-cw-dataset-key-"),
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Policy=_key_policy(account_id, deny_caller_decrypt=True),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    def _best_effort_disassociate():
        try:
            cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_best_effort_disassociate)

    # On real AWS, the caller-decrypt dry-run failure for this operation surfaces as a generic
    # "AccessDenied" error rather than the modeled KmsAccessDeniedException shape.
    deadline = time.monotonic() + 30.0
    seen_code = None
    seen_message = None
    seen_status = None
    while time.monotonic() < deadline:
        try:
            cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn)
            seen_code = "SUCCESS"
            break
        except ClientError as e:
            seen_code = e.response["Error"]["Code"]
            seen_message = e.response["Error"].get("Message", "")
            seen_status = e.response["ResponseMetadata"]["HTTPStatusCode"]
            if seen_code == "AccessDenied":
                break
            time.sleep(3.0)

    # message varies: per-request authorization id (it ends with the request id of CloudWatch's
    # internal KMS call, which the response does not expose anywhere else).
    assert seen_code == "AccessDenied", f"expected AccessDenied, got {seen_code}: {seen_message}"
    assert seen_status == 403, f"expected HTTP 403 for AccessDenied, got {seen_status}"
    # The text before the KMS request id is stable and asserted exactly.
    assert seen_message.partition(" KMS request id: ")[0] == (
        f"Caller lacks kms:Decrypt permission on KMS key {key_arn}. "
        "Update your IAM policy to include kms:Decrypt on this key."
    ), seen_message
    assert seen_message.partition(" KMS request id: ")[2].endswith("."), seen_message
    post_reject = cw.get_dataset(DatasetIdentifier="default")
    assert "KmsKeyArn" not in post_reject, (
        f"expected no KmsKeyArn on the dataset after the rejected association, "
        f"got {post_reject.get('KmsKeyArn')!r}"
    )

    # Positive control: drop the explicit Deny and retry the identical call.
    kms.put_key_policy(
        KeyId=key_id, PolicyName="default", Policy=_key_policy(account_id, deny_caller_decrypt=False)
    )
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
    assert last_err is None, f"expected success once Deny removed, got {last_err}"
    post_accept = cw.get_dataset(DatasetIdentifier="default")["KmsKeyArn"]
    assert post_accept == key_arn, f"expected dataset KmsKeyArn {key_arn!r}, got {post_accept!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
