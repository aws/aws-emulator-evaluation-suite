"""associate-dataset-kms-key-cross-account-key-denied."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-dataset-kms-key-cross-account-key-denied"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDatasetKmsKey with a key ARN in another account fails with ValidationError "KMS key
    account <foreign> does not match caller account <own>" and leaves the dataset's key unchanged;
    a same-account key whose policy grants CloudWatch access associates."""
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")
    own_account = sts.get_caller_identity()["Account"]
    foreign_account = "111111111111" if own_account != "111111111111" else "222222222222"
    foreign_key_arn = f"arn:aws:kms:{ctx.region}:{foreign_account}:key/{uuid.uuid4()}"

    before = cw.get_dataset(DatasetIdentifier="default")
    before_kms = before.get("KmsKeyArn")

    code, message = _refusal(
        lambda: cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=foreign_key_arn)
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r} ({message!r})"
    assert message == f"KMS key account {foreign_account} does not match caller account {own_account}", (
        f"unexpected ValidationError message {message!r}"
    )

    # effect absent: the dataset's KMS association is unchanged
    after = cw.get_dataset(DatasetIdentifier="default")
    assert after.get("KmsKeyArn") == before_kms, (
        f"rejected AssociateDatasetKmsKey must leave the association unchanged: "
        f"expected {before_kms!r}, got {after.get('KmsKeyArn')!r}"
    )

    # positive control: a real, same-account key with a policy that grants CloudWatch access
    # associates successfully
    kms = ctx.client("kms")
    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{own_account}:root"},
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
        ],
    }
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-cw-dataset-key-"),
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))

    def _restore():
        if before_kms:
            cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=before_kms)
        else:
            try:
                cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key["Arn"])
    ctx.on_cleanup(_restore)
    confirmed = cw.get_dataset(DatasetIdentifier="default")
    assert confirmed["KmsKeyArn"] == key["Arn"], (
        f"positive control: expected the properly-permissioned same-account key to be "
        f"associated, expected {key['Arn']!r}, got {confirmed.get('KmsKeyArn')!r}"
    )


def _refusal(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) of the refusal. An unexpected
    SUCCESS raises, so a target accepting a call AWS refuses is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

