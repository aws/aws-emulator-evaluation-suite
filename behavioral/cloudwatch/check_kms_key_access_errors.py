"""kms-key-access-errors."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kms-key-access-errors"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']


def _err(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _associate_ok(cw, key_arn):
    """True once AssociateDatasetKmsKey succeeds; False on a ClientError still settling."""
    try:
        cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn)
    except ClientError:
        return False
    return True


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _cloudwatch_kms_policy(account, *, allow_cloudwatch):
    statements = [
        {
            "Sid": "EnableRootAccess",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "kms:*",
            "Resource": "*",
        }
    ]
    if allow_cloudwatch:
        statements.append(
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
            }
        )
    return {"Version": "2012-10-17", "Statement": statements}


def _create_kms_key(ctx, policy):
    """Create a real KMS key with the given key policy. Returns (key_id, key_arn)."""
    kms = ctx.client("kms")
    resp = kms.create_key(
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    key_arn = resp["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    return key_id, key_arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateDatasetKmsKey rejects a key policy without a CloudWatch grant and a disabled key,
    both as AccessDenied with distinct messages, and succeeds once each precondition is fixed.
    """
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    account = ctx.client("sts").get_caller_identity()["Account"]

    def _reset():
        try:
            cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_reset)
    _reset()

    def _associate_succeeds(key_arn, *, description):
        """Poll AssociateDatasetKmsKey past transient KMS propagation errors, then confirm via GetDataset."""
        _poll_until(
            lambda: _associate_ok(cw, key_arn),
            lambda ok: ok,
            timeout_s=60,
            interval_s=5,
            description=description,
        )
        ds = cw.get_dataset(DatasetIdentifier="default")
        assert ds.get("KmsKeyArn") == key_arn, (
            f"expected AssociateDatasetKmsKey to take effect once the precondition was fixed, "
            f"got KmsKeyArn={ds.get('KmsKeyArn')!r}"
        )

    # The account root has full access, but cloudwatch.amazonaws.com has no grant.
    no_cw_key_id, no_cw_key_arn = _create_kms_key(ctx, _cloudwatch_kms_policy(account, allow_cloudwatch=False))

    def call_denied():
        cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=no_cw_key_arn)

    code, message = _err(call_denied)
    assert code == "AccessDenied", (
        f"expected AccessDenied when the key policy doesn't grant CloudWatch access, got {code}"
    )
    assert message == (
        f"Unable to validate KMS key {no_cw_key_arn}. Verify the key exists and the key policy "
        "grants kms:DescribeKey to the CloudWatch service principal."
    ), f"unexpected AccessDenied message for a key without a CloudWatch grant: {message!r}"
    ds = cw.get_dataset(DatasetIdentifier="default")
    assert ds.get("KmsKeyArn") != no_cw_key_arn, "a rejected association must not take effect"

    # Granting the same key proves the rejection was the missing grant, not a blanket denial.
    kms.put_key_policy(
        KeyId=no_cw_key_id,
        PolicyName="default",
        Policy=json.dumps(_cloudwatch_kms_policy(account, allow_cloudwatch=True)),
    )
    _associate_succeeds(
        no_cw_key_arn,
        description="AssociateDatasetKmsKey succeeds once the key policy grants CloudWatch access",
    )
    _reset()

    disabled_key_id, disabled_key_arn = _create_kms_key(ctx, _cloudwatch_kms_policy(account, allow_cloudwatch=True))
    kms.disable_key(KeyId=disabled_key_id)
    _poll_until(
        lambda: kms.describe_key(KeyId=disabled_key_id)["KeyMetadata"]["KeyState"],
        lambda state: state == "Disabled",
        timeout_s=30,
        interval_s=2,
        description="KMS key reaches Disabled state",
    )

    def call_disabled():
        cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=disabled_key_arn)

    # KMS is eventually consistent after create/disable and can transiently throttle.
    code, message = _poll_until(
        lambda: _err(call_disabled),
        lambda c: c[0] != "Throttling",
        timeout_s=30,
        interval_s=5,
        description="AssociateDatasetKmsKey settles past transient Throttling",
    )
    assert code == "AccessDenied", (
        f"expected AccessDenied for a disabled KMS key, got {code}"
    )
    assert message == f"KMS key {disabled_key_arn} is disabled.", f"unexpected AccessDenied message for a disabled key: {message!r}"

    ds = cw.get_dataset(DatasetIdentifier="default")
    assert ds.get("KmsKeyArn") != disabled_key_arn, "a rejected association must not take effect"

    # Re-enabling proves the rejection tracked the Disabled state, not a blanket denial.
    kms.enable_key(KeyId=disabled_key_id)
    _poll_until(
        lambda: kms.describe_key(KeyId=disabled_key_id)["KeyMetadata"]["KeyState"],
        lambda state: state == "Enabled",
        timeout_s=30,
        interval_s=2,
        description="KMS key reaches Enabled state",
    )
    _associate_succeeds(
        disabled_key_arn,
        description="AssociateDatasetKmsKey succeeds once the key is re-enabled",
    )

    _reset()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
