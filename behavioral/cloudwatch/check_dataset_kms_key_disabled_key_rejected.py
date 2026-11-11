"""dataset-kms-key-disabled-key-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "dataset-kms-key-disabled-key-rejected"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateDatasetKmsKey rejects a disabled KMS key with an AccessDenied
    error and does not change the dataset's encryption state; re-enabling the
    same key lets the identical call succeed."""
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # The key policy must grant the CloudWatch service the permissions it
    # needs to even evaluate the key, otherwise AssociateDatasetKmsKey fails
    # with AccessDenied (a KMS-policy problem) rather than exercising the
    # disabled-key rejection path we actually want to test here.
    policy = json.dumps(
        {
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
    )

    def _make_key(label: str) -> tuple[str, str]:
        key = kms.create_key(
            Description=ctx.unique_name(f"sim2real-cw-{label}-"),
            Policy=policy,
            Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
        )["KeyMetadata"]
        kid = key["KeyId"]
        ctx.on_cleanup(
            lambda kid=kid: _ignore_errors(
                lambda: kms.schedule_key_deletion(KeyId=kid, PendingWindowInDays=7)
            )
        )
        return kid, key["Arn"]

    # Positive control: a second, always-enabled key so the "effect absent"
    # check below has a real prior association to hold constant, not a
    # tautology against the same key it is about to be denied.
    control_id, control_arn = _make_key("control-key")
    target_id, target_arn = _make_key("disabled-key")

    _accepted(
        lambda: cw.associate_dataset_kms_key(
            DatasetIdentifier="default", KmsKeyArn=control_arn
        ),
        retry_on=("KMSAccessDeniedException",),
        timeout_s=30,
        interval_s=3,
    )
    after_control = cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")
    assert after_control == control_arn, (
        f"positive control did not take effect: expected {control_arn!r}, got {after_control!r}"
    )

    # Break exactly one thing: disable the key we are about to try to rotate onto.
    kms.disable_key(KeyId=target_id)
    _wait_key_state(kms, target_id, "Disabled")

    # Freshly-applied key policies can take a few seconds to propagate; a
    # wrapped KMSAccessDeniedException in that window is transient and worth
    # retrying through. On real AWS, however, CloudWatch's dataset-encryption
    # API does not surface a KMS-specific "disabled key" exception at all -
    # it rejects a disabled key with the generic "AccessDenied" error, which
    # is the stable (non-transient) outcome we actually want to assert here.
    code, message = _retry_refusal(
        lambda: cw.associate_dataset_kms_key(
            DatasetIdentifier="default", KmsKeyArn=target_arn
        ),
        retry_on=("KMSAccessDeniedException",),
        timeout_s=30,
        interval_s=3,
    )
    assert code == "AccessDenied", f"expected AccessDenied, got {code} ({message!r})"
    assert message == f"KMS key {target_arn} is disabled.", (
        f"unexpected AccessDenied message {message!r}"
    )

    # The dataset's encryption configuration must be unchanged by the rejected call.
    after_rejected = cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")
    assert after_rejected == control_arn, (
        f"dataset encryption changed despite rejected association: "
        f"{control_arn!r} -> {after_rejected!r}"
    )

    # Restore: re-enable the same key and demand the identical call now succeeds.
    kms.enable_key(KeyId=target_id)
    _wait_key_state(kms, target_id, "Enabled")
    _accepted(
        lambda: cw.associate_dataset_kms_key(
            DatasetIdentifier="default", KmsKeyArn=target_arn
        ),
        retry_on=("KMSAccessDeniedException",),
        timeout_s=30,
        interval_s=3,
    )
    after_restored = cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")
    assert after_restored == target_arn, (
        f"restored key did not take effect: expected {target_arn!r}, got {after_restored!r}"
    )


def _ignore_errors(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _refusal(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return botocore (Error.Code, Error.Message) of the refusal. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _retry_refusal(
    fn: Callable[[], Any],
    *,
    retry_on: tuple[str, ...],
    timeout_s: float = 30.0,
    interval_s: float = 3.0,
) -> tuple[str, str]:
    """_refusal(fn), repeated while the refusal code is a transient one in retry_on."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = _refusal(fn)
        if code not in retry_on or time.monotonic() >= deadline:
            return code, message
        time.sleep(interval_s)


def _accepted(
    fn: Callable[[], Any],
    *,
    retry_on: tuple[str, ...],
    timeout_s: float = 30.0,
    interval_s: float = 3.0,
) -> Any:
    """Call fn() until it succeeds, retrying only the transient codes in retry_on; any other
    refusal, or a transient one past the deadline, raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") not in retry_on:
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _wait_key_state(kms: Any, key_id: str, expected_state: str, timeout_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
        if last == expected_state:
            return
        time.sleep(1.5)
    raise AssertionError(f"key never reached state {expected_state}, last was {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
