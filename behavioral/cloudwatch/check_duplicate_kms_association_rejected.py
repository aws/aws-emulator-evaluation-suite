"""duplicate-kms-association-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-kms-association-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']
_TEARDOWN_S = 300.0

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises, so an emulator accepting input AWS refuses is never reported as a
    mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With key A associated to the `default` dataset, AssociateDatasetKmsKey with a key CloudWatch
    cannot use fails with AccessDenied "Unable to validate KMS key <arn>. ..." and key A stays;
    a CloudWatch-accessible key B then replaces A."""
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    account = ctx.client("sts").get_caller_identity()["Account"]

    def _reset_dataset():
        """Disassociate; no association is already clean, a concurrent change is retried."""
        deadline = time.monotonic() + _TEARDOWN_S
        while True:
            try:
                cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code != "ConflictException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2.0)

    _reset_dataset()
    ctx.on_cleanup(_reset_dataset)

    def _make_cw_key():
        policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "EnableRootAccess",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
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
        resp = kms.create_key(Policy=policy, Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}])
        key_id = resp["KeyMetadata"]["KeyId"]
        ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
        return resp["KeyMetadata"]["Arn"]

    key_a_arn = _make_cw_key()
    cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_a_arn)

    def dataset_key():
        return cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")

    _poll_until(dataset_key, lambda k: k == key_a_arn, timeout_s=30, interval_s=3)

    # An inaccessible-to-CloudWatch key must be rejected while key A is active.
    no_cw_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableRootAccess",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        }
    )
    resp = kms.create_key(Policy=no_cw_policy, Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}])
    no_cw_key_id = resp["KeyMetadata"]["KeyId"]
    no_cw_key_arn = resp["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda _k=no_cw_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    def call_inaccessible():
        cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=no_cw_key_arn)

    code, message = _poll_until(
        lambda: _err(call_inaccessible),
        lambda r: r[0] != "Throttling",
        timeout_s=30,
        interval_s=5,
        description="AssociateDatasetKmsKey (inaccessible key) settles past transient Throttling",
    )
    assert code == "AccessDenied", (
        f"expected AccessDenied associating a key CloudWatch cannot use while a valid key is "
        f"already active, got {code}"
    )
    assert message == (
        f"Unable to validate KMS key {no_cw_key_arn}. Verify the key exists and the key policy "
        "grants kms:DescribeKey to the CloudWatch service principal."
    ), message
    still_a = dataset_key()
    assert still_a == key_a_arn, (
        f"a rejected duplicate-association attempt must not disturb the active key, "
        f"expected {key_a_arn}, got {still_a}"
    )

    # A DIFFERENT, genuinely CloudWatch-accessible key, by contrast, is permitted
    # to overwrite the active association -- confirming the rejection above is
    # specifically about key USABILITY, not about "already has an active
    # association" being blanket-forbidden.
    key_b_arn = _make_cw_key()
    cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_b_arn)
    swapped = _poll_until(dataset_key, lambda k: k == key_b_arn, timeout_s=30, interval_s=3)
    assert swapped == key_b_arn, f"expected the active association to swap to key B, got {swapped}"

    _reset_dataset()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
