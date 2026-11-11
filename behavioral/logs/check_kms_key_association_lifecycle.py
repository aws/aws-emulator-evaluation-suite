"""kms-key-association-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "kms-key-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateKmsKey attaches a key to a log group and DisassociateKmsKey removes the
    association, reflected on subsequent describes."""
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-kms-assoc-")
    logs.create_log_group(logGroupName=group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCloudWatchLogs",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": [
                    "kms:Encrypt*",
                    "kms:Decrypt*",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*",
                ],
                "Resource": "*",
            },
        ],
    }
    key = kms.create_key(
        Description="sim2real-behav logs kms association test",
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    def _associate():
        return logs.associate_kms_key(logGroupName=group_name, kmsKeyId=key_arn)

    _retry_on_code(_associate, "InvalidParameterException", attempts=10, delay_s=3)
    ctx.on_cleanup(lambda: _safe_disassociate(logs, group_name))

    described = _poll_until(
        lambda: logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0],
        lambda lg: lg.get("kmsKeyId") == key_arn,
        timeout_s=30,
        interval_s=2,
    )
    assert described["kmsKeyId"] == key_arn, (
        f"expected kmsKeyId {key_arn} after AssociateKmsKey, got {described.get('kmsKeyId')!r}"
    )

    logs.disassociate_kms_key(logGroupName=group_name)

    described_after = _poll_until(
        lambda: logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0],
        lambda lg: "kmsKeyId" not in lg,
        timeout_s=30,
        interval_s=2,
    )
    assert "kmsKeyId" not in described_after, (
        f"expected no kmsKeyId after DisassociateKmsKey, got {described_after.get('kmsKeyId')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _retry_on_code(fn, code: str, *, attempts: int = 5, delay_s: float = 2.0):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != code:
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _safe_disassociate(logs, group_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        logs.disassociate_kms_key(logGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
