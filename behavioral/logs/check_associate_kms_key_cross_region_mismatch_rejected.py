"""associate-kms-key-cross-region-mismatch-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-kms-key-cross-region-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateKmsKey rejects a key from another region with InvalidParameterException and leaves
    kmsKeyId unset, while a key from the log group's own region is accepted (positive control)."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-logs-kmsregion-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    same_region_key = _create_kms_key(ctx, ctx.client("kms"))
    _grant_logs_service_key_permissions(ctx.client("kms"), same_region_key["id"], ctx.region)

    # Any region distinct from ctx.region exercises the mismatch; the specific pair is arbitrary,
    # not a region-pinned resource.
    other_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    cross_kms = ctx.client("kms", region=other_region)
    cross_region_key = _create_kms_key(ctx, cross_kms)

    code, message = _error(
        lambda: logs.associate_kms_key(
            logGroupName=group_name, kmsKeyId=cross_region_key["arn"]
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = "The specified KMS Key Id could not be found."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the log group still has no KMS key associated.
    lg = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]
    assert lg.get("kmsKeyId") is None, f"expected no kmsKeyId, found {lg.get('kmsKeyId')}"

    # Positive control: a real key from the SAME region as the log group is accepted.
    logs.associate_kms_key(logGroupName=group_name, kmsKeyId=same_region_key["arn"])

    updated = _poll_until(
        lambda: logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0],
        lambda g: g.get("kmsKeyId") == same_region_key["arn"],
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert updated["kmsKeyId"] == same_region_key["arn"], (
        f"expected kmsKeyId {same_region_key['arn']}, got {updated.get('kmsKeyId')}"
    )


def _error(fn):
    """Call fn() expecting a ClientError; return its (Code, Message). A success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result={result!r}")


def _create_kms_key(ctx, kms_client):
    key = kms_client.create_key(
        Description="sim2real logs behavioral test key",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "Sim2RealOwner", "TagValue": "behavioral-suite"}],
    )["KeyMetadata"]
    ctx.on_cleanup(
        lambda: kms_client.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7)
    )
    return {"id": key["KeyId"], "arn": key["Arn"]}


def _grant_logs_service_key_permissions(kms_client, key_id, region):
    current = json.loads(kms_client.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    current["Statement"].append(
        {
            "Sid": "AllowCloudWatchLogsUseOfKey",
            "Effect": "Allow",
            "Principal": {"Service": f"logs.{region}.amazonaws.com"},
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:Describe*",
            ],
            "Resource": "*",
        }
    )
    kms_client.put_key_policy(
        KeyId=key_id, PolicyName="default", Policy=json.dumps(current)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
