"""replicate-key-tags-and-policy-preserved-across-region."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replicate-key-tags-and-policy-preserved-across-region"
GROUP = "representation"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags and a key policy given to CreateKey and again to ReplicateKey come back unchanged from
    ListResourceTags and GetKeyPolicy on both the primary and the replica."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    primary_region = ctx.region
    # The replica Region must differ from the primary; the choice is arbitrary.
    replica_region = "us-west-2" if primary_region != "us-west-2" else "us-east-1"
    primary_kms = ctx.client("kms")
    replica_kms = ctx.client("kms", region=replica_region)

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableRootFullAccess",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "sim2real-marker-statement",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:DescribeKey",
                    "Resource": "*",
                },
            ],
        }
    )
    tags = [
        {"TagKey": "sim2real-team", "TagValue": "kms-behavioral"},
        {"TagKey": "sim2real-purpose", "TagValue": "replicate-key-representation"},
    ]

    created = primary_kms.create_key(
        MultiRegion=True,
        KeyUsage="ENCRYPT_DECRYPT",
        Policy=policy_doc,
        Tags=tags,
        Description=ctx.unique_name("sim2real-mrk-repr-"),
    )
    key_id = created["KeyMetadata"]["KeyId"]

    def _cleanup() -> None:
        for region_client in (primary_kms, replica_kms):
            try:
                region_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    # ReplicateKey does not copy tags or policy from the primary, so pass them again.
    primary_kms.replicate_key(
        KeyId=key_id, ReplicaRegion=replica_region, Policy=policy_doc, Tags=tags
    )

    replica_meta = _poll_until(
        lambda: _try_describe(replica_kms, key_id),
        lambda m: m is not None and m["KeyState"] == "Enabled",
        timeout_s=180,
        interval_s=10,
    )
    actual_mr_type = replica_meta["MultiRegionConfiguration"]["MultiRegionKeyType"]
    assert actual_mr_type == "REPLICA", f"expected replica MultiRegionKeyType=REPLICA, got {actual_mr_type!r}"

    primary_tags = {t["TagKey"]: t["TagValue"] for t in primary_kms.list_resource_tags(KeyId=key_id)["Tags"]}
    replica_tags = {t["TagKey"]: t["TagValue"] for t in replica_kms.list_resource_tags(KeyId=key_id)["Tags"]}
    expected_tags = {t["TagKey"]: t["TagValue"] for t in tags}
    assert primary_tags == expected_tags, f"expected primary tags {expected_tags}, got {primary_tags}"
    assert replica_tags == expected_tags, f"expected replica tags {expected_tags}, got {replica_tags}"

    primary_policy = json.loads(primary_kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    replica_policy = json.loads(replica_kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    expected_policy = json.loads(policy_doc)
    assert primary_policy == expected_policy, f"expected primary policy {expected_policy}, got {primary_policy}"
    assert replica_policy == expected_policy, f"expected replica policy {expected_policy}, got {replica_policy}"


def _try_describe(client, key_id):
    try:
        return client.describe_key(KeyId=key_id)["KeyMetadata"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return None
        raise


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
