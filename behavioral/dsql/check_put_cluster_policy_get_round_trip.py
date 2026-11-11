"""put-cluster-policy-get-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-cluster-policy-get-round-trip"
GROUP = "data-plane"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutClusterPolicy persists a resource policy that GetClusterPolicy returns, with an incrementing version."""
    dsql = ctx.client("dsql")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    marker = ctx.unique_name("sim2real-dsql-policy-rt-")
    created = dsql.create_cluster(deletionProtectionEnabled=False, tags={"sim2real-purpose": marker})
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))
    final_status = _poll_until(
        lambda: dsql.get_cluster(identifier=identifier)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final_status == "ACTIVE", f"cluster reached terminal status {final_status!r} instead of ACTIVE"

    policy_v1 = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAccountConnect",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "dsql:DbConnect",
                "Resource": "*",
            }
        ],
    }
    put1 = dsql.put_cluster_policy(identifier=identifier, policy=json.dumps(policy_v1))
    version1 = put1["policyVersion"]

    got1 = dsql.get_cluster_policy(identifier=identifier)
    assert json.loads(got1["policy"]) == policy_v1, f"expected {policy_v1}, got {got1['policy']}"
    assert got1["policyVersion"] == version1, f"expected policyVersion {version1!r}, got {got1['policyVersion']!r}"

    policy_v2 = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAccountConnectAdmin",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["dsql:DbConnect", "dsql:DbConnectAdmin"],
                "Resource": "*",
            }
        ],
    }
    put2 = dsql.put_cluster_policy(
        identifier=identifier, policy=json.dumps(policy_v2), expectedPolicyVersion=version1
    )
    version2 = put2["policyVersion"]
    assert version2 != version1, "policyVersion did not change after an update"

    got2 = dsql.get_cluster_policy(identifier=identifier)
    assert json.loads(got2["policy"]) == policy_v2, f"expected {policy_v2}, got {got2['policy']}"
    assert got2["policyVersion"] == version2, f"expected policyVersion {version2!r}, got {got2['policyVersion']!r}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_cluster(ctx, identifier):
    from botocore.exceptions import ClientError

    dsql = ctx.client("dsql")
    try:
        dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
