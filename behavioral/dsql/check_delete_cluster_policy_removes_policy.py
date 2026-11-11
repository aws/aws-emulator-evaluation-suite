"""delete-cluster-policy-removes-policy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-cluster-policy-removes-policy"
GROUP = "data-plane"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteClusterPolicy removes the attached policy; GetClusterPolicy then reports ResourceNotFoundException."""
    dsql = ctx.client("dsql")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    created = dsql.create_cluster(deletionProtectionEnabled=False)
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))
    _poll_until(
        lambda: dsql.get_cluster(identifier=identifier)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )

    policy = {
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
    dsql.put_cluster_policy(identifier=identifier, policy=json.dumps(policy))
    # sanity: the policy is attached before we delete it.
    attached = dsql.get_cluster_policy(identifier=identifier)["policy"]
    assert attached, f"expected a non-empty policy after put_cluster_policy, got {attached!r}"

    dsql.delete_cluster_policy(identifier=identifier)

    code, message = _error(lambda: dsql.get_cluster_policy(identifier=identifier))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException from GetClusterPolicy after delete, got {code}"
    assert message == f"Aurora DSQL can't find the policy for the resource {identifier}. Verify that the policy exists.", message

    # the deleted policy is also gone as a mutation target: a second delete on the
    # now-absent policy must fail the same way, not silently no-op.
    redelete_code, redelete_message = _error(lambda: dsql.delete_cluster_policy(identifier=identifier))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from a DeleteClusterPolicy retry on an already-deleted "
        f"policy, got {redelete_code}"
    )
    assert redelete_message == f"Aurora DSQL can't find the policy for the resource {identifier}. Verify that the policy exists.", redelete_message


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
