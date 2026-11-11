"""put-cluster-policy-rejects-stale-version-and-lockout-policy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-cluster-policy-rejects-stale-version-and-lockout-policy"
GROUP = "overly-permissive"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutClusterPolicy rejects a stale expectedPolicyVersion (optimistic concurrency) and a policy
    whose principal is not a resolvable IAM entity (ValidationException), while a correctly-versioned,
    resolvable policy succeeds each time."""
    dsql = ctx.client("dsql")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-created-with": "create-cluster", "sim2real-purpose": "behavioral-test"},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))
    _poll_until(
        lambda: dsql.get_cluster(identifier=identifier)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )

    allow_policy = {
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
    put1 = dsql.put_cluster_policy(identifier=identifier, policy=json.dumps(allow_policy))
    version1 = put1["policyVersion"]

    # Advance the policy once more so version1 becomes a real, well-formed, but superseded token.
    # (DSQL validates that policy principals resolve to real IAM entities, so this references the
    # caller's own account root rather than a fabricated role ARN.)
    other_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyAdminConnect",
                "Effect": "Deny",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "dsql:DbConnectAdmin",
                "Resource": "*",
            }
        ],
    }
    put2 = dsql.put_cluster_policy(identifier=identifier, policy=json.dumps(other_policy), expectedPolicyVersion=version1)
    version2 = put2["policyVersion"]
    assert version2 != version1, f"expected policyVersion to advance past {version1!r}, got {version2!r}"

    # Boundary 1: reusing the now-stale (but well-formed and real) version1 -> ConflictException,
    # policy unchanged.
    stale_code, stale_message = _error(
        lambda: dsql.put_cluster_policy(
            identifier=identifier,
            policy=json.dumps(allow_policy),
            expectedPolicyVersion=version1,
        )
    )
    assert stale_code == "ConflictException", stale_code
    assert stale_message == f"Aurora DSQL can't find policy version {version1} for resource {identifier}. Verify that the policy exists and that the version is correct.", stale_message
    unchanged = dsql.get_cluster_policy(identifier=identifier)
    assert json.loads(unchanged["policy"]) == other_policy, (
        f"expected policy to remain {other_policy!r} after stale-version rejection, got {unchanged['policy']!r}"
    )
    assert unchanged["policyVersion"] == version2, (
        f"expected policyVersion to remain {version2!r} after stale-version rejection, got {unchanged['policyVersion']!r}"
    )

    # Boundary 2: a policy whose principal doesn't correspond to a resolvable IAM entity is rejected
    # with ValidationException (empirically verified against real AWS), and the policy is left
    # unchanged at version2.
    unresolvable_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyUnresolvablePrincipal",
                "Effect": "Deny",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:role/sim2real-does-not-exist"},
                "Action": "dsql:DbConnect",
                "Resource": "*",
            }
        ],
    }
    unresolvable_code, unresolvable_message = _error(
        lambda: dsql.put_cluster_policy(
            identifier=identifier, policy=json.dumps(unresolvable_policy), expectedPolicyVersion=version2
        )
    )
    assert unresolvable_code == "ValidationException", unresolvable_code
    assert unresolvable_message == "Invalid input for 'policy'. Aurora DSQL can't apply the policy because the policy document isn't valid. Make sure your policy includes all required elements (Version, Statement, Principal, Action, and Resource) in valid JSON format and try again.", unresolvable_message
    still_unchanged = dsql.get_cluster_policy(identifier=identifier)
    assert json.loads(still_unchanged["policy"]) == other_policy, (
        f"expected policy to remain {other_policy!r} after unresolvable-principal rejection, "
        f"got {still_unchanged['policy']!r}"
    )
    assert still_unchanged["policyVersion"] == version2, (
        f"expected policyVersion to remain {version2!r} after unresolvable-principal rejection, "
        f"got {still_unchanged['policyVersion']!r}"
    )

    # Positive control: a resolvable, syntactically valid policy at the correct expectedPolicyVersion
    # is accepted and advances the version again.
    final_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAccountAdminConnect",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "dsql:DbConnectAdmin",
                "Resource": "*",
            }
        ],
    }
    accepted = dsql.put_cluster_policy(
        identifier=identifier, policy=json.dumps(final_policy), expectedPolicyVersion=version2
    )
    assert accepted["policyVersion"] != version2, (
        f"expected policyVersion to advance past {version2!r}, got {accepted['policyVersion']!r}"
    )
    final = dsql.get_cluster_policy(identifier=identifier)
    assert json.loads(final["policy"]) == final_policy, (
        f"expected final policy {final_policy!r}, got {final['policy']!r}"
    )


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
