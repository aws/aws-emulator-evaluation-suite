"""put-cluster-policy-version-conflict-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-cluster-policy-version-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutClusterPolicy with a superseded expectedPolicyVersion fails with ConflictException and AWS's exact
    message and leaves the attached policy unchanged, while the current version succeeds and advances
    the version token."""
    dsql = ctx.client("dsql")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    created = dsql.create_cluster(
        deletionProtectionEnabled=False, tags={"sim2real-created-with": CHECK},
    )
    identifier = created["identifier"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))
    _wait_for_status(dsql, identifier, {"ACTIVE"}, timeout_s=180)

    policy_v1 = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "dsql:DbConnect", "Resource": arn,
        }],
    }
    put1 = dsql.put_cluster_policy(identifier=identifier, policy=json.dumps(policy_v1))
    version1 = put1["policyVersion"]

    # Advance the policy once so version1 becomes a real, well-formed, but stale token
    # (a version that once existed, distinct from a syntactically-invalid one).
    policy_v2 = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "dsql:DbConnectAdmin", "Resource": arn,
        }],
    }
    put2 = dsql.put_cluster_policy(identifier=identifier, policy=json.dumps(policy_v2), expectedPolicyVersion=version1)
    version2 = put2["policyVersion"]
    assert version2 != version1, f"expected the advancing put to mint a new version token, got version1={version1!r} version2={version2!r}"

    policy_v3_attempt = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": ["dsql:DbConnect", "dsql:DbConnectAdmin"], "Resource": arn,
        }],
    }
    # Reusing the stale version1 rather than the current version2 is rejected.
    stale_code, stale_message = _error(lambda: dsql.put_cluster_policy(
        identifier=identifier, policy=json.dumps(policy_v3_attempt), expectedPolicyVersion=version1,
    ))
    assert stale_code == "ConflictException", f"expected ConflictException for a stale expectedPolicyVersion={version1!r}, got {stale_code!r}"
    assert stale_message == f"Aurora DSQL can't find policy version {version1} for resource {identifier}. Verify that the policy exists and that the version is correct.", stale_message

    # effect absent: the attached policy is still the v2 document/version
    unchanged = dsql.get_cluster_policy(identifier=identifier)
    assert unchanged["policyVersion"] == version2, f"expected the rejected put to leave policyVersion at {version2!r}, got {unchanged['policyVersion']!r}"
    assert json.loads(unchanged["policy"]) == policy_v2, f"expected the rejected put to leave the policy document at policy_v2, got {unchanged['policy']!r}"

    # positive control: the correct expectedPolicyVersion is accepted and advances the version
    put3 = dsql.put_cluster_policy(identifier=identifier, policy=json.dumps(policy_v3_attempt), expectedPolicyVersion=version2)
    assert put3["policyVersion"] != version2, f"expected the correctly-versioned put to mint a new version token, got {put3['policyVersion']!r} == version2"
    updated = dsql.get_cluster_policy(identifier=identifier)
    assert json.loads(updated["policy"]) == policy_v3_attempt, f"expected the accepted put to persist policy_v3_attempt, got {updated['policy']!r}"


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_status(dsql, identifier, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = dsql.get_cluster(identifier=identifier)
        if last["status"] in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last={last}")


def _best_effort_delete(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
