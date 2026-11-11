"""put-cluster-policy-lockout-safety-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-cluster-policy-lockout-safety-rejected"
GROUP = "overly-permissive"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutClusterPolicy with a policy denying every principal all dsql actions fails with
    ValidationException and AWS's exact lockout-safety message and attaches nothing, while a normal
    policy is accepted."""
    dsql = ctx.client("dsql")

    created = dsql.create_cluster(deletionProtectionEnabled=False)
    identifier = created["identifier"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))
    _wait_for_status(dsql, identifier, {"ACTIVE"}, timeout_s=180)

    lockout_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "dsql:*", "Resource": arn}],
    }
    lockout_code, lockout_message = _error(lambda: dsql.put_cluster_policy(
        identifier=identifier, policy=json.dumps(lockout_policy),
    ))
    assert lockout_code == "ValidationException", (
        f"expected ValidationException for a policy locking out every principal, got {lockout_code!r}"
    )
    assert lockout_message == "The new policy would result in the calling principal being unable to further update and delete this cluster's policy. Set the 'bypassPolicyLockoutSafetyCheck' parameter to 'true' to confirm this intent.", lockout_message

    # effect absent: nothing was attached
    absent_code, absent_message = _error(lambda: dsql.get_cluster_policy(identifier=identifier))
    assert absent_code == "ResourceNotFoundException", (
        f"expected no policy attached after the lockout policy was rejected, got {absent_code!r}"
    )
    assert absent_message == f"Aurora DSQL can't find the policy for the resource {identifier}. Verify that the policy exists.", absent_message

    # positive control: a normal, non-locking policy is accepted
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    safe_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "dsql:DbConnect", "Resource": arn,
        }],
    }
    put_ok = dsql.put_cluster_policy(identifier=identifier, policy=json.dumps(safe_policy))
    assert put_ok["policyVersion"], "expected put_cluster_policy to return a policyVersion on acceptance"

    # terminal read: independent of the mutating call, at the destination
    attached = dsql.get_cluster_policy(identifier=identifier)
    assert json.loads(attached["policy"]) == safe_policy, (
        f"expected the attached policy to equal the accepted safe policy, got {attached['policy']}"
    )
    assert attached["policyVersion"] == put_ok["policyVersion"], (
        f"expected GetClusterPolicy version {put_ok['policyVersion']!r}, got {attached['policyVersion']!r}"
    )


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
