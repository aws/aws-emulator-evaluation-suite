"""cluster-policy-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-policy-lifecycle"
GROUP = "state"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetClusterPolicy on a cluster without a policy fails with ResourceNotFoundException; PutClusterPolicy
    attaches one that GetClusterPolicy returns with the same version, and after DeleteClusterPolicy both
    the read and a second delete fail with ResourceNotFoundException and AWS's exact messages."""
    dsql = ctx.client("dsql")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    created = dsql.create_cluster(
        deletionProtectionEnabled=False, tags={"sim2real-purpose": CHECK}
    )
    identifier = created["identifier"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))
    _wait_for_status(dsql, identifier, {"ACTIVE"}, timeout_s=180)

    no_policy_code, no_policy_message = _error(lambda: dsql.get_cluster_policy(identifier=identifier))
    assert no_policy_code == "ResourceNotFoundException", (
        f"a cluster with no attached policy should report ResourceNotFoundException from "
        f"GetClusterPolicy, got {no_policy_code!r}"
    )
    assert no_policy_message == f"Aurora DSQL can't find the policy for the resource {identifier}. Verify that the policy exists.", no_policy_message

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "dsql:DbConnect",
            "Resource": arn,
        }],
    }
    put1 = dsql.put_cluster_policy(identifier=identifier, policy=json.dumps(policy_doc))
    version1 = put1["policyVersion"]
    assert version1, f"PutClusterPolicy did not return a policyVersion token, got {put1!r}"

    fetched = dsql.get_cluster_policy(identifier=identifier)
    assert json.loads(fetched["policy"]) == policy_doc, (
        f"GetClusterPolicy returned {fetched['policy']!r}, expected {policy_doc!r}"
    )
    assert fetched["policyVersion"] == version1, (
        f"GetClusterPolicy policyVersion {fetched['policyVersion']!r} does not match "
        f"PutClusterPolicy's {version1!r}"
    )

    dsql.delete_cluster_policy(identifier=identifier, expectedPolicyVersion=version1)
    gone_code, gone_message = _error(lambda: dsql.get_cluster_policy(identifier=identifier))
    assert gone_code == "ResourceNotFoundException", (
        f"GetClusterPolicy after DeleteClusterPolicy should be ResourceNotFoundException, "
        f"got {gone_code!r}"
    )
    assert gone_message == f"Aurora DSQL can't find the policy for the resource {identifier}. Verify that the policy exists.", gone_message

    redelete_code, redelete_message = _error(
        lambda: dsql.delete_cluster_policy(identifier=identifier, expectedPolicyVersion=version1)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"DeleteClusterPolicy on an already-gone policy should be ResourceNotFoundException, "
        f"got {redelete_code!r}"
    )
    assert redelete_message == f"Aurora DSQL can't find policy version {version1} for resource {identifier}. Verify that the policy exists and that the version is correct.", redelete_message


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
