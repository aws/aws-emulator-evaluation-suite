"""create-cluster-inline-policy-attached."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-inline-policy-attached"
GROUP = "resource-policy"
SERVICES = ["dsql"]

_ACTIVE_TIMEOUT_S = 600.0


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy passed to CreateCluster is attached at creation: GetClusterPolicy returns the same
    statements under a version, PutClusterPolicy against any other version is refused and leaves it,
    and DeleteClusterPolicy naming that version removes it."""
    dsql = ctx.client("dsql")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyPlaintextConnect", "Effect": "Deny", "Principal": "*",
            "Action": "dsql:DbConnect", "Resource": "*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }],
    }
    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        policy=json.dumps(policy),
        tags={"sim2real": CHECK, "Name": ctx.unique_name("sim2real-behav-dsql-")},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(dsql, identifier))
    _wait_active(dsql, identifier)

    attached = dsql.get_cluster_policy(identifier=identifier)
    assert json.loads(attached["policy"]) == policy, (
        f"the policy attached at creation reads back as {attached['policy']!r}"
    )
    version = attached["policyVersion"]
    assert version.isdigit(), f"policyVersion {version!r} is not a version number"

    stale = str(int(version) + 1)
    code, message = _error(lambda: dsql.put_cluster_policy(
        identifier=identifier, policy=json.dumps(policy), expectedPolicyVersion=stale))
    assert code == "ConflictException", f"PutClusterPolicy against version {stale} answered {code!r}"
    assert message == (
        f"Aurora DSQL can't find policy version {stale} for resource {identifier}. "
        "Verify that the policy exists and that the version is correct."
    ), f"the stale-version refusal said {message!r}"
    assert dsql.get_cluster_policy(identifier=identifier)["policyVersion"] == version, (
        "a refused PutClusterPolicy changed the policy version"
    )

    deleted = dsql.delete_cluster_policy(identifier=identifier, expectedPolicyVersion=version)
    assert deleted["policyVersion"] == version, f"DeleteClusterPolicy answered version {deleted['policyVersion']!r}"
    code, message = _error(lambda: dsql.get_cluster_policy(identifier=identifier))
    assert code == "ResourceNotFoundException", f"GetClusterPolicy after delete answered {code!r}"
    assert message == (
        f"Aurora DSQL can't find the policy for the resource {identifier}. Verify that the policy exists."
    ), f"GetClusterPolicy after delete said {message!r}"


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_active(dsql, identifier: str) -> dict:
    deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
    while True:
        cluster = dsql.get_cluster(identifier=identifier)
        if cluster["status"] in ("ACTIVE", "FAILED") or time.monotonic() >= deadline:
            break
        time.sleep(3)
    assert cluster["status"] == "ACTIVE", f"cluster settled in {cluster['status']!r}, not ACTIVE"
    return cluster


def _delete_cluster(dsql, identifier: str) -> None:
    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
