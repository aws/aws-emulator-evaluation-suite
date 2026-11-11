"""get-registry-policy-not-found-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-registry-policy-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """GetRegistryPolicy before any policy has ever been put returns RegistryPolicyNotFoundException,
    but once a real policy is put it round-trips correctly (positive control)."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")

    original = _snapshot_registry_policy(ecr)
    ctx.on_cleanup(lambda: _restore_registry_policy(ecr, original))
    if original is not None:
        ecr.delete_registry_policy()

    code, message = _error(lambda: ecr.get_registry_policy())
    assert code == "RegistryPolicyNotFoundException", code
    assert message == (
        f"Registry policy does not exist in the registry with id '{ctx.account}'"
    ), message

    # Positive control: once a policy is actually set, GetRegistryPolicy returns it.
    account_id = sts.get_caller_identity()["Account"]
    policy = _valid_registry_policy(account_id, ctx.region)
    ecr.put_registry_policy(policyText=json.dumps(policy))
    got = ecr.get_registry_policy()
    got_policy = json.loads(got["policyText"])
    assert got_policy == policy, f"expected {policy!r}, got {got_policy!r}"

    # Tearing it back down reverts GetRegistryPolicy to NotFound (effect is not sticky).
    ecr.delete_registry_policy()
    code2, message2 = _error(lambda: ecr.get_registry_policy())
    assert code2 == "RegistryPolicyNotFoundException", code2
    assert message2 == (
        f"Registry policy does not exist in the registry with id '{ctx.account}'"
    ), message2


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _snapshot_registry_policy(ecr):
    try:
        return ecr.get_registry_policy()["policyText"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "RegistryPolicyNotFoundException":
            return None
        raise


def _restore_registry_policy(ecr, original):
    try:
        ecr.delete_registry_policy()
    except ClientError as err:
        if err.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
            raise
    if original is not None:
        ecr.put_registry_policy(policyText=original)


def _valid_registry_policy(account_id, region):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealAllowReplicationFromSelf",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["ecr:CreateRepository", "ecr:ReplicateImage"],
                "Resource": f"arn:aws:ecr:{region}:{account_id}:repository/*",
            }
        ],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
