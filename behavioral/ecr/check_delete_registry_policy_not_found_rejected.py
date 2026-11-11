"""delete-registry-policy-not-found-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-registry-policy-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """DeleteRegistryPolicy on a registry with no policy set returns RegistryPolicyNotFoundException,
    and GetRegistryPolicy agrees that nothing is set -- but once a policy really exists both
    operations succeed (positive control)."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")

    original = _snapshot_registry_policy(ecr)
    ctx.on_cleanup(lambda: _restore_registry_policy(ecr, original))
    if original is not None:
        ecr.delete_registry_policy()

    code, code_msg = _error(lambda: ecr.delete_registry_policy())
    assert code == "RegistryPolicyNotFoundException", code
    expected_msg = f"Registry policy does not exist in the registry with id '{ctx.account}'"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    # Effect absent: there is still nothing to get either.
    code2, code2_msg = _error(lambda: ecr.get_registry_policy())
    assert code2 == "RegistryPolicyNotFoundException", code2
    expected_msg = f"Registry policy does not exist in the registry with id '{ctx.account}'"
    assert code2_msg == expected_msg, f"expected message {expected_msg!r}, got {code2_msg!r}"

    # Positive control: once a real policy is set, both Get and Delete succeed.
    account_id = sts.get_caller_identity()["Account"]
    policy = _valid_registry_policy(account_id, ctx.region)
    ecr.put_registry_policy(policyText=json.dumps(policy))
    got = ecr.get_registry_policy()
    got_policy = json.loads(got["policyText"])
    assert got_policy == policy, f"expected {policy}, got {got_policy}"
    ecr.delete_registry_policy()
    code3, code3_msg = _error(lambda: ecr.get_registry_policy())
    assert code3 == "RegistryPolicyNotFoundException", code3
    expected_msg = f"Registry policy does not exist in the registry with id '{ctx.account}'"
    assert code3_msg == expected_msg, f"expected message {expected_msg!r}, got {code3_msg!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
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
