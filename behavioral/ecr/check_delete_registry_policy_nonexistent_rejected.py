"""delete-registry-policy-nonexistent-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-registry-policy-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """With no registry policy, DeleteRegistryPolicy and GetRegistryPolicy are refused
    RegistryPolicyNotFoundException with the exact message; a policy put is read back, deletes,
    and Get is then refused the same way."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    original = _snapshot_registry_policy(ecr)
    ctx.on_cleanup(lambda: _restore_registry_policy(ecr, original))
    if original is not None:
        ecr.delete_registry_policy()

    err_code, err_code_msg = _error(lambda: ecr.delete_registry_policy())
    assert err_code == "RegistryPolicyNotFoundException", f"expected RegistryPolicyNotFoundException, got {err_code}"
    expected_msg = f"Registry policy does not exist in the registry with id '{ctx.account}'"
    assert err_code_msg == expected_msg, f"expected message {expected_msg!r}, got {err_code_msg!r}"

    get_err_code, get_err_code_msg = _error(lambda: ecr.get_registry_policy())
    assert get_err_code == "RegistryPolicyNotFoundException", (
        f"expected NotFound on Get too (no policy was ever created), got {get_err_code}"
    )
    expected_msg = f"Registry policy does not exist in the registry with id '{ctx.account}'"
    assert get_err_code_msg == expected_msg, f"expected message {expected_msg!r}, got {get_err_code_msg!r}"

    # Positive control: once a real policy is put, Get returns it faithfully and Delete
    # succeeds -- the two NotFoundExceptions above are a refusal tied to the absent-policy
    # state, not a target that errors on these operations unconditionally.
    policy = _valid_registry_policy(account_id, ctx.region)
    ecr.put_registry_policy(policyText=json.dumps(policy))
    got = ecr.get_registry_policy()
    assert json.loads(got["policyText"]) == policy, (
        f"expected the put policy to round-trip exactly, got {got.get('policyText')}"
    )

    ecr.delete_registry_policy()
    get_after_delete, get_after_delete_msg = _error(lambda: ecr.get_registry_policy())
    assert get_after_delete == "RegistryPolicyNotFoundException", (
        f"expected the freshly-put policy to be gone after delete, got {get_after_delete}"
    )
    expected_msg = f"Registry policy does not exist in the registry with id '{ctx.account}'"
    assert get_after_delete_msg == expected_msg, f"expected message {expected_msg!r}, got {get_after_delete_msg!r}"


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
