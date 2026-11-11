"""registry-policy-delete-then-not-found."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "registry-policy-delete-then-not-found"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """After DeleteRegistryPolicy removes a previously-put registry permissions policy,
    GetRegistryPolicy raises RegistryPolicyNotFoundException, confirming full teardown."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Snapshot any pre-existing registry policy so we can restore it (Put/Delete operate on
    # the single registry-wide policy).
    original_policy = _get_registry_policy_or_none(ecr)

    def _restore() -> None:
        if original_policy is not None:
            ecr.put_registry_policy(policyText=original_policy)
        else:
            _delete_registry_policy_or_ignore(ecr)

    ctx.on_cleanup(_restore)

    policy_text = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Sim2RealAllowDescribe",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "ecr:DescribeRepositories",
                    "Resource": "*",
                }
            ],
        }
    )

    put_resp = ecr.put_registry_policy(policyText=policy_text)
    put_policy = json.loads(put_resp["policyText"])
    assert put_policy == json.loads(policy_text), f"put echoed {put_policy!r}"

    get_resp = ecr.get_registry_policy()
    get_policy = json.loads(get_resp["policyText"])
    assert get_policy == json.loads(policy_text), f"get returned {get_policy!r} after put"

    ecr.delete_registry_policy()

    code, message = _client_error(lambda: ecr.get_registry_policy())
    assert code == "RegistryPolicyNotFoundException", f"expected NotFound after delete, got {code!r}"
    expected = f"Registry policy does not exist in the registry with id '{account_id}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The delete already removed the policy; prove it is not just gone but that a further
    # mutation on the now-dead policy also fails, rather than delete silently no-op'ing on
    # an absent target.
    redelete_code, redelete_message = _client_error(lambda: ecr.delete_registry_policy())
    assert redelete_code == "RegistryPolicyNotFoundException", (
        f"expected a second DeleteRegistryPolicy on an already-deleted policy to also raise "
        f"NotFound, got {redelete_code!r}"
    )
    expected_redelete = f"Registry policy does not exist in the registry with id '{account_id}'"
    assert redelete_message == expected_redelete, (
        f"expected message {expected_redelete!r}, got {redelete_message!r}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly instead of reading as a
    code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _get_registry_policy_or_none(ecr):
    from botocore.exceptions import ClientError

    try:
        return ecr.get_registry_policy()["policyText"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "RegistryPolicyNotFoundException":
            return None
        raise


def _delete_registry_policy_or_ignore(ecr) -> None:
    from botocore.exceptions import ClientError

    try:
        ecr.delete_registry_policy()
    except ClientError as err:
        if err.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
