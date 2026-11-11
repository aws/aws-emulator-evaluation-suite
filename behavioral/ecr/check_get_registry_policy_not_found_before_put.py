"""get-registry-policy-not-found-before-put."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-registry-policy-not-found-before-put"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """GetRegistryPolicy is refused RegistryPolicyNotFoundException with the exact message before
    any policy is put, returns the exact put policy and registryId afterwards, and is refused the
    same way after DeleteRegistryPolicy."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    original = _get_current_registry_policy(ecr)
    ctx.on_cleanup(lambda: _restore_registry_policy(ecr, original))

    if original is not None:
        ecr.delete_registry_policy()

    code, message = _error(lambda: ecr.get_registry_policy())
    assert code == "RegistryPolicyNotFoundException", code
    expected = f"Registry policy does not exist in the registry with id '{ctx.account}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    policy_text = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Sim2RealBehavioralAllowDescribe",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "ecr:DescribeRepositories",
                    "Resource": "*",
                }
            ],
        }
    )

    # Positive control: after a Put, Get must succeed and return the same policy text,
    # with each field individually verified (representation fidelity, not just a
    # round-trip JSON blob comparison).
    ecr.put_registry_policy(policyText=policy_text)
    resp = ecr.get_registry_policy()
    returned = json.loads(resp["policyText"])
    assert returned == json.loads(policy_text), f"expected {policy_text}, got {resp['policyText']!r}"
    statement = returned["Statement"][0]
    assert statement["Sid"] == "Sim2RealBehavioralAllowDescribe", f"expected Sid Sim2RealBehavioralAllowDescribe, got {statement.get('Sid')!r}"
    assert statement["Effect"] == "Allow", f"expected Effect Allow, got {statement.get('Effect')!r}"
    assert statement["Principal"] == {"AWS": f"arn:aws:iam::{account_id}:root"}, f"expected Principal arn:aws:iam::{account_id}:root, got {statement.get('Principal')!r}"
    assert statement["Action"] == "ecr:DescribeRepositories", f"expected Action ecr:DescribeRepositories, got {statement.get('Action')!r}"
    assert statement["Resource"] == "*", f"expected Resource *, got {statement.get('Resource')!r}"
    assert resp.get("registryId") == account_id, f"expected registryId {account_id}, got {resp.get('registryId')!r}"

    ecr.delete_registry_policy()
    code_after_delete, message_after_delete = _error(lambda: ecr.get_registry_policy())
    assert code_after_delete == "RegistryPolicyNotFoundException", code_after_delete
    assert message_after_delete == expected, (
        f"expected message {expected!r}, got {message_after_delete!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _get_current_registry_policy(ecr):
    try:
        return ecr.get_registry_policy()["policyText"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "RegistryPolicyNotFoundException":
            return None
        raise


def _restore_registry_policy(ecr, original) -> None:
    try:
        if original is None:
            ecr.delete_registry_policy()
        else:
            ecr.put_registry_policy(policyText=original)
    except ClientError as e:
        if e.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
