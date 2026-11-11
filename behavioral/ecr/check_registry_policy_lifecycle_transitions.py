"""registry-policy-lifecycle-transitions."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "registry-policy-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """A registry policy reads back after PutRegistryPolicy, GetRegistryPolicy raises
    RegistryPolicyNotFoundException after DeleteRegistryPolicy, and a second Put round-trips
    again, so the registry-wide policy slot is reusable."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Snapshot any pre-existing registry policy so we restore account state afterward.
    original_policy_text = None
    try:
        original_policy_text = ecr.get_registry_policy()["policyText"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
            raise

    def _restore():
        try:
            if original_policy_text is not None:
                ecr.put_registry_policy(policyText=original_policy_text)
            else:
                ecr.delete_registry_policy()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
                raise

    ctx.on_cleanup(_restore)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealAllowReplicate",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["ecr:ReplicateImage"],
                "Resource": f"arn:aws:ecr:{ctx.region}:{account_id}:repository/*",
            }
        ],
    }
    policy_text = json.dumps(policy)

    put_resp = ecr.put_registry_policy(policyText=policy_text)
    put_policy = json.loads(put_resp["policyText"])
    assert _normalize_policy(put_policy) == _normalize_policy(policy), (
        f"PutRegistryPolicy echo mismatch: expected {policy}, got {put_policy}"
    )

    get_resp = ecr.get_registry_policy()
    get_policy = json.loads(get_resp["policyText"])
    assert _normalize_policy(get_policy) == _normalize_policy(policy), (
        f"GetRegistryPolicy after Put mismatch: expected {policy}, got {get_policy}"
    )

    ecr.delete_registry_policy()

    code, message = _client_error(lambda: ecr.get_registry_policy())
    assert code == "RegistryPolicyNotFoundException", (
        f"expected RegistryPolicyNotFoundException after delete, got {code!r}"
    )
    expected = f"Registry policy does not exist in the registry with id '{account_id}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The registry policy is a reusable slot, not a one-shot resource: prove the delete did
    # not leave it permanently unputtable by round-tripping it a second time.
    put_again_resp = ecr.put_registry_policy(policyText=policy_text)
    put_again_policy = json.loads(put_again_resp["policyText"])
    assert _normalize_policy(put_again_policy) == _normalize_policy(policy), (
        f"PutRegistryPolicy after delete mismatch: expected {policy}, got {put_again_policy}"
    )

    get_again_resp = ecr.get_registry_policy()
    get_again_policy = json.loads(get_again_resp["policyText"])
    assert _normalize_policy(get_again_policy) == _normalize_policy(policy), (
        f"GetRegistryPolicy after re-Put mismatch: expected {policy}, got {get_again_policy}"
    )


# ===== helpers =====
def _as_list(value):
    return value if isinstance(value, list) else [value]


def _normalize_policy(policy: dict) -> dict:
    """IAM/ECR may collapse single-element Action/Resource lists to bare strings on
    round-trip; normalize both sides to lists so semantic equality holds."""
    normalized_statements = []
    for stmt in policy["Statement"]:
        normalized_statements.append(
            {
                "Sid": stmt.get("Sid"),
                "Effect": stmt["Effect"],
                "Principal": stmt["Principal"],
                "Action": sorted(_as_list(stmt["Action"])),
                "Resource": sorted(_as_list(stmt["Resource"])),
            }
        )
    return {"Version": policy["Version"], "Statement": normalized_statements}

def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly instead of reading as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
