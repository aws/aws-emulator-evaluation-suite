"""registry-policy-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly instead of reading as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

CHECK = "registry-policy-lifecycle"
GROUP = 'registry-config'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """PutRegistryPolicy and GetRegistryPolicy return the registry id and the ReplicateImage
    allow statement, and after DeleteRegistryPolicy Get is refused
    RegistryPolicyNotFoundException with the exact message."""
    ecr = ctx.client("ecr")
    registry_id = ecr.describe_registry()["registryId"]
    region = ctx.region
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReplicationAccessCrossAccount",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{registry_id}:root"},
                "Action": ["ecr:CreateRepository", "ecr:ReplicateImage"],
                "Resource": [f"arn:aws:ecr:{region}:{registry_id}:repository/*"],
            }
        ],
    }

    # The registry policy is ACCOUNT-GLOBAL — there is one per registry, so this check
    # overwrites whatever the account already had. Capture it first and restore it at the
    # end, so a pre-existing policy is never silently destroyed.
    original_policy = None
    try:
        original_policy = ecr.get_registry_policy()["policyText"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RegistryPolicyNotFoundException":
            raise

    def _restore():
        if original_policy is None:
            try:
                ecr.delete_registry_policy()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
                    raise
        else:
            ecr.put_registry_policy(policyText=original_policy)

    # Registered BEFORE the first write: a failing assertion below must not be able to
    # leave the account's global policy destroyed, so restore cannot live on the success
    # path (or in a finally that the delete->gone assertion runs after).
    ctx.on_cleanup(_restore)

    put = ecr.put_registry_policy(policyText=json.dumps(policy))
    assert put["registryId"] == registry_id, (put["registryId"], registry_id)
    got = ecr.get_registry_policy()
    assert got["registryId"] == registry_id, (got["registryId"], registry_id)
    parsed = json.loads(got["policyText"])
    stmt = parsed["Statement"][0]
    assert stmt["Sid"] == "ReplicationAccessCrossAccount", stmt
    assert stmt["Effect"] == "Allow", stmt
    assert "ecr:ReplicateImage" in stmt["Action"], stmt

    ecr.delete_registry_policy()
    code, message = _client_error(lambda: ecr.get_registry_policy())
    assert code == "RegistryPolicyNotFoundException", code
    expected = f"Registry policy does not exist in the registry with id '{registry_id}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
