"""put-registry-policy-invalid-json-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-registry-policy-invalid-json-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """PutRegistryPolicy with a malformed (not-parseable) policy document returns
    InvalidParameterException and never persists the bad document; a syntactically valid
    document is accepted (positive control)."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")

    original = _snapshot_registry_policy(ecr)
    ctx.on_cleanup(lambda: _restore_registry_policy(ecr, original))
    if original is not None:
        ecr.delete_registry_policy()

    malformed = '{"Version": "2012-10-17", "Statement": [ this is not valid json'
    account_id = sts.get_caller_identity()["Account"]
    code, message = _client_error(lambda: ecr.put_registry_policy(policyText=malformed))
    assert code == "InvalidParameterException", code
    expected = (
        "Invalid parameter at 'PolicyText' failed to satisfy constraint: "
        "'Invalid registry policy provided'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the malformed document was never persisted.
    code2, message2 = _client_error(lambda: ecr.get_registry_policy())
    assert code2 == "RegistryPolicyNotFoundException", code2
    expected2 = f"Registry policy does not exist in the registry with id '{account_id}'"
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"

    # Positive control: a syntactically valid IAM policy document is accepted.
    policy = _valid_registry_policy(account_id, ctx.region)
    ecr.put_registry_policy(policyText=json.dumps(policy))
    got = ecr.get_registry_policy()
    got_policy = json.loads(got["policyText"])
    assert got_policy == policy, f"expected {policy}, got {got_policy}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly instead of reading as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
