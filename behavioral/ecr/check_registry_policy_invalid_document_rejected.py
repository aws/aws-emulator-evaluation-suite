"""registry-policy-invalid-document-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "registry-policy-invalid-document-rejected"
GROUP = "representation"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """PutRegistryPolicy rejects a syntactically-invalid document (InvalidParameterException)
    without altering the stored registry policy, while a well-formed document still succeeds
    (positive control) in the same run."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    original = _get_registry_policy_text(ecr)

    def _restore():
        if original is None:
            _delete_registry_policy_ignore_missing(ecr)
        else:
            ecr.put_registry_policy(policyText=original)

    ctx.on_cleanup(_restore)

    # Break exactly one thing: submit a policyText that is not valid JSON at all.
    broken_text = "{this is not valid json at all"
    code, message = _client_error(lambda: ecr.put_registry_policy(policyText=broken_text))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a non-JSON policyText, got {code!r}"
    )
    expected = (
        "Invalid parameter at 'PolicyText' failed to satisfy constraint: "
        "'Invalid registry policy provided'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the stored policy is unchanged by the rejected call.
    after_reject = _get_registry_policy_text(ecr)
    assert after_reject == original, (
        f"rejected policyText leaked into storage: expected {original!r}, got {after_reject!r}"
    )

    # Positive control: a syntactically valid document is accepted in the same file.
    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCreateRepoControl",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "ecr:CreateRepository",
                "Resource": f"arn:aws:ecr:{ctx.region}:{account_id}:repository/*",
            }
        ],
    }
    ecr.put_registry_policy(policyText=json.dumps(valid_policy))
    confirmed = json.loads(ecr.get_registry_policy()["policyText"])
    assert confirmed == valid_policy, (
        f"positive control did not round-trip: expected {valid_policy!r}, got {confirmed!r}"
    )


def _get_registry_policy_text(ecr):
    try:
        return ecr.get_registry_policy()["policyText"]
    except ecr.exceptions.RegistryPolicyNotFoundException:
        return None


def _delete_registry_policy_ignore_missing(ecr) -> None:
    try:
        ecr.delete_registry_policy()
    except ecr.exceptions.RegistryPolicyNotFoundException:
        pass


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
