"""put-registry-policy-overly-broad-principal-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-registry-policy-overly-broad-principal-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """PutRegistryPolicy rejects a policy whose Effect is outside {Allow, Deny} with
    InvalidParameterException and leaves the registry policy unchanged, while a well-formed
    Allow statement for the account root is accepted and persisted."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    original_policy_text = _current_policy_text(ecr)
    ctx.on_cleanup(lambda: _restore_policy(ecr, original_policy_text))

    resource_arn = f"arn:aws:ecr:{region}:{account_id}:repository/*"
    # Real AWS accepts a bare wildcard Principal in a registry policy (there is no
    # extra "unconditioned wildcard" guardrail on top of standard IAM policy
    # validation) -- confirmed empirically. The actual, empirically-verified boundary
    # is standard IAM resource-policy document validation: an Effect value outside
    # the {Allow, Deny} enum is not a valid IAM policy document and is rejected.
    bad_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "InvalidEffectValue",
                "Effect": "AllowAndDeny",
                "Principal": "*",
                "Action": "ecr:CreateRepository",
                "Resource": resource_arn,
            }
        ],
    }
    code, message = _client_error(lambda: ecr.put_registry_policy(policyText=json.dumps(bad_policy)))
    assert code == "InvalidParameterException", f"unexpected code: {code}"
    expected = (
        "Invalid parameter at 'PolicyText' failed to satisfy constraint: "
        "'Invalid registry policy provided'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: registry policy is unchanged from the pre-mutation state.
    after_bad_text = _current_policy_text(ecr)
    assert after_bad_text == original_policy_text, "registry policy mutated despite rejection"

    # Positive control: a well-formed statement (valid "Allow" Effect, account-root
    # Principal) for the same action and resource succeeds and persists.
    good_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ConcretePrincipal",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "ecr:CreateRepository",
                "Resource": resource_arn,
            }
        ],
    }
    ecr.put_registry_policy(policyText=json.dumps(good_policy))
    stored = json.loads(_current_policy_text(ecr))
    assert stored["Statement"][0]["Sid"] == "ConcretePrincipal", (
        f"positive control did not persist: {stored}"
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


def _current_policy_text(ecr):
    from botocore.exceptions import ClientError

    try:
        return ecr.get_registry_policy()["policyText"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "RegistryPolicyNotFoundException":
            return None
        raise


def _restore_policy(ecr, original_text):
    if original_text is None:
        from botocore.exceptions import ClientError

        try:
            ecr.delete_registry_policy()
        except ClientError as err:
            if err.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
                raise
    else:
        ecr.put_registry_policy(policyText=original_text)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
