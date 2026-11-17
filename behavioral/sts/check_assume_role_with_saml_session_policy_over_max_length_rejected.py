"""assume-role-with-saml-session-policy-over-max-length-rejected."""
from __future__ import annotations

import json

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-with-saml-session-policy-over-max-length-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]


def _refusal(fn):
    """(code, message) of the error ``fn`` raises; raises AssertionError when it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRoleWithSAML refuses a Policy document one char past the 2048-char maximum with a
    ValidationError, ahead of parsing the SAMLAssertion it was handed."""

    sts = ctx.client("sts", config=Config(retries={"max_attempts": 1}, parameter_validation=False))
    role_arn = f"arn:aws:iam::{ctx.account}:role/{ctx.unique_name('sim2real-behav-no-such-role-')}"
    provider_arn = (
        f"arn:aws:iam::{ctx.account}:saml-provider/"
        f"{ctx.unique_name('sim2real-behav-no-such-provider-')}"
    )
    not_a_real_assertion = "bm90LWEtcmVhbC1zYW1sLWFzc2VydGlvbg=="

    def _policy_of_length(length: int) -> str:
        """A syntactically valid IAM policy document, padded to exactly ``length`` characters
        via its Sid."""
        template = {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "", "Effect": "Allow", "Action": "sts:GetCallerIdentity",
                           "Resource": "*"}],
        }
        base_len = len(json.dumps(template))
        template["Statement"][0]["Sid"] = "S" * (length - base_len)
        policy = json.dumps(template)
        assert len(policy) == length, (len(policy), length)
        return policy

    at_max = _policy_of_length(2048)
    over_max = _policy_of_length(2049)

    # Neighbour control: the same request with Policy at the maximum length passes length
    # validation and is refused only for the (deliberately fake) SAMLAssertion, proving the
    # ValidationError below is specifically about the extra character in Policy.
    control_code, _ = _refusal(
        lambda: sts.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=provider_arn,
            SAMLAssertion=not_a_real_assertion,
            Policy=at_max,
        )
    )
    assert control_code == "InvalidIdentityToken", (
        f"expected a max-length Policy to pass length validation and fail on the SAMLAssertion "
        f"instead, got {control_code}"
    )

    code, message = _refusal(
        lambda: sts.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=provider_arn,
            SAMLAssertion=not_a_real_assertion,
            Policy=over_max,
        )
    )
    assert code == "ValidationError", (
        f"expected ValidationError for a session Policy one char past the max length, got {code}"
    )
    assert message == (
        f"1 validation error detected: Value '{over_max}' at 'policy' failed to satisfy "
        "constraint: Member must have length less than or equal to 2048"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
