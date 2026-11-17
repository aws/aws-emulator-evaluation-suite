"""assume-role-with-web-identity-minimum-session-token-size-exceeds-max-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-with-web-identity-minimum-session-token-size-exceeds-max-rejected"
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
    """AssumeRoleWithWebIdentity refuses a MinimumSessionTokenSize one byte past the 4096-byte
    maximum with a ValidationError, ahead of parsing the WebIdentityToken it was handed."""

    sts = ctx.client("sts", config=Config(retries={"max_attempts": 1}, parameter_validation=False))
    role_arn = f"arn:aws:iam::{ctx.account}:role/{ctx.unique_name('sim2real-behav-no-such-role-')}"
    session_name = ctx.unique_name("sim2real-behav-sess-")
    not_a_real_token = "bm90LWEtcmVhbC1vaWRjLXRva2Vu"

    # Neighbour control: the same request with MinimumSessionTokenSize at the maximum passes
    # range validation and is refused only for the (deliberately fake) WebIdentityToken, proving
    # the ValidationError below is specifically about the one extra byte.
    control_code, _ = _refusal(
        lambda: sts.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=not_a_real_token,
            MinimumSessionTokenSize=4096,
        )
    )
    assert control_code == "InvalidIdentityToken", (
        f"expected a max-size request to pass range validation and fail on the WebIdentityToken "
        f"instead, got {control_code}"
    )

    code, message = _refusal(
        lambda: sts.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=not_a_real_token,
            MinimumSessionTokenSize=4097,
        )
    )
    assert code == "ValidationError", (
        f"expected ValidationError for MinimumSessionTokenSize one byte past the max, got {code}"
    )
    assert message == (
        "1 validation error detected: Value '4097' at 'minimumSessionTokenSize' failed to "
        "satisfy constraint: Member must have value less than or equal to 4096"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
