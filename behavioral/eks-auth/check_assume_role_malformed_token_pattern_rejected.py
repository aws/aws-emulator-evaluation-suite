"""assume-role-malformed-token-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-malformed-token-pattern-rejected"
GROUP = "error-semantics"
SERVICES = ["eks-auth"]

_MISSING_KID_MESSAGE = "The token included in the request has missing header - kid."
_TOKEN_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'token' failed to satisfy constraint: "
    r"Member must satisfy regular expression pattern: [A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+"
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRoleForPodIdentity with a token that has no dots fails with InvalidParameterException and its
    exact message, while a three-part token against the same cluster fails with InvalidTokenException.
    """
    eks_auth = ctx.client("eks-auth")
    # Valid clusterName format so only the token's shape is under test.
    cluster_name = ctx.unique_name("sim2real-nonexistent-")
    malformed_token = "not-a-jwt-token-at-all"
    shaped_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

    code, message = _error_code(
        lambda: eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=malformed_token)
    )
    assert code == "InvalidParameterException", (
        f"GOT={code!r}; a token with no dot separators at all should be rejected as a "
        "malformed parameter before any cluster lookup is attempted"
    )
    assert message == _TOKEN_PATTERN_MESSAGE, f"expected message {_TOKEN_PATTERN_MESSAGE!r}, got {message!r}"

    control_code, control_message = _error_code(
        lambda: eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=shaped_token)
    )
    assert control_code == "InvalidTokenException", (
        f"GOT={control_code!r}; a shape-valid token against the SAME nonexistent cluster should "
        "reach deep token parsing (InvalidTokenException) instead of the coarse parameter check, "
        "proving the InvalidParameterException above is about the token's shape, not the "
        "cluster's nonexistence"
    )
    assert control_message == _MISSING_KID_MESSAGE, (
        f"expected message {_MISSING_KID_MESSAGE!r}, got {control_message!r}"
    )


def _error_code(fn):
    """Call fn, require it to raise, return the error Code and Message.

    Raises on unexpected SUCCESS rather than returning a falsy sentinel: an emulator that mints
    credentials for one of these tokens is the strongest possible finding and must not read as
    an error-code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"AssumeRoleForPodIdentity succeeded unexpectedly; response members were "
        f"{sorted(result)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
