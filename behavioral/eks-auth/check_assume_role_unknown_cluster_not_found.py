"""assume-role-unknown-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-unknown-cluster-not-found"
GROUP = "overly-permissive"
SERVICES = ["eks-auth"]

_MISSING_KID_MESSAGE = "The token included in the request has missing header - kid."
_TOKEN_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'token' failed to satisfy constraint: "
    r"Member must satisfy regular expression pattern: [A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+"
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRoleForPodIdentity with a JWT-shaped but invalid token against an unknown cluster fails with
    InvalidTokenException (token validation runs before the cluster lookup), and a dotless token fails
    with InvalidParameterException; both with their exact messages.
    """
    eks_auth = ctx.client("eks-auth")
    bogus_cluster = ctx.unique_name("sim2real-nonexistent-")
    # Structurally valid (three dot-separated base64url segments matching the modeled token
    # pattern) but not a real, signed Kubernetes service-account JWT.
    plausible_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

    code, message = _error_code(
        lambda: eks_auth.assume_role_for_pod_identity(clusterName=bogus_cluster, token=plausible_token)
    )
    assert code == "InvalidTokenException", f"GOT={code!r}"
    assert message == _MISSING_KID_MESSAGE, f"expected message {_MISSING_KID_MESSAGE!r}, got {message!r}"

    # Positive control proving this is genuinely about token validity, not merely that any
    # unresolvable clusterName always yields InvalidTokenException regardless of shape: a token
    # that fails the coarse SHAPE check entirely (not three dot-separated segments) against the
    # very same nonexistent cluster yields InvalidParameterException instead -- a distinct code
    # for a distinct failure -- confirming these are two different validation layers, both of
    # which run ahead of the cluster lookup.
    code2, message2 = _error_code(
        lambda: eks_auth.assume_role_for_pod_identity(clusterName=bogus_cluster, token="not-a-jwt-at-all")
    )
    assert code2 == "InvalidParameterException", f"GOT={code2!r}"
    assert message2 == _TOKEN_PATTERN_MESSAGE, f"expected message {_TOKEN_PATTERN_MESSAGE!r}, got {message2!r}"


def _error_code(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
