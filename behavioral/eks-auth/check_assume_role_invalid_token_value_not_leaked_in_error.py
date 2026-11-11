"""assume-role-invalid-token-value-not-leaked-in-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-invalid-token-value-not-leaked-in-error"
GROUP = "error-semantics"
SERVICES = ["eks-auth"]

_TOKEN_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'token' failed to satisfy constraint: "
    r"Member must satisfy regular expression pattern: [A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+"
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The 'token' member is modeled as sensitive. When a malformed token is rejected with
    InvalidParameterException, the raw token value supplied by the caller must not be echoed
    back verbatim in the error response (message or metadata)."""
    eks_auth = ctx.client("eks-auth")
    cluster_name = ctx.unique_name("sim2real-nonexistent-")
    secret_marker = "SIM2REALSECRETMARKER" + ctx.unique_name("").replace("-", "")
    malformed_token = f"not-a-jwt-{secret_marker}"

    try:
        eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=malformed_token)
        raise AssertionError("expected InvalidParameterException, call unexpectedly succeeded")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
        message = exc.response["Error"].get("Message")
        assert message == _TOKEN_PATTERN_MESSAGE, f"expected message {_TOKEN_PATTERN_MESSAGE!r}, got {message!r}"
        assert secret_marker not in str(exc.response), (
            f"secret marker {secret_marker!r} leaked verbatim in error response: {exc.response!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
