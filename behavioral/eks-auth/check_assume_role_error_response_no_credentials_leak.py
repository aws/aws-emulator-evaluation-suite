"""assume-role-error-response-no-credentials-leak."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-error-response-no-credentials-leak"
GROUP = "overly-permissive"
SERVICES = ["eks-auth"]

_MISSING_KID_MESSAGE = "The token included in the request has missing header - kid."


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRoleForPodIdentity with an invalid token fails with InvalidTokenException and its exact message,
    and the error response carries no credentials or assumedRoleUser.
    """
    eks_auth = ctx.client("eks-auth")
    bogus_cluster = ctx.unique_name("sim2real-nonexistent-")
    plausible_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

    try:
        eks_auth.assume_role_for_pod_identity(clusterName=bogus_cluster, token=plausible_token)
        raise AssertionError("expected InvalidTokenException, call unexpectedly succeeded")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "InvalidTokenException", f"expected InvalidTokenException, got {code!r}"
        message = exc.response["Error"].get("Message")
        assert message == _MISSING_KID_MESSAGE, f"expected message {_MISSING_KID_MESSAGE!r}, got {message!r}"
        assert "credentials" not in exc.response, f"'credentials' key leaked in error response: {exc.response!r}"
        assert "Credentials" not in exc.response, f"'Credentials' key leaked in error response: {exc.response!r}"
        assert "assumedRoleUser" not in exc.response, (
            f"'assumedRoleUser' key leaked in error response: {exc.response!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
