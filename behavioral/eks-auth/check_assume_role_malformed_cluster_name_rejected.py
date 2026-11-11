"""assume-role-malformed-cluster-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-malformed-cluster-name-rejected"
GROUP = "error-semantics"
SERVICES = ["eks-auth"]

_MISSING_KID_MESSAGE = "The token included in the request has missing header - kid."


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRoleForPodIdentity with a clusterName starting with a hyphen fails with
    InvalidParameterException and its exact message, while a well-formed unknown clusterName reaches token
    validation and fails with InvalidTokenException.
    """
    eks_auth = ctx.client("eks-auth")
    plausible_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"
    # Leading hyphen violates the "must start with [0-9A-Za-z]" constraint while staying well
    # within the 1-100 length bound, so this can't be confused with a length violation.
    bad_cluster_name = "-" + ctx.unique_name("bad-cluster-")
    well_formed_cluster_name = ctx.unique_name("sim2real-nonexistent-")

    code, message = _error_identity(
        lambda: eks_auth.assume_role_for_pod_identity(clusterName=bad_cluster_name, token=plausible_token)
    )
    assert code == "InvalidParameterException", (
        f"malformed clusterName {bad_cluster_name!r} (leading hyphen): expected "
        f"InvalidParameterException, got {code!r} ({message!r})"
    )
    expected_message = (
        f"1 validation error detected: Value '{bad_cluster_name}' at 'clusterName' failed to "
        r"satisfy constraint: Member must satisfy regular expression pattern: [0-9A-Za-z][A-Za-z0-9\-_]*"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    control_code, control_message = _error_identity(
        lambda: eks_auth.assume_role_for_pod_identity(clusterName=well_formed_cluster_name, token=plausible_token)
    )
    assert control_code == "InvalidTokenException", (
        f"well-formed clusterName {well_formed_cluster_name!r} was expected to clear shape "
        f"validation and fail deeper at token validation (InvalidTokenException), got "
        f"{control_code!r} ({control_message!r})"
    )
    assert control_message == _MISSING_KID_MESSAGE, (
        f"expected message {_MISSING_KID_MESSAGE!r}, got {control_message!r}"
    )


def _error_identity(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"assume_role_for_pod_identity unexpectedly SUCCEEDED; response members were "
        f"{sorted(result)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
