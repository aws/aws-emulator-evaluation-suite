"""get-resource-policy-not-found-without-statements."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resource-policy-not-found-without-statements"
GROUP = "resource-policy"
SERVICES = ["signin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on an account with no AWS Sign-In permission statements raises
    ResourceNotFoundException "Requested resource not found" rather than returning an empty policy document.
    """
    signin = ctx.client("signin")

    code, message = _error(lambda: signin.get_resource_policy())
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException with no permission statements, got {code!r}"
    )
    assert message == "Requested resource not found", (
        f"expected message 'Requested resource not found' with no permission statements, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
