"""list-checks-aws-service-filter-consistency."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-checks-aws-service-filter-consistency"
GROUP = "list-filtering"
SERVICES = ["trustedadvisor"]

TOO_LONG_SERVICE = "x" * 31
TOO_LONG_SERVICE_MESSAGE = (
    f"1 validation error detected: Value '{TOO_LONG_SERVICE}' at 'awsService' failed to "
    "satisfy constraint: Member must have length less than or equal to 30"
)


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _outcome(fn):
    """Call fn(); return its error code, or "(accepted)" when it succeeds."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return "(accepted)"


@tags("axis:rejection", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChecks with an over-length awsService fails with ValidationException and the exact length
    message, while a well-formed awsService filter does not fail with that code."""
    ta = ctx.client("trustedadvisor")

    # break exactly one thing: violate awsService's length trait (max 30) while everything else
    # about the request stays well-formed. botocore only validates the *minimum* length of this
    # field locally (confirmed: maxResults and awsService both raise ParamValidationError below
    # their modelled minimum but reach the network above their modelled maximum), so this value is
    # guaranteed to reach the service rather than being rejected by the SDK before the request is
    # ever sent.
    too_long_code, too_long_msg = _error(
        lambda: ta.list_checks(awsService=TOO_LONG_SERVICE, maxResults=200)
    )
    assert too_long_code == "ValidationException", (
        f"expected ValidationException for an awsService value longer than the "
        f"modelled 30-character maximum, got {too_long_code!r}"
    )
    assert too_long_msg == TOO_LONG_SERVICE_MESSAGE, (
        f"expected the exact length-violation message {TOO_LONG_SERVICE_MESSAGE!r}, "
        f"got {too_long_msg!r}"
    )

    # control: a well-formed awsService value is not refused by the same validation, so the
    # rejection above is not a blanket refusal. The call may succeed or be refused for another
    # reason; neither is graded.
    control_code = _outcome(lambda: ta.list_checks(awsService="EC2", maxResults=200))
    assert control_code != too_long_code, (
        "a well-formed awsService filter must not be rejected like the over-length one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
