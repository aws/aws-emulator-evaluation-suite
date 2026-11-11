"""submit-benefit-application-twice-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "submit-benefit-application-twice-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-benefits"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SubmitBenefitApplication rejects a malformed Identifier with the exact pattern
    ValidationException and a well-formed nonexistent one with the exact entitlement
    AccessDeniedException, identically twice; GetBenefitApplication on it is denied the same way."""
    client = _pcb_client(ctx)

    shape_code, shape_message = _error(
        lambda: client.submit_benefit_application(
            Catalog="Sandbox", Identifier="!!! not a valid identifier !!!"
        )
    )
    expected = _pattern_message("identifier", "(arn:.+|benappl-[0-9a-z]{14})")
    assert (shape_code, shape_message) == ("ValidationException", expected), (
        f"expected the identifier-pattern ValidationException (the positive control that "
        f"the request reaches shape validation), got {(shape_code, shape_message)!r}"
    )

    identifier = "benappl-00000000000000"
    first_code, first_message = _error(
        lambda: client.submit_benefit_application(Catalog="Sandbox", Identifier=identifier)
    )
    assert (first_code, first_message) == ("AccessDeniedException", _DENIED), (
        f"expected the entitlement AccessDeniedException submitting a well-formed but "
        f"nonexistent application, got {(first_code, first_message)!r}"
    )

    second = _error(
        lambda: client.submit_benefit_application(Catalog="Sandbox", Identifier=identifier)
    )
    assert second == (first_code, first_message), (
        f"repeating the identical SubmitBenefitApplication call must be rejected the "
        f"same way: first={(first_code, first_message)!r} second={second!r}"
    )

    read_code, read_message = _error(
        lambda: client.get_benefit_application(Catalog="Sandbox", Identifier=identifier)
    )
    assert (read_code, read_message) == ("AccessDeniedException", _DENIED), (
        f"an independent GetBenefitApplication read on the same identifier must show "
        f"no application is visible after either submit attempt, got {(read_code, read_message)!r}"
    )


_DENIED = (
    "This action requires an active AWS partner benefit. Register as an AWS partner if "
    "you haven't already, or contact AWS partner central support."
)


def _pattern_message(member: str, pattern: str) -> str:
    """The exact ValidationException message for a member that fails its modelled pattern."""
    return (
        f"1 validation error detected: Value at '{member}' failed to satisfy constraint: "
        f"Member must satisfy regular expression pattern: {pattern}"
    )


def _pcb_client(ctx):
    """partnercentral-benefits serves only us-east-1, at an api.aws host botocore does not
    resolve by default; ctx.service_url names that host on real AWS and the target's endpoint
    otherwise."""
    return ctx.client(
        "partnercentral-benefits",
        region="us-east-1",
        endpoint_url=ctx.service_url("https://partnercentral-benefits.us-east-1.api.aws"),
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )


def _error(fn):
    """(Code, Message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
