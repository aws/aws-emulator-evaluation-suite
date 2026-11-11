"""list-benefits-requires-active-partner-benefit-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-benefits-requires-active-partner-benefit-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-benefits"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A well-formed ListBenefits is refused with the exact entitlement AccessDeniedException for a
    caller without an active AWS partner benefit, while an out-of-range MaxResults gets the exact
    ValidationException: range validation runs before the entitlement gate."""
    client = _pcb_client(ctx)

    control = _error(lambda: client.list_benefits(Catalog="Sandbox", MaxResults=1000))
    expected = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    )
    assert control == ("ValidationException", expected), (
        f"positive control failed: expected the maxResults-range ValidationException for "
        f"MaxResults=1000, got {control!r} -- cannot attribute the AccessDeniedException "
        f"below to entitlement if the request never reached validation"
    )

    denied = _error(
        lambda: client.list_benefits(Catalog="Sandbox", Status=["ACTIVE"], MaxResults=20)
    )
    assert denied == ("AccessDeniedException", _DENIED), (
        f"expected the entitlement AccessDeniedException for a well-formed ListBenefits "
        f"call, got {denied!r}"
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
