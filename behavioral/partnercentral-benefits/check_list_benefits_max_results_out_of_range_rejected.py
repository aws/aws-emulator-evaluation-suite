"""list-benefits-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-benefits-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-benefits"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListBenefits rejects a MaxResults outside [1, 100] with the exact range ValidationException,
    while an in-range MaxResults does not get ValidationException."""
    client = _pcb_client(ctx)

    control_code, _ = _error(lambda: client.list_benefits(Catalog="Sandbox", MaxResults=20))
    assert control_code != "ValidationException", (
        f"an in-range MaxResults must not itself draw ValidationException, got {control_code!r}"
    )

    refusal = _error(lambda: client.list_benefits(Catalog="Sandbox", MaxResults=1000))
    expected = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    )
    assert refusal == ("ValidationException", expected), (
        f"expected the maxResults-range ValidationException, got {refusal!r}"
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
