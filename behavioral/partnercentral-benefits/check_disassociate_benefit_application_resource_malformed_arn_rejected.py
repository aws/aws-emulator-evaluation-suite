"""disassociate-benefit-application-resource-malformed-arn-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-benefit-application-resource-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-benefits"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateBenefitApplicationResource rejects a ResourceArn that is not an ARN with the exact
    pattern ValidationException, while a well-formed request does not get ValidationException, so the
    rejection is earned by the malformed ARN."""
    client = _pcb_client(ctx)

    control_code, _ = _error(
        lambda: client.disassociate_benefit_application_resource(
            Catalog="Sandbox",
            BenefitApplicationIdentifier="benappl-00000000000000",
            ResourceArn=f"arn:aws:s3:::{ctx.unique_name('sim2real-nonexistent-')}",
        )
    )
    assert control_code != "ValidationException", (
        f"a well-formed ResourceArn/BenefitApplicationIdentifier must not itself be "
        f"rejected as ValidationException, got {control_code!r}"
    )

    code, message = _error(
        lambda: client.disassociate_benefit_application_resource(
            Catalog="Sandbox",
            BenefitApplicationIdentifier="benappl-00000000000000",
            ResourceArn="not-an-arn",
        )
    )
    expected = _pattern_message(
        "resourceArn",
        r"arn:aws:([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.+)",
    )
    assert code == "ValidationException", f"expected the resourceArn-pattern ValidationException, got {code!r}: {message!r}"
    assert message == expected, f"expected the resourceArn-pattern ValidationException message {expected!r}, got {message!r}"


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
