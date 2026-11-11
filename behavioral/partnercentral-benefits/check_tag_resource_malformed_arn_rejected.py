"""tag-resource-malformed-arn-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-benefits"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a resourceArn that is not an ARN with the exact pattern ValidationException,
    while a well-formed TaggableResourceArn naming a missing benefit gets ResourceNotFoundException
    "Catalog `null` not found": shape validation runs before resolution."""
    client = _pcb_client(ctx)
    well_formed_arn = (
        f"arn:aws:partnercentral:us-east-1:{ctx.account}:"
        "catalog/Sandbox/benefit/ben-00000000000000"
    )

    positive = _error(
        lambda: client.tag_resource(
            resourceArn=well_formed_arn, tags=[{"Key": "sim2real-k1", "Value": "v1"}]
        )
    )
    assert positive == ("ResourceNotFoundException", "Catalog `null` not found"), (
        f"expected ResourceNotFoundException for a well-formed TagResource call naming "
        f"a benefit that does not exist, got {positive!r}"
    )

    refusal = _error(
        lambda: client.tag_resource(
            resourceArn="not-an-arn", tags=[{"Key": "sim2real-k1", "Value": "v1"}]
        )
    )
    expected = _pattern_message(
        "resourceArn",
        r"arn:[\w+=/,.@-]+:partnercentral:[\w+=/,.@-]*:[0-9]{12}:"
        r"catalog/([a-zA-Z]+)/[\w+=,.@-]+(/[\w+=,.@-]+)*",
    )
    assert refusal == ("ValidationException", expected), (
        f"expected the resourceArn-pattern ValidationException, got {refusal!r}"
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
