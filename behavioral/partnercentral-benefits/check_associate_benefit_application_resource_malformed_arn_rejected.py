"""associate-benefit-application-resource-malformed-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-benefit-application-resource-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-benefits"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateBenefitApplicationResource with a ResourceArn that is not a valid ARN fails with
    ValidationException before any lookup, while the same call with a valid ARN fails differently, so the
    rejection is about the malformed ARN.
    """
    client = _pcb_client(ctx)
    # A pattern-VALID but nonexistent identifier: BenefitApplicationIdentifier's own
    # Smithy pattern requires exactly 14 chars after "benappl-", so any other length
    # is itself a malformed-input rejection that would confound the ARN-specific
    # assertion below.
    identifier = "benappl-00000000000000"

    control_code, _ = _error(
        lambda: client.associate_benefit_application_resource(
            Catalog="Sandbox",
            BenefitApplicationIdentifier=identifier,
            ResourceArn="arn:aws:s3:::sim2real-pcb-associate-control-resource",
        )
    )
    assert control_code != "ValidationException", (
        "positive control: a syntactically valid ResourceArn must not be rejected by "
        f"ARN pattern validation, got {control_code!r}"
    )

    code, message = _error(
        lambda: client.associate_benefit_application_resource(
            Catalog="Sandbox",
            BenefitApplicationIdentifier=identifier,
            ResourceArn="not-an-arn",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value at 'resourceArn' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: "
        r"arn:aws:([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.+)"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _pcb_client(ctx):
    """partnercentral-benefits is only deployed in us-east-1, so pin the region."""
    from botocore.config import Config

    return ctx.client(
        "partnercentral-benefits",
        region="us-east-1",
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
