"""put-deployment-parameter-secret-string-too-long-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-deployment-parameter-secret-string-too-long-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-deployment"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A 15001-character secretString (documented maximum 15000) is refused with ForbiddenException
    'Forbidden' rather than truncated and stored, while a well-formed request with the same ids fails
    ResourceNotFoundException, so the refusal is specific to the oversized field."""
    md = _md_client(ctx)
    catalog = "AWSMarketplace"
    product_id = ctx.unique_name("prod-")
    agreement_id = ctx.unique_name("agr-")

    control_code, control_message = _error(
        lambda: md.put_deployment_parameter(
            catalog=catalog,
            productId=product_id,
            agreementId=agreement_id,
            deploymentParameter={
                "name": ctx.unique_name("sim2real-dp-"),
                "secretString": "s3cr3t-value-1",
            },
        )
    )
    assert control_code == "ResourceNotFoundException", control_code
    assert control_message == (
        "ProductId: Request references a resource which does not exist."
    ), control_message

    too_long_secret = "x" * 15001
    code, message = _error(
        lambda: md.put_deployment_parameter(
            catalog=catalog,
            productId=product_id,
            agreementId=agreement_id,
            deploymentParameter={
                "name": ctx.unique_name("sim2real-dp-"),
                "secretString": too_long_secret,
            },
        )
    )
    assert code == "ForbiddenException", code
    assert message == "Forbidden", message



def _md_client(ctx):
    """marketplace-deployment serves only us-east-1, so the client pins that region."""
    return ctx.client(
        "marketplace-deployment",
        region="us-east-1",
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
