"""put-deployment-parameter-nonexistent-agreement-not-found."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-deployment-parameter-nonexistent-agreement-not-found"
GROUP = "error-semantics"
SERVICES = ["marketplace-deployment"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDeploymentParameter with a well-formed but unknown productId/agreementId fails
    ResourceNotFoundException with the exact message, while a malformed catalog on the same call fails
    ValidationException: existence is checked as its own step, not by one blanket error."""
    md = _md_client(ctx)
    product_id = ctx.unique_name("no-such-product-")
    agreement_id = ctx.unique_name("no-such-agreement-")
    name = ctx.unique_name("sim2real-dp-")

    def _put(catalog: str):
        return md.put_deployment_parameter(
            catalog=catalog,
            productId=product_id,
            agreementId=agreement_id,
            deploymentParameter={"name": name, "secretString": "s3cr3t-value-1"},
        )

    control_code, control_message = _error(lambda: _put("Not-A-Real-Catalog!"))
    assert control_code == "ValidationException", (
        f"expected ValidationException for a malformed catalog, got {control_code!r}"
    )
    assert control_message == (
        "1 validation error detected: Value 'Not-A-Real-Catalog!' at 'catalog' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [a-zA-Z_-]+"
    ), control_message

    code, message = _error(lambda: _put("AWSMarketplace"))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-provisioned agreement, got {code!r}"
    )
    assert message == "ProductId: Request references a resource which does not exist.", message
    assert code != control_code, (
        f"nonexistent-agreement ({code!r}) and malformed-catalog ({control_code!r}) must not "
        "share the same error code"
    )


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
