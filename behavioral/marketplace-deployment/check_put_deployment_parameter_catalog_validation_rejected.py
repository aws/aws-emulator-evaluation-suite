"""put-deployment-parameter-catalog-validation-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-deployment-parameter-catalog-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-deployment"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDeploymentParameter fails ValidationException with the exact message for a catalog that breaks
    the pattern and for a pattern-valid catalog other than AWSMarketplace, while AWSMarketplace passes
    catalog validation and fails ResourceNotFoundException on the unknown productId."""
    md = _md_client(ctx)
    product_id = ctx.unique_name("prod-")
    agreement_id = ctx.unique_name("agr-")
    name = ctx.unique_name("sim2real-dp-")

    def _put(catalog: str):
        return md.put_deployment_parameter(
            catalog=catalog,
            productId=product_id,
            agreementId=agreement_id,
            deploymentParameter={"name": name, "secretString": "s3cr3t-value-1"},
        )

    code, message = _error(lambda: _put("AWSMarketplace"))
    assert code == "ResourceNotFoundException", code
    assert message == "ProductId: Request references a resource which does not exist.", message

    code, message = _error(lambda: _put("AWS Marketplace!"))
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value 'AWS Marketplace!' at 'catalog' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [a-zA-Z_-]+"
    ), message

    code, message = _error(lambda: _put("NotTheRealMarketplace"))
    assert code == "ValidationException", code
    assert message == (
        'Catalog: The provided Catalog is invalid. Provide a valid Catalog. Supported values are '
        '["AWSMarketplace"].'
    ), message


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
