"""put-deployment-parameter-name-pattern-violation-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-deployment-parameter-name-pattern-violation-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-deployment"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDeploymentParameter with the name 'bad name!' fails ValidationException with the exact pattern
    message, while a pattern-valid name on the same unknown productId/agreementId fails
    ResourceNotFoundException, so the rejection is specific to the name."""
    md = _md_client(ctx)
    product_id = ctx.unique_name("prod-")
    agreement_id = ctx.unique_name("agr-")

    def _put(name: str):
        return md.put_deployment_parameter(
            catalog="AWSMarketplace",
            productId=product_id,
            agreementId=agreement_id,
            deploymentParameter={"name": name, "secretString": "s3cr3t-value-1"},
        )

    control_code, control_message = _error(lambda: _put(ctx.unique_name("sim2real-dp-")))
    assert control_code == "ResourceNotFoundException", (
        f"positive control: a pattern-valid name against a never-provisioned agreement should "
        f"be rejected with ResourceNotFoundException, got {control_code!r}"
    )
    assert control_message == (
        "ProductId: Request references a resource which does not exist."
    ), control_message

    code, message = _error(lambda: _put("bad name!"))
    assert code == "ValidationException", (
        f"a name containing a space and '!' violates the [a-zA-Z0-9/_+=.@-]+ pattern and "
        f"should be rejected with ValidationException, got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value 'bad name!' at 'deploymentParameter.name' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9/_+=.@-]+"
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
