"""put-deployment-parameter-tags-exceed-max-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-deployment-parameter-tags-exceed-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-deployment"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a deployment parameter with 51 tags (documented maximum 50) fails BadRequestException
    with the exact tag-limit message rather than truncating, while a well-formed tags map with the same
    ids fails ResourceNotFoundException, so the rejection is specific to the tag count."""
    md = _md_client(ctx)
    too_many_tags = {f"key{i}": f"value{i}" for i in range(51)}

    control_code, control_message = _error(
        lambda: md.put_deployment_parameter(
            catalog="AWSMarketplace",
            productId=ctx.unique_name("prod-"),
            agreementId=ctx.unique_name("agr-"),
            deploymentParameter={
                "name": ctx.unique_name("sim2real-dp-"),
                "secretString": "s3cr3t-value-1",
            },
            tags={"one-tag": "under-the-limit"},
        )
    )
    assert control_code == "ResourceNotFoundException", control_code
    assert control_message == (
        "AgreementId: Request references a resource which does not exist."
    ), control_message

    code, message = _error(
        lambda: md.put_deployment_parameter(
            catalog="AWSMarketplace",
            productId=ctx.unique_name("prod-"),
            agreementId=ctx.unique_name("agr-"),
            deploymentParameter={
                "name": ctx.unique_name("sim2real-dp-"),
                "secretString": "s3cr3t-value-1",
            },
            tags=too_many_tags,
        )
    )
    assert code == "BadRequestException", code
    assert message == "The resultant tag set must not have more than 50 user tags.", message



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
