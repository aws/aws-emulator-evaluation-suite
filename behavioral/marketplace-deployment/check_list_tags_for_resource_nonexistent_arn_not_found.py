"""list-tags-for-resource-nonexistent-arn-not-found."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-nonexistent-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["marketplace-deployment"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a never-created ARN of the DeploymentParameter resource shape fails
    NotFoundException with message 'Resource was not found', never an empty tag map that would read
    as "no tags yet"."""
    md = _md_client(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = (
        f"arn:aws:aws-marketplace:us-east-1:{account_id}:DeploymentParameter:"
        f"catalogs/AWSMarketplace/products/{ctx.unique_name('prod-')}/"
        f"{ctx.unique_name('dp-')}"
    )

    code, message = _error(lambda: md.list_tags_for_resource(resourceArn=fake_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Resource was not found", message



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
