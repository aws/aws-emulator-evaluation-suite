"""op-contract-listTagsForResource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-listTagsForResource"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource returns exactly the tags applied at job-definition registration
    time; a syntactically invalid resource ARN is rejected with BadRequestException."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jd-")
    reg = batch.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "command": ["sleep", "30"],
            "resourceRequirements": [{"type": "VCPU", "value": "1"}, {"type": "MEMORY", "value": "512"}],
        },
        tags={"team": "sim2real", "stage": "alpha"},
    )
    jd_arn = reg["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=jd_arn))

    tags = batch.list_tags_for_resource(resourceArn=jd_arn)["tags"]
    assert tags == {"team": "sim2real", "stage": "alpha"}, f"expected the tags set at registration, got {tags!r}"

    # Error boundary: a syntactically invalid (non-ARN) resource identifier is rejected. Real
    # Batch's REST front end rejects a resourceArn that doesn't even parse as an ARN at the
    # request-framework level, surfacing the generic "BadRequestException" rather than the
    # operation-specific ClientException/ServerException pair declared in the service model.
    code, message = _error_code(lambda: batch.list_tags_for_resource(resourceArn="this-is-not-an-arn"))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "Invalid input resource arn: bad syntax", f"unexpected message {message!r}"

    # The real resource's tags are unaffected by the rejected lookup against the bogus ARN.
    still_tags = batch.list_tags_for_resource(resourceArn=jd_arn)["tags"]
    assert still_tags == tags, f"expected unaffected {tags!r}, got {still_tags!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected list_tags_for_resource to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
