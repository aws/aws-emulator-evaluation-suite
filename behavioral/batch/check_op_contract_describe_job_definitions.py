"""op-contract-describeJobDefinitions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describeJobDefinitions"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeJobDefinitions returns full container properties for a specific ARN and both
    revisions when filtered by name; a malformed nextToken is rejected."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jd-")
    image_v1 = "public.ecr.aws/amazonlinux/amazonlinux:2023"
    image_v2 = "public.ecr.aws/docker/library/busybox:latest"

    tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch-jd-"}

    r1 = batch.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": image_v1,
            "command": ["sleep", "30"],
            "resourceRequirements": [{"type": "VCPU", "value": "1"}, {"type": "MEMORY", "value": "512"}],
        },
        tags=tags,
    )
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=r1["jobDefinitionArn"]))

    r2 = batch.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": image_v2,
            "command": ["sleep", "45"],
            "resourceRequirements": [{"type": "VCPU", "value": "1"}, {"type": "MEMORY", "value": "512"}],
        },
        tags=tags,
    )
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=r2["jobDefinitionArn"]))

    by_arn = batch.describe_job_definitions(jobDefinitions=[r1["jobDefinitionArn"]])["jobDefinitions"]
    assert len(by_arn) == 1, f"expected exactly one job definition for the ARN, got {len(by_arn)}"
    assert by_arn[0]["containerProperties"]["image"] == image_v1, (
        f"expected image {image_v1!r}, got {by_arn[0]['containerProperties'].get('image')!r}"
    )
    assert by_arn[0]["containerProperties"]["command"] == ["sleep", "30"], (
        f"expected full container properties, got command={by_arn[0]['containerProperties'].get('command')!r}"
    )
    assert by_arn[0]["revision"] == r1["revision"], (
        f"expected revision {r1['revision']!r}, got {by_arn[0]['revision']!r}"
    )

    by_name = batch.describe_job_definitions(jobDefinitionName=name)["jobDefinitions"]
    images_by_revision = {jd["revision"]: jd["containerProperties"]["image"] for jd in by_name}
    expected = {r1["revision"]: image_v1, r2["revision"]: image_v2}
    assert images_by_revision == expected, f"expected {expected}, got {images_by_revision}"

    # Error boundary: a malformed nextToken is rejected.
    code, message = _error_code(lambda: batch.describe_job_definitions(nextToken="!!not-a-valid-token!!"))
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    assert message == "Error processing next token", f"unexpected message {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
