"""op-contract-tagResource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-tagResource"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource merges new tags onto a job definition without disturbing existing ones;
    tagging a nonexistent resource ARN is rejected with NotFoundException."""
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
        tags={"owner": "sim2real"},
    )
    jd_arn = reg["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=jd_arn))

    initial = batch.list_tags_for_resource(resourceArn=jd_arn)["tags"]
    assert initial == {"owner": "sim2real"}, initial

    batch.tag_resource(resourceArn=jd_arn, tags={"env": "test"})
    merged = batch.list_tags_for_resource(resourceArn=jd_arn)["tags"]
    assert merged == {"owner": "sim2real", "env": "test"}, "TagResource must merge, not replace, existing tags"

    # Error boundary: tagging a nonexistent resource ARN is rejected.
    fake_arn = jd_arn.rsplit("/", 1)[0] + "/" + ctx.unique_name("sim2real-batch-jd-missing-") + ":1"
    code, message = _error_code(lambda: batch.tag_resource(resourceArn=fake_arn, tags={"env": "test"}))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "Resource was not found", f"unexpected message {message!r}"
    # The real resource's tags must remain exactly as merged above.
    still_merged = batch.list_tags_for_resource(resourceArn=jd_arn)["tags"]
    assert still_merged == {"owner": "sim2real", "env": "test"}, still_merged


def _error_code(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
