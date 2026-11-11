"""tag-nonexistent-resource-fails."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "tag-nonexistent-resource-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so accepting the
    call fails as itself and not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected TagResource against a nonexistent resource to fail, but it succeeded: {result!r}"
    )


def _batch_arn(ctx, resource):
    """Build an in-account Batch ARN, e.g. _batch_arn(ctx, "job-queue/nope")."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:batch:{ctx.region}:{account}:{resource}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on a job definition the check creates succeeds and ListTagsForResource shows the
    tag, while TagResource on a Batch ARN that does not exist fails with NotFoundException and the
    message "Resource was not found"."""
    bat = ctx.client("batch")

    name = ctx.unique_name("sim2real-behav-batch-jd-")
    reg = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "command": ["true"],
            "resourceRequirements": [{"type": "VCPU", "value": "1"}, {"type": "MEMORY", "value": "512"}],
        },
    )
    jd_arn = reg["jobDefinitionArn"]
    ctx.on_cleanup(lambda: bat.deregister_job_definition(jobDefinition=jd_arn))

    bat.tag_resource(resourceArn=jd_arn, tags={"env": "fidelity"})
    live_tags = bat.list_tags_for_resource(resourceArn=jd_arn)["tags"]
    assert live_tags == {"env": "fidelity"}, (
        f"positive control failed: TagResource against a real job definition did not stick, got {live_tags!r}"
    )

    bogus_arn = _batch_arn(ctx, "job-queue/sim2real-behav-batch-absent")
    error = _error(lambda: bat.tag_resource(resourceArn=bogus_arn, tags={"env": "fidelity"}))
    code, message = error.get("Code"), error.get("Message")
    assert code == "NotFoundException", (
        f"expected NotFoundException tagging an unknown in-account resource, got {code!r}"
    )
    assert message == "Resource was not found", (
        f"expected the exact TagResource not-found message, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
