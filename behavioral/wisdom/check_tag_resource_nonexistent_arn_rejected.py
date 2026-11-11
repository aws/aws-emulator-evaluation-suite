"""tag-resource-nonexistent-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-nonexistent-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource against an ARN that does not correspond to any Wisdom resource is rejected
    with NotFoundException and the exact message, has no effect on a real resource, while tagging a real
    resource (positive control) succeeds."""
    wisdom = ctx.client("wisdom")
    assistant = wisdom.create_assistant(name=ctx.unique_name("sim2real-behav-asst-"), type="AGENT")["assistant"]
    assistant_id = assistant["assistantId"]
    real_arn = assistant["assistantArn"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_assistant(assistantId=assistant_id)))

    fake_arn = real_arn.rsplit("/", 1)[0] + "/00000000-0000-0000-0000-000000000000"
    assert fake_arn != real_arn, f"fabricated ARN collided with the real ARN {real_arn}"

    baseline = wisdom.list_tags_for_resource(resourceArn=real_arn)["tags"]
    assert baseline == {}, f"expected no tags on the fresh assistant, got {baseline}"

    code, message = _error(lambda: wisdom.tag_resource(resourceArn=fake_arn, tags={"k": "v"}))
    assert code == "NotFoundException", f"code={code}"
    assert message == "Resource was not found", f"message={message!r}"

    # effect absent: the rejected call against the fake ARN must not have tagged the real resource
    untouched = wisdom.list_tags_for_resource(resourceArn=real_arn)["tags"]
    assert untouched == {}, f"expected real resource untouched by the rejected call, got {untouched}"

    # positive control: tagging the real resource succeeds
    wisdom.tag_resource(resourceArn=real_arn, tags={"k": "v"})
    applied = wisdom.list_tags_for_resource(resourceArn=real_arn)["tags"]
    assert applied == {"k": "v"}, f"expected {{'k': 'v'}} after tagging the real resource, got {applied}"


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return the botocore (error code, error message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
