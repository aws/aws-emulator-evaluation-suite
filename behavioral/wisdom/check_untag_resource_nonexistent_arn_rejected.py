"""untag-resource-nonexistent-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-resource-nonexistent-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource against an ARN that does not correspond to any Wisdom resource is rejected
    with NotFoundException and the exact message, while untagging a real, tagged resource (positive control)
    succeeds and actually removes the tag."""
    wisdom = ctx.client("wisdom")
    assistant = wisdom.create_assistant(
        name=ctx.unique_name("sim2real-behav-asst-"), type="AGENT", tags={"k": "v"}
    )["assistant"]
    assistant_id = assistant["assistantId"]
    real_arn = assistant["assistantArn"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_assistant(assistantId=assistant_id)))

    fake_arn = real_arn.rsplit("/", 1)[0] + "/00000000-0000-0000-0000-000000000000"
    assert fake_arn != real_arn, f"fake_arn {fake_arn!r} collided with real_arn {real_arn!r}"

    code, message = _error(lambda: wisdom.untag_resource(resourceArn=fake_arn, tagKeys=["k"]))
    assert code == "NotFoundException", f"code={code}"
    assert message == "Resource was not found", f"message={message!r}"

    # effect absent: the real resource's tag is untouched by the failed call
    still_tagged = wisdom.list_tags_for_resource(resourceArn=real_arn)["tags"]
    assert still_tagged == {"k": "v"}, f"tags={still_tagged}, expected the untouched {{'k': 'v'}}"

    # positive control: untagging the real resource succeeds and removes the tag
    wisdom.untag_resource(resourceArn=real_arn, tagKeys=["k"])
    after = wisdom.list_tags_for_resource(resourceArn=real_arn)["tags"]
    assert after == {}, f"tags={after} after UntagResource on the real ARN, expected {{}}"


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Return the rejected call's (error code, error message). An unexpected SUCCESS raises, because
    an over-permissive target accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
