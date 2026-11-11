"""update-tags-exceeds-quota-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-tags-exceeds-quota-rejected"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTagsForResource that would push a resource's tag count past the 50-tag quota is
    rejected with TooManyTagsException, and none of the offending tags are persisted; a
    same-file positive control adding a tag set under the quota succeeds and persists."""
    eb = ctx.client("elasticbeanstalk")

    app_name = ctx.unique_name("sim2real-ebquota-app-")
    app_arn = eb.create_application(ApplicationName=app_name)["Application"]["ApplicationArn"]
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name))

    too_many_tags = [{"Key": f"sim2real-k{i}", "Value": f"v{i}"} for i in range(60)]
    code, message = _error_code(lambda: eb.update_tags_for_resource(ResourceArn=app_arn, TagsToAdd=too_many_tags))
    assert code == "TooManyTagsException", f"expected TooManyTagsException, got {code!r}"
    expected_message = "The maximum number of tags per resource is exceeded. The number of allowed tags is 50."
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    after_reject = eb.list_tags_for_resource(ResourceArn=app_arn)["ResourceTags"]
    assert not after_reject, f"tags leaked onto the resource despite the quota rejection: {after_reject}"

    # positive control: a tag set safely under the quota succeeds and is actually persisted
    small_tags = [{"Key": "sim2real-owner", "Value": "behavioral-check"}]
    eb.update_tags_for_resource(ResourceArn=app_arn, TagsToAdd=small_tags)
    after_accept = eb.list_tags_for_resource(ResourceArn=app_arn)["ResourceTags"]
    assert {"Key": "sim2real-owner", "Value": "behavioral-check"} in after_accept, (
        f"expected the under-quota tag to persist, got {after_accept}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (Error code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
