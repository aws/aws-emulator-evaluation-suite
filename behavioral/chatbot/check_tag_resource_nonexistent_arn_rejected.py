"""tag-resource-nonexistent-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["chatbot"]


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource and ListTagsForResource on a well-formed custom-action ARN that was never created fail with
    UnauthorizedException "Unauthorized", not ResourceNotFoundException, while tagging a real custom action
    stores exactly {"k": "v"}."""
    chatbot = ctx.client("chatbot")
    sts = ctx.client("sts")
    region = ctx.region
    account_id = sts.get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:chatbot:{region}:{account_id}:custom-action/"
        f"{ctx.unique_name('sim2real-ca-nonexistent-')}"
    )

    code, message = _error(
        lambda: chatbot.tag_resource(ResourceARN=bogus_arn, Tags=[{"TagKey": "k", "TagValue": "v"}])
    )
    assert code == "UnauthorizedException", f"unexpected code={code!r}"
    assert message == "Unauthorized", f"unexpected message={message!r}"

    # Independent read: the rejected TagResource must not have persisted anything an
    # over-permissive target could still expose under the same bogus ARN.
    list_code, list_message = _error(lambda: chatbot.list_tags_for_resource(ResourceARN=bogus_arn))
    assert list_code == "UnauthorizedException", f"unexpected code={list_code!r}"
    assert list_message == "Unauthorized", f"unexpected message={list_message!r}"

    # Positive control: tagging a real, existing resource succeeds.
    real_arn = chatbot.create_custom_action(
        ActionName=ctx.unique_name("sim2real-ca-"),
        Definition={"CommandText": "echo control"},
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=real_arn))

    chatbot.tag_resource(ResourceARN=real_arn, Tags=[{"TagKey": "k", "TagValue": "v"}])
    tags = {t["TagKey"]: t["TagValue"] for t in chatbot.list_tags_for_resource(ResourceARN=real_arn)["Tags"]}
    assert tags == {"k": "v"}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
