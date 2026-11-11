"""untag-resource-nonexistent-key-is-idempotent-noop."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-resource-nonexistent-key-is-idempotent-noop"
GROUP = "state"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a TagKey that was never present on the resource succeeds as a
    harmless no-op (does not raise), and the resource's existing tags are left
    completely untouched."""
    chatbot = ctx.client("chatbot")
    name = ctx.unique_name("sim2realuntagnoop").replace("-", "")[:64]
    arn = chatbot.create_custom_action(ActionName=name, Definition={"CommandText": "echo untagnoop"})[
        "CustomActionArn"
    ]
    ctx.on_cleanup(lambda: _safe_delete(ctx, arn))

    chatbot.tag_resource(ResourceARN=arn, Tags=[{"TagKey": "present", "TagValue": "yes"}])

    # "never-set" was never applied to this resource; removing it must be a no-op.
    chatbot.untag_resource(ResourceARN=arn, TagKeys=["never-set"])

    tags = chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]
    tag_map = {t["TagKey"]: t["TagValue"] for t in tags}
    assert tag_map == {"present": "yes"}, (
        f"untagging a never-set key must leave existing tags untouched: expected "
        f"{{'present': 'yes'}}, got {tag_map}"
    )


def _safe_delete(ctx, arn: str) -> None:
    chatbot = ctx.client("chatbot")
    try:
        chatbot.delete_custom_action(CustomActionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
