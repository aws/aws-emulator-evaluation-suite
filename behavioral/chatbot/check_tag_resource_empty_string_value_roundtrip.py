"""tag-resource-empty-string-value-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-empty-string-value-roundtrip"
GROUP = "state"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with an empty-string TagValue succeeds, and ListTagsForResource returns that key with
    value "" (not dropped, not null) next to a normal key with value "v"."""
    chatbot = ctx.client("chatbot")
    name = ctx.unique_name("sim2realemptytag").replace("-", "")[:64]
    arn = chatbot.create_custom_action(ActionName=name, Definition={"CommandText": "echo emptytag"})[
        "CustomActionArn"
    ]
    ctx.on_cleanup(lambda: _safe_delete(ctx, arn))

    chatbot.tag_resource(
        ResourceARN=arn,
        Tags=[{"TagKey": "empty-value-key", "TagValue": ""}, {"TagKey": "normal-key", "TagValue": "v"}],
    )

    tags = chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]
    tag_map = {t["TagKey"]: t["TagValue"] for t in tags}
    assert "empty-value-key" in tag_map, "tag with an empty-string value was dropped entirely"
    assert tag_map["empty-value-key"] == "", (
        f"expected empty-string TagValue to round-trip as '', got {tag_map['empty-value-key']!r}"
    )
    assert tag_map["normal-key"] == "v", f"expected normal-key='v', got {tag_map['normal-key']!r}"


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
