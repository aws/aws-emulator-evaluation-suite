"""tag-value-unicode-and-empty-string-preserved."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-value-unicode-and-empty-string-preserved"
GROUP = "representation"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a unicode value and a separate empty-string value both survive
    unchanged through ListTagsForResource, distinguishing empty from absent."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-")
    rum.create_app_monitor(Name=name, Domain="localhost")
    ctx.on_cleanup(lambda: _safe(lambda: rum.delete_app_monitor(Name=name)))

    arn = _app_monitor_arn(ctx, name)
    unicode_value = "日本語タグ-テスト_value.for:testing+more=stuff@example"
    rum.tag_resource(
        ResourceArn=arn,
        Tags={"sim2realUnicodeTag": unicode_value, "sim2realEmptyTag": ""},
    )

    tags = rum.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags.get("sim2realUnicodeTag") == unicode_value, tags.get("sim2realUnicodeTag")
    assert "sim2realEmptyTag" in tags, "empty-string tag key missing entirely"
    assert tags["sim2realEmptyTag"] == "", tags["sim2realEmptyTag"]
    assert "sim2realNeverSetTag" not in tags, tags.get("sim2realNeverSetTag")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name: str) -> str:
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
