"""tag-and-untag-resource-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-and-untag-resource-roundtrip"
GROUP = "adapter-lifecycle"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds entries to the adapter's tag map; UntagResource removes exactly those keys."""
    textract = ctx.client("textract")
    name = ctx.unique_name("sim2real-adapter-")
    adapter_id = textract.create_adapter(AdapterName=name, FeatureTypes=["QUERIES"])["AdapterId"]
    ctx.on_cleanup(lambda: textract.delete_adapter(AdapterId=adapter_id))

    arn = _adapter_arn(ctx, adapter_id)

    textract.tag_resource(ResourceARN=arn, Tags={"env": "sim2real", "purpose": "fidelity-check"})
    tags = textract.list_tags_for_resource(ResourceARN=arn)["Tags"]
    assert tags.get("env") == "sim2real", f"expected tag env=sim2real, got {tags.get('env')!r}"
    assert tags.get("purpose") == "fidelity-check", (
        f"expected tag purpose=fidelity-check, got {tags.get('purpose')!r}"
    )

    textract.untag_resource(ResourceARN=arn, TagKeys=["purpose"])
    tags_after = textract.list_tags_for_resource(ResourceARN=arn)["Tags"]
    assert tags_after.get("env") == "sim2real", (
        f"expected untouched tag env=sim2real to survive untag, got {tags_after.get('env')!r}"
    )
    assert "purpose" not in tags_after, (
        f"expected purpose to be removed by UntagResource, still present: {tags_after!r}"
    )


def _adapter_arn(ctx, adapter_id: str) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:textract:{ctx.region}:{account_id}:/adapters/{adapter_id}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
