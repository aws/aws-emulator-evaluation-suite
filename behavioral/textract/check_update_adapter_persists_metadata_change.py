"""update-adapter-persists-metadata-change."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-adapter-persists-metadata-change"
GROUP = "adapter-lifecycle"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAdapter mutates Description/AutoUpdate/AdapterName in place, visible via GetAdapter."""
    textract = ctx.client("textract")
    name = ctx.unique_name("sim2real-adapter-")
    new_name = name + "-renamed"
    adapter_id = textract.create_adapter(
        AdapterName=name,
        FeatureTypes=["QUERIES"],
        Description="original description",
        AutoUpdate="DISABLED",
    )["AdapterId"]
    ctx.on_cleanup(lambda: textract.delete_adapter(AdapterId=adapter_id))

    updated = textract.update_adapter(
        AdapterId=adapter_id,
        AdapterName=new_name,
        Description="updated description",
        AutoUpdate="ENABLED",
    )
    assert updated["AdapterName"] == new_name, (
        f"expected UpdateAdapter response AdapterName={new_name!r}, got {updated['AdapterName']!r}"
    )
    assert updated["Description"] == "updated description", (
        f"expected UpdateAdapter response Description='updated description', got {updated['Description']!r}"
    )
    assert updated["AutoUpdate"] == "ENABLED", (
        f"expected UpdateAdapter response AutoUpdate='ENABLED', got {updated['AutoUpdate']!r}"
    )

    got = textract.get_adapter(AdapterId=adapter_id)
    assert got["AdapterName"] == new_name, (
        f"expected GetAdapter AdapterName={new_name!r} after update, got {got['AdapterName']!r}"
    )
    assert got["Description"] == "updated description", (
        f"expected GetAdapter Description='updated description' after update, got {got['Description']!r}"
    )
    assert got["AutoUpdate"] == "ENABLED", (
        f"expected GetAdapter AutoUpdate='ENABLED' after update, got {got['AutoUpdate']!r}"
    )
    # FeatureTypes was not part of the update request and must be unaffected.
    assert got["FeatureTypes"] == ["QUERIES"], (
        f"expected GetAdapter FeatureTypes unchanged as ['QUERIES'], got {got['FeatureTypes']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
