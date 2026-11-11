"""associate-feed-appends-outputs-patch-semantics."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "associate-feed-appends-outputs-patch-semantics"
GROUP = "data-plane"
SERVICES = ["elementalinference"]


def _subtitling_output(name: str, language: str = "eng") -> dict:
    return {"name": name, "outputConfig": {"subtitling": {"language": language}}, "status": "ENABLED"}


def _smart_crop_output(name: str) -> dict:
    return {"name": name, "outputConfig": {"cropping": {}}, "status": "ENABLED"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateFeed is a PATCH: new outputs are appended, existing outputs from CreateFeed are left untouched."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    created = ei.create_feed(
        name=name, outputs=[_subtitling_output("out-a")], tags={"sim2real": CHECK}
    )
    feed_id = created["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))
    created_out_a = next(o for o in created["outputs"] if o["name"] == "out-a")

    resource_name = ctx.unique_name("sim2real-ei-src-")
    ei.associate_feed(
        id=feed_id,
        associatedResourceName=resource_name,
        outputs=[_smart_crop_output("out-b")],
    )

    got = ei.get_feed(id=feed_id)
    names = {o["name"] for o in got["outputs"]}
    assert names == {"out-a", "out-b"}, f"expected both outputs to remain, got {names}"
    by_name = {o["name"]: o for o in got["outputs"]}
    assert by_name["out-a"].get("fromAssociation", False) is False
    assert by_name["out-b"]["fromAssociation"] is True
    # The pre-existing output must be left untouched, not just present by name: compare
    # against what CreateFeed itself reported, not a reconstruction of the input.
    assert by_name["out-a"] == created_out_a, (
        f"existing output body changed by AssociateFeed: {by_name['out-a']} != {created_out_a}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
