"""list-tags-for-resource-returns-tags-set-at-creation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-returns-tags-set-at-creation"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags provided at CreateChannel time are retrievable via ListTagsForResource
    using the channel's own Arn."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-tags-")
    created = mp.create_channel(
        Id=cid, Tags={"env": "sim2real-test", "purpose": "behavioral-check"}
    )
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))
    arn = created["Arn"]

    listed = mp.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert listed.get("env") == "sim2real-test", (
        f"expected creation tag env=sim2real-test, got {listed.get('env')!r}"
    )
    assert listed.get("purpose") == "behavioral-check", (
        f"expected creation tag purpose=behavioral-check, got {listed.get('purpose')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
