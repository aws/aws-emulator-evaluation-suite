"""tag-resource-and-list-tags-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-round-trip"
GROUP = "tags"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags that then show up verbatim via ListTagsForResource."""
    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(description=ctx.unique_name("sim2real-iot-tunnel-"))
    tunnel_id = opened["tunnelId"]
    tunnel_arn = opened["tunnelArn"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    client.tag_resource(
        resourceArn=tunnel_arn,
        tags=[{"key": "env", "value": "sim2real"}, {"key": "owner", "value": "behavioral-suite"}],
    )

    listed = {t["key"]: t["value"] for t in client.list_tags_for_resource(resourceArn=tunnel_arn)["tags"]}
    assert listed.get("env") == "sim2real", f"expected tag env=sim2real, got {listed!r}"
    assert listed.get("owner") == "behavioral-suite", f"expected tag owner=behavioral-suite, got {listed!r}"
    assert listed == {"env": "sim2real", "owner": "behavioral-suite"}, (
        f"expected tags to round-trip verbatim with no extra or missing keys, got {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
