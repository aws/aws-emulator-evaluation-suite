"""untag-resource-removes-tag-from-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag-from-list"
GROUP = "tags"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named key, leaving the other tags intact."""
    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(description=ctx.unique_name("sim2real-iot-tunnel-"))
    tunnel_id = opened["tunnelId"]
    tunnel_arn = opened["tunnelArn"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    client.tag_resource(
        resourceArn=tunnel_arn,
        tags=[{"key": "keep-me", "value": "1"}, {"key": "drop-me", "value": "2"}],
    )
    client.untag_resource(resourceArn=tunnel_arn, tagKeys=["drop-me"])

    tags = {t["key"]: t["value"] for t in client.list_tags_for_resource(resourceArn=tunnel_arn)["tags"]}
    assert "drop-me" not in tags, f"expected 'drop-me' removed, got tags={tags}"
    assert tags.get("keep-me") == "1", f"expected keep-me='1' preserved, got {tags.get('keep-me')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
