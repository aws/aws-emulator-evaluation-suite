"""open-tunnel-initial-tags-visible-in-describe-and-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "open-tunnel-initial-tags-visible-in-describe-and-list"
GROUP = "tags"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied on OpenTunnel show up on both DescribeTunnel and ListTagsForResource."""
    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-"),
        tags=[{"key": "purpose", "value": "sim2real-initial-tag"}],
    )
    tunnel_id = opened["tunnelId"]
    tunnel_arn = opened["tunnelArn"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    described = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
    described_tags = {t["key"]: t["value"] for t in described.get("tags", [])}
    assert described_tags.get("purpose") == "sim2real-initial-tag", (
        f"DescribeTunnel tags expected purpose=sim2real-initial-tag, got {described_tags!r}"
    )

    listed_tags = {t["key"]: t["value"] for t in client.list_tags_for_resource(resourceArn=tunnel_arn)["tags"]}
    assert listed_tags.get("purpose") == "sim2real-initial-tag", (
        f"ListTagsForResource expected purpose=sim2real-initial-tag, got {listed_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
