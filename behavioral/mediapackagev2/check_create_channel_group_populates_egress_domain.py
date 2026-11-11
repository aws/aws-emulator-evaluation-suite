"""create-channel-group-populates-egress-domain."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "create-channel-group-populates-egress-domain"
GROUP = "control-plane"
SERVICES = ["mediapackagev2"]

_EGRESS_DOMAIN_RE = re.compile(r"[A-Za-z0-9.-]+(:\d+)?")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannelGroup returns a real EgressDomain/Arn/ETag and GetChannelGroup reflects them."""
    mp = ctx.client("mediapackagev2")
    name = ctx.unique_name("sim2real-mpkg-cg-")
    created = mp.create_channel_group(
        ChannelGroupName=name, Description="behavioral check", Tags={"sim2real-audit": "true"}
    )
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=name))

    assert created["ChannelGroupName"] == name, f"expected ChannelGroupName {name!r}, got {created.get('ChannelGroupName')!r}"
    assert created["Arn"].endswith(name), f"expected Arn to end with {name!r}, got {created.get('Arn')!r}"
    egress_domain = created["EgressDomain"]
    assert _EGRESS_DOMAIN_RE.fullmatch(egress_domain or ""), (
        f"expected EgressDomain to be a well-formed hostname, got {egress_domain!r}"
    )
    assert created["ETag"], f"expected a non-empty ETag, got {created.get('ETag')!r}"

    got = mp.get_channel_group(ChannelGroupName=name)
    assert got["ChannelGroupName"] == name, f"expected ChannelGroupName {name!r}, got {got.get('ChannelGroupName')!r}"
    assert got["EgressDomain"] == created["EgressDomain"], (
        f"GetChannelGroup EgressDomain {got.get('EgressDomain')!r} != CreateChannelGroup's {egress_domain!r}"
    )
    assert got["Arn"] == created["Arn"], f"GetChannelGroup Arn {got.get('Arn')!r} != CreateChannelGroup's {created['Arn']!r}"
    assert got["ETag"] == created["ETag"], f"GetChannelGroup ETag {got.get('ETag')!r} != CreateChannelGroup's {created['ETag']!r}"
    assert got["Description"] == "behavioral check", f"expected Description 'behavioral check', got {got.get('Description')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
