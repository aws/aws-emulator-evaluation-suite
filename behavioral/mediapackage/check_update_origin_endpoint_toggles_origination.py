"""update-origin-endpoint-toggles-origination."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-origin-endpoint-toggles-origination"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateOriginEndpoint's Origination flag transitions ALLOW <-> DENY and the
    transition is durably visible via DescribeOriginEndpoint."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-orig-")
    mp.create_channel(Id=cid, Tags={"created-by": "sim2real"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))

    oid = ctx.unique_name("sim2real-mp-oe-")
    mp.create_origin_endpoint(
        Id=oid, ChannelId=cid, HlsPackage={}, Tags={"created-by": "sim2real"}
    )

    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=oid))

    denied = mp.update_origin_endpoint(Id=oid, Origination="DENY", HlsPackage={})
    assert denied["Origination"] == "DENY", (
        f"expected update response Origination=DENY, got {denied['Origination']!r}"
    )
    described_denied = mp.describe_origin_endpoint(Id=oid)
    assert described_denied["Origination"] == "DENY", (
        f"expected DescribeOriginEndpoint Origination=DENY after update, "
        f"got {described_denied['Origination']!r}"
    )

    allowed = mp.update_origin_endpoint(Id=oid, Origination="ALLOW", HlsPackage={})

    assert allowed["Origination"] == "ALLOW", (
        f"expected update response Origination=ALLOW, got {allowed['Origination']!r}"
    )
    described_allowed = mp.describe_origin_endpoint(Id=oid)
    assert described_allowed["Origination"] == "ALLOW", (
        f"expected DescribeOriginEndpoint Origination=ALLOW after update, "
        f"got {described_allowed['Origination']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
