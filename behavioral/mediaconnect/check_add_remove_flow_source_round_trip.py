"""add-remove-flow-source-round-trip."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags

CHECK = "add-remove-flow-source-round-trip"
GROUP = "data-plane"
SERVICES = ["mediaconnect"]


def _port_for(name: str, base: int = 5000, spread: int = 4000) -> int:
    """Derive a pseudo-unique ingest port from a name to avoid cross-check port
    collisions when many flows are created concurrently in the same account/region."""
    return base + (int(hashlib.sha1(name.encode()).hexdigest(), 16) % spread)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddFlowSources attaches an additional source that is immediately visible on
    DescribeFlow (now two sources); RemoveFlowSource detaches it, leaving exactly
    the original source and leaving the removed source's ARN unusable."""
    mc = ctx.client("mediaconnect")
    flow_name = ctx.unique_name("sim2real-mc-flow-")
    flow_arn = mc.create_flow(
        Name=flow_name,
        Source={
            "Name": "source1",
            "Protocol": "rtp",
            "WhitelistCidr": "203.0.113.0/24",
            "IngestPort": _port_for(flow_name + "-1"),
        },
        FlowTags={"sim2real:managed": "true", "sim2real": CHECK},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: mc.delete_flow(FlowArn=flow_arn))

    original_sources = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Sources"]
    assert len(original_sources) == 1, f"expected 1 source at creation, got {len(original_sources)}"

    # source failover must be enabled before a second source can be added
    mc.update_flow(
        FlowArn=flow_arn,
        SourceFailoverConfig={"State": "ENABLED", "FailoverMode": "MERGE", "RecoveryWindow": 200},
    )

    add_resp = mc.add_flow_sources(
        FlowArn=flow_arn,
        Sources=[
            {
                "Name": "source2",
                "Protocol": "rtp",
                "WhitelistCidr": "203.0.113.0/24",
                "IngestPort": _port_for(flow_name + "-2"),
            }
        ],
    )
    new_source_arn = add_resp["Sources"][0]["SourceArn"]

    sources = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Sources"]
    assert len(sources) == 2, f"expected 2 sources after add, got {len(sources)}"
    arns = {s["SourceArn"] for s in sources}
    assert new_source_arn in arns, f"expected {new_source_arn} in {arns} after add_flow_sources"

    mc.remove_flow_source(FlowArn=flow_arn, SourceArn=new_source_arn)

    sources = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Sources"]
    assert len(sources) == 1, f"expected 1 source after remove, got {len(sources)}"
    arns = {s["SourceArn"] for s in sources}
    assert new_source_arn not in arns, f"expected {new_source_arn} absent from {arns} after remove_flow_source"

    # the removed source's ARN is now dead: a mutation against it must fail, not silently no-op
    code, message = _client_error(
        lambda: mc.update_flow_source(FlowArn=flow_arn, SourceArn=new_source_arn, Description="dead")
    )
    assert code == "NotFoundException", f"expected NotFoundException updating removed source, got {code}"
    expected = f"Not found: {new_source_arn}"
    assert message == expected, f"expected message {expected!r} updating removed source, got {message!r}"


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    accepting a mutation real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected NotFoundException updating removed source, but call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
