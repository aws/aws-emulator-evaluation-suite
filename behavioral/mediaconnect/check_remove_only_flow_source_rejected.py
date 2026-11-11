"""remove-only-flow-source-rejected."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags

CHECK = "remove-only-flow-source-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediaconnect"]


def _port_for(name: str, base: int = 5000, spread: int = 4000) -> int:
    """Derive a pseudo-unique ingest port from a name to avoid cross-check port
    collisions when many flows are created concurrently in the same account/region."""
    return base + (int(hashlib.sha1(name.encode()).hexdigest(), 16) % spread)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemoveFlowSource on a flow's only source fails BadRequestException with the exact message and the
    source stays; once a second source is added, the identical call succeeds and only the second source
    remains."""
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
        FlowTags={"sim2real-check": CHECK},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: mc.delete_flow(FlowArn=flow_arn))

    sources = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Sources"]
    assert len(sources) == 1, (
        f"expected exactly 1 source right after CreateFlow, got {len(sources)}: {sources!r}"
    )
    only_source_arn = sources[0]["SourceArn"]

    error = _client_error(
        lambda: mc.remove_flow_source(FlowArn=flow_arn, SourceArn=only_source_arn)
    )
    assert error.get("Code") == "BadRequestException", (
        f"removing the flow's only source was rejected with {error.get('Code')!r}, "
        f"expected 'BadRequestException'"
    )
    expected = (
        "Validation failed:\nYour request removes the only source that is assigned to this flow. "
        "Each flow must have at least one source. Review the existing source and make changes as "
        "needed. Your request removes all sources that are assigned to this flow."
    )
    assert error.get("Message") == expected, (
        f"expected message {expected!r} removing the flow's only source, got {error.get('Message')!r}"
    )

    # effect absent: the source is still there
    sources = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Sources"]
    assert len(sources) == 1, (
        f"the rejected RemoveFlowSource changed the source count to {len(sources)}: {sources!r}"
    )
    assert sources[0]["SourceArn"] == only_source_arn, (
        f"the rejected RemoveFlowSource left source {sources[0]['SourceArn']!r}, "
        f"expected the original {only_source_arn!r} untouched"
    )

    # restore: once a second source exists, removal is allowed
    # (source failover must be enabled before a second source can be added)
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
    second_source_arn = add_resp["Sources"][0]["SourceArn"]

    # the identical call that was just rejected succeeds
    mc.remove_flow_source(FlowArn=flow_arn, SourceArn=only_source_arn)
    sources = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Sources"]
    assert {s["SourceArn"] for s in sources} == {second_source_arn}, (
        f"after removing the once-rejected source now that a second source exists, "
        f"expected only {second_source_arn!r} to remain, "
        f"got {[s['SourceArn'] for s in sources]!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except Exception as exc:
        error = getattr(exc, "response", {}).get("Error")
        if error is not None:
            return error
        raise
    raise AssertionError(
        f"real AWS rejects removing the flow's only source, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
