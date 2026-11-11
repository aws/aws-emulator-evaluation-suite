"""stage-endpoints-present-all-protocols."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stage-endpoints-present-all-protocols"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStage returns non-empty, distinct events/whip/rtmp/rtmps endpoint URLs for
    the new stage, and a subsequent independent GetStage reports the identical block."""
    ivs = ctx.client("ivs-realtime")
    created = ivs.create_stage(
        name=ctx.unique_name("sim2real-stage-"),
        tags={"sim2real": "stage-endpoints-present-all-protocols"},
    )["stage"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=arn))

    endpoints = created["endpoints"]
    for key in ("events", "whip", "rtmp", "rtmps"):
        assert endpoints.get(key), (key, endpoints)

    # rtmp/rtmps endpoints must actually be well-formed rtmp(s) URLs.
    assert endpoints["rtmp"].startswith("rtmp://"), endpoints["rtmp"]
    assert endpoints["rtmps"].startswith("rtmps://"), endpoints["rtmps"]

    # A lazy implementation could satisfy every check above by returning the same
    # placeholder hostname for all four protocols; each must resolve independently.
    values = {endpoints[key] for key in ("events", "whip", "rtmp", "rtmps")}
    assert len(values) == 4, (values, endpoints)

    fetched = ivs.get_stage(arn=arn)["stage"]["endpoints"]
    assert fetched == endpoints, (fetched, endpoints)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
