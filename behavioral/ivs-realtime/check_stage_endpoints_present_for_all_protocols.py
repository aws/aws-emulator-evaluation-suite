"""stage-endpoints-present-for-all-protocols."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stage-endpoints-present-for-all-protocols"
GROUP = "data-plane"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new stage's endpoints block carries non-empty, distinct events, whip, rtmp and rtmps hostnames, which
    real clients need even though control-plane CRUD never uses them."""
    client = ctx.client("ivs-realtime")
    stage = client.create_stage(
        name=ctx.unique_name("sim2real-stage"), tags={"sim2real": CHECK}
    )["stage"]
    stage_arn = stage["arn"]
    ctx.on_cleanup(lambda: client.delete_stage(arn=stage_arn))

    endpoints = client.get_stage(arn=stage_arn)["stage"]["endpoints"]
    for key in ("events", "whip", "rtmp", "rtmps"):
        assert endpoints.get(key), f"endpoints.{key} was empty/missing: {endpoints!r}"

    values = {endpoints["events"], endpoints["whip"], endpoints["rtmp"], endpoints["rtmps"]}
    assert len(values) == 4, f"expected 4 distinct endpoint hostnames, got {values!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
