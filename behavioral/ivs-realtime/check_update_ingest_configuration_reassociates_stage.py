"""update-ingest-configuration-reassociates-stage."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-ingest-configuration-reassociates-stage"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIngestConfiguration re-points an INACTIVE ingest configuration at a new stage."""
    ivs = ctx.client("ivs-realtime")
    stage1 = ivs.create_stage(name=ctx.unique_name("sim2real-stage1-"))["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage1))
    stage2 = ivs.create_stage(name=ctx.unique_name("sim2real-stage2-"))["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage2))

    ingest = ivs.create_ingest_configuration(
        name=ctx.unique_name("sim2real-ingest-"),
        stageArn=stage1,
        ingestProtocol="RTMPS",
    )["ingestConfiguration"]
    arn = ingest["arn"]
    ctx.on_cleanup(lambda: ivs.delete_ingest_configuration(arn=arn))
    assert ingest["stageArn"] == stage1, ingest["stageArn"]

    updated = ivs.update_ingest_configuration(arn=arn, stageArn=stage2)["ingestConfiguration"]
    assert updated["stageArn"] == stage2, updated["stageArn"]
    assert updated["state"] == "INACTIVE", updated["state"]

    fetched = ivs.get_ingest_configuration(arn=arn)["ingestConfiguration"]
    assert fetched["stageArn"] == stage2, fetched["stageArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
