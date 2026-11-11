"""update-ingest-configuration-reassign-stage."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-ingest-configuration-reassign-stage"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIngestConfiguration moves an inactive ingest configuration to another stage, and
    GetIngestConfiguration then reads the new stageArn with state INACTIVE."""
    client = ctx.client("ivs-realtime")
    stage_a = client.create_stage(name=ctx.unique_name("sim2real-stage-a"))["stage"]["arn"]
    ctx.on_cleanup(lambda: client.delete_stage(arn=stage_a))
    stage_b = client.create_stage(name=ctx.unique_name("sim2real-stage-b"))["stage"]["arn"]
    ctx.on_cleanup(lambda: client.delete_stage(arn=stage_b))

    ingest = client.create_ingest_configuration(
        name=ctx.unique_name("sim2real-ingest"), stageArn=stage_a, ingestProtocol="RTMPS"
    )["ingestConfiguration"]
    ingest_arn = ingest["arn"]
    ctx.on_cleanup(lambda: client.delete_ingest_configuration(arn=ingest_arn, force=True))
    assert ingest["stageArn"] == stage_a, (
        f"expected new ingest configuration to reflect stageArn {stage_a}, "
        f"got {ingest['stageArn']}"
    )

    updated = client.update_ingest_configuration(arn=ingest_arn, stageArn=stage_b)[
        "ingestConfiguration"
    ]
    assert updated["stageArn"] == stage_b, (
        f"expected UpdateIngestConfiguration response to reflect stageArn {stage_b}, "
        f"got {updated['stageArn']}"
    )

    fetched = client.get_ingest_configuration(arn=ingest_arn)["ingestConfiguration"]
    assert fetched["stageArn"] == stage_b, (
        f"expected independent GetIngestConfiguration read to reflect stageArn {stage_b}, "
        f"got {fetched['stageArn']}"
    )
    assert fetched["state"] == "INACTIVE", (
        f"expected reassignment to leave the ingest configuration INACTIVE, "
        f"got {fetched['state']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
