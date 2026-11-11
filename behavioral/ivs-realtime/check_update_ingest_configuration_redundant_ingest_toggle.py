"""update-ingest-configuration-redundant-ingest-toggle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-ingest-configuration-redundant-ingest-toggle"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIngestConfiguration's RedundantIngest flag actually flips the stored value
    (and only appears/disappears where documented): off by default, RedundantIngest=True
    persists via GetIngestConfiguration, and flipping back to False persists too."""
    client = ctx.client("ivs-realtime")
    stage_arn = client.create_stage(
        name=ctx.unique_name("sim2real-stage"), tags={"sim2real": CHECK}
    )["stage"]["arn"]
    ctx.on_cleanup(lambda: client.delete_stage(arn=stage_arn))

    ingest = client.create_ingest_configuration(
        name=ctx.unique_name("sim2real-ingest"),
        stageArn=stage_arn,
        ingestProtocol="RTMPS",
        tags={"sim2real": CHECK},
    )["ingestConfiguration"]
    ingest_arn = ingest["arn"]
    ctx.on_cleanup(lambda: client.delete_ingest_configuration(arn=ingest_arn, force=True))
    assert ingest["redundantIngest"] is False, (
        f"expected redundantIngest False on creation, got {ingest['redundantIngest']}"
    )

    enabled = client.update_ingest_configuration(arn=ingest_arn, redundantIngest=True)[
        "ingestConfiguration"
    ]
    assert enabled["redundantIngest"] is True, (
        f"expected redundantIngest True in UpdateIngestConfiguration response, "
        f"got {enabled['redundantIngest']}"
    )

    fetched_enabled = client.get_ingest_configuration(arn=ingest_arn)["ingestConfiguration"]
    assert fetched_enabled["redundantIngest"] is True, (
        f"expected redundantIngest True to persist via an independent GetIngestConfiguration, "
        f"got {fetched_enabled['redundantIngest']}"
    )

    disabled = client.update_ingest_configuration(arn=ingest_arn, redundantIngest=False)[
        "ingestConfiguration"
    ]
    assert disabled["redundantIngest"] is False, (
        f"expected redundantIngest False in UpdateIngestConfiguration response after flipping "
        f"back, got {disabled['redundantIngest']}"
    )

    fetched_disabled = client.get_ingest_configuration(arn=ingest_arn)["ingestConfiguration"]
    assert fetched_disabled["redundantIngest"] is False, (
        f"expected redundantIngest False to persist via an independent GetIngestConfiguration, "
        f"got {fetched_disabled['redundantIngest']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
