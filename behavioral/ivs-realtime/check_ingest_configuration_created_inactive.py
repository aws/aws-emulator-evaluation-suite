"""ingest-configuration-created-inactive."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ingest-configuration-created-inactive"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A brand-new IngestConfiguration starts INACTIVE (no publisher has ever connected)."""
    ivs = ctx.client("ivs-realtime")
    tag_set = {"sim2real": "true"}
    stage_arn = ivs.create_stage(
        name=ctx.unique_name("sim2real-stage-"), tags=tag_set
    )["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage_arn))

    created = ivs.create_ingest_configuration(
        name=ctx.unique_name("sim2real-ingest-"),
        stageArn=stage_arn,
        ingestProtocol="RTMPS",
        tags=tag_set,
    )["ingestConfiguration"]
    arn = created["arn"]
    state = {"deleted": False}
    ctx.on_cleanup(lambda: state["deleted"] or ivs.delete_ingest_configuration(arn=arn))

    assert created["state"] == "INACTIVE", created["state"]
    assert created["stageArn"] == stage_arn, (created["stageArn"], stage_arn)

    fetched = ivs.get_ingest_configuration(arn=arn)["ingestConfiguration"]
    assert fetched["state"] == "INACTIVE", fetched["state"]

    # filterByState=ACTIVE must exclude it; filterByState=INACTIVE must include it.
    active = ivs.list_ingest_configurations(filterByState="ACTIVE")["ingestConfigurations"]
    assert arn not in [c["arn"] for c in active], (arn, [c["arn"] for c in active])
    inactive = ivs.list_ingest_configurations(filterByState="INACTIVE")["ingestConfigurations"]
    assert arn in [c["arn"] for c in inactive], (arn, [c["arn"] for c in inactive])

    ivs.delete_ingest_configuration(arn=arn)
    state["deleted"] = True
    code, message = _error(lambda: ivs.get_ingest_configuration(arn=arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"Resource: {arn} not found", message


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected ResourceNotFoundException, call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
