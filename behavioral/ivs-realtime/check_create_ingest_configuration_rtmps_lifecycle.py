"""create-ingest-configuration-rtmps-lifecycle."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "create-ingest-configuration-rtmps-lifecycle"
GROUP = "ingest-configuration"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIngestConfiguration with RTMPS starts INACTIVE, assigns a participantId and a
    pattern-valid streamKey, and is retrievable/listable/deletable."""
    ivsrt = ctx.client("ivs-realtime")
    stage = ivsrt.create_stage(name=ctx.unique_name("sim2real-ivsrt-stage-"))["stage"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=stage["arn"]))

    name = ctx.unique_name("sim2real-ivsrt-ingest-")
    created = ivsrt.create_ingest_configuration(
        name=name, ingestProtocol="RTMPS", stageArn=stage["arn"]
    )["ingestConfiguration"]
    arn = created["arn"]
    state = {"deleted": False}
    ctx.on_cleanup(lambda: state["deleted"] or ivsrt.delete_ingest_configuration(arn=arn))

    assert created["state"] == "INACTIVE", created["state"]
    assert created["ingestProtocol"] == "RTMPS"
    assert created["stageArn"] == stage["arn"]
    assert created["participantId"]
    assert re.match(r"^rt_[0-9]+_[a-z0-9-]+_[a-zA-Z0-9-]+_.+$", created["streamKey"]), created[
        "streamKey"
    ]

    fetched = ivsrt.get_ingest_configuration(arn=arn)["ingestConfiguration"]
    assert fetched["state"] == "INACTIVE"
    assert fetched["stageArn"] == stage["arn"]

    inactive_arns = {
        c["arn"]
        for c in ivsrt.list_ingest_configurations(filterByState="INACTIVE")["ingestConfigurations"]
    }
    assert arn in inactive_arns

    ivsrt.delete_ingest_configuration(arn=arn)
    state["deleted"] = True

    not_found_message = f"Resource: {arn} not found"
    error = _client_error(lambda: ivsrt.get_ingest_configuration(arn=arn))
    assert error.get("Code") == "ResourceNotFoundException", error
    assert error.get("Message") == not_found_message, error

    # A mutation on the dead id must also fail, not silently resurrect or no-op it.
    redelete = _client_error(lambda: ivsrt.delete_ingest_configuration(arn=arn))
    assert redelete.get("Code") == "ResourceNotFoundException", redelete
    assert redelete.get("Message") == not_found_message, redelete


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
