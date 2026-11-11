"""multiplex-start-stop-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "multiplex-start-stop-lifecycle"
GROUP = "state"
SERVICES = ["medialive"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartMultiplex/StopMultiplex drive a real IDLE->STARTING->RUNNING->STOPPING->IDLE cycle."""
    medialive = ctx.client("medialive")
    azs = _two_availability_zones(ctx)
    multiplex = medialive.create_multiplex(
        Name=ctx.unique_name("sim2real-medialive-mux-"),
        AvailabilityZones=azs,
        RequestId=ctx.unique_name("req-"),
        MultiplexSettings={"TransportStreamBitrate": 10000000, "TransportStreamId": 1},
        Tags={"sim2real-env": "test", "sim2real-owner": "medialive-suite"},
    )["Multiplex"]
    multiplex_id = multiplex["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: medialive.delete_multiplex(MultiplexId=multiplex_id)))
    create_state = _wait_for_multiplex_state(ctx, multiplex_id, {"IDLE", "CREATE_FAILED"}, timeout_s=300.0)
    assert create_state == "IDLE", f"multiplex {multiplex_id} entered {create_state!r} instead of IDLE after creation"

    program = medialive.create_multiplex_program(
        MultiplexId=multiplex_id,
        ProgramName="program1",
        RequestId=ctx.unique_name("req-"),
        MultiplexProgramSettings={"ProgramNumber": 1},
    )["MultiplexProgram"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: medialive.delete_multiplex_program(MultiplexId=multiplex_id, ProgramName=program["ProgramName"])
        )
    )

    medialive.start_multiplex(MultiplexId=multiplex_id)
    running_state = _wait_for_multiplex_state(ctx, multiplex_id, {"RUNNING", "CREATE_FAILED"}, timeout_s=300.0)
    assert running_state == "RUNNING", f"multiplex entered {running_state} instead of RUNNING"
    described = medialive.describe_multiplex(MultiplexId=multiplex_id)
    assert described["PipelinesRunningCount"] >= 1, (
        f"running multiplex {multiplex_id} reported PipelinesRunningCount={described['PipelinesRunningCount']}"
    )

    medialive.stop_multiplex(MultiplexId=multiplex_id)
    idle_state = _wait_for_multiplex_state(ctx, multiplex_id, {"IDLE"}, timeout_s=300.0)
    assert idle_state == "IDLE", f"multiplex {multiplex_id} settled in {idle_state!r} instead of IDLE after stop"


def _two_availability_zones(ctx):
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    names = sorted(z["ZoneName"] for z in zones)
    if len(names) < 2:
        raise AssertionError("region has fewer than 2 availability zones; cannot create a MediaLive multiplex")
    return names[:2]


def _wait_for_multiplex_state(ctx, multiplex_id, target_states, timeout_s=300.0, interval_s=10.0):
    medialive = ctx.client("medialive")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = medialive.describe_multiplex(MultiplexId=multiplex_id)["State"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"multiplex {multiplex_id} never reached {target_states}, last state={last}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
