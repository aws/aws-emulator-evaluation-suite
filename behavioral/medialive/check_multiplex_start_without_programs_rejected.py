"""multiplex-start-without-programs-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "multiplex-start-without-programs-rejected"
GROUP = "overly-permissive"
SERVICES = ["medialive"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartMultiplex on an IDLE multiplex with zero programs runs it (RUNNING, ProgramCount 0), and
    DeleteMultiplex while RUNNING fails ConflictException with the exact message; stopped to IDLE, the delete
    drops it from ListMultiplexes, and StartMultiplex while DELETING fails ConflictException."""
    medialive = ctx.client("medialive")
    azs = _two_availability_zones(ctx)
    multiplex = medialive.create_multiplex(
        Name=ctx.unique_name("sim2real-medialive-mux-"),
        AvailabilityZones=azs,
        RequestId=ctx.unique_name("req-"),
        MultiplexSettings={"TransportStreamBitrate": 10000000, "TransportStreamId": 1},
        Tags={"sim2real-env": "test", "sim2real-owner": "behavioral"},
    )["Multiplex"]
    multiplex_id = multiplex["Id"]
    ctx.on_cleanup(lambda: _cleanup_multiplex(medialive, multiplex_id))

    # Positive control: creation itself succeeds and settles into IDLE (proves the account and
    # credentials are healthy for this service before the assertions below).
    created_state = _wait_for_multiplex_state(ctx, multiplex_id, {"IDLE", "CREATE_FAILED"}, timeout_s=300.0)
    assert created_state == "IDLE", f"expected multiplex to settle into IDLE after creation, got {created_state}"

    # AWS accepts StartMultiplex with zero programs; the rejections this check asserts are
    # DeleteMultiplex while RUNNING and StartMultiplex while DELETING.
    medialive.start_multiplex(MultiplexId=multiplex_id)
    running_state = _wait_for_multiplex_state(ctx, multiplex_id, {"RUNNING", "CREATE_FAILED"}, timeout_s=300.0)
    assert running_state == "RUNNING", f"multiplex entered {running_state} instead of RUNNING with zero programs"
    described = medialive.describe_multiplex(MultiplexId=multiplex_id)
    assert described["ProgramCount"] == 0, f"expected ProgramCount 0 while running empty, got {described['ProgramCount']}"
    assert described["PipelinesRunningCount"] >= 1, "expected at least one pipeline running with zero programs"

    # The negative: DeleteMultiplex while RUNNING is rejected.
    code, message = _client_error(
        lambda: medialive.delete_multiplex(MultiplexId=multiplex_id), "DeleteMultiplex while RUNNING"
    )
    assert code == "ConflictException", f"expected ConflictException deleting a running multiplex, got {code}"
    assert message == "Cannot delete a multiplex that is in RUNNING state", message
    # Effect absent: the multiplex is still there, still running.
    still_running = medialive.describe_multiplex(MultiplexId=multiplex_id)
    assert still_running["State"] == "RUNNING", f"expected still RUNNING after rejected delete, got {still_running['State']}"

    # Restore: stopping first makes the identical delete call succeed.
    medialive.stop_multiplex(MultiplexId=multiplex_id)
    idle_state = _wait_for_multiplex_state(ctx, multiplex_id, {"IDLE"}, timeout_s=300.0)
    assert idle_state == "IDLE", f"expected IDLE after stop, got {idle_state}"
    medialive.delete_multiplex(MultiplexId=multiplex_id)

    # Gone from the list immediately (the reliable independent read for existence), and
    # unusable while it settles -- DescribeMultiplex still reports it DELETING for a while, and a
    # mutation against that DELETING id is rejected with ConflictException, not NotFoundException.
    listed_ids = _wait_for_absent_from_list(ctx, multiplex_id, timeout_s=60.0)
    assert multiplex_id not in listed_ids, f"expected {multiplex_id} to disappear from ListMultiplexes"
    start_code, start_message = _client_error(
        lambda: medialive.start_multiplex(MultiplexId=multiplex_id), "StartMultiplex on a deleting multiplex"
    )
    assert start_code == "ConflictException", f"expected ConflictException starting a deleting multiplex, got {start_code}"
    assert start_message == f"Multiplex {multiplex_id} cannot be started while in DELETING state", start_message


def _client_error(fn, description):
    """Call fn() and return its (code, message). An unexpected success raises, so an emulator
    accepting what AWS refuses fails loudly rather than reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to be rejected, but it succeeded: {result!r}")


def _wait_for_absent_from_list(ctx, multiplex_id, timeout_s=60.0, interval_s=5.0):
    medialive = ctx.client("medialive")
    deadline = time.monotonic() + timeout_s
    ids = None
    while time.monotonic() < deadline:
        ids = [m["Id"] for m in medialive.list_multiplexes().get("Multiplexes", [])]
        if multiplex_id not in ids:
            return ids
        time.sleep(interval_s)
    raise AssertionError(f"multiplex {multiplex_id} never left ListMultiplexes, last list={ids}")


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


def _cleanup_multiplex(medialive, multiplex_id):
    """Best-effort: stop before delete, since DeleteMultiplex rejects anything but IDLE and the
    body normally already deletes it itself -- this only matters if an assertion fails mid-run."""
    _safe(lambda: medialive.stop_multiplex(MultiplexId=multiplex_id))
    _safe(lambda: medialive.delete_multiplex(MultiplexId=multiplex_id))


def _safe(fn):
    try:
        fn()
    except Exception:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
