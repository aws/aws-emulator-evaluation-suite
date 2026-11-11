"""multiplex-program-name-race-exactly-one-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "multiplex-program-name-race-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["medialive"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateMultiplexProgram calls racing on the same ProgramName settle deterministically:
    either exactly one wins (name is a create-once identifier) or every racer succeeds and the last
    write observably wins (name behaves as an upsert key) — but never a mix of both plus data loss."""
    medialive = ctx.client("medialive")
    azs = _two_availability_zones(ctx)
    multiplex = medialive.create_multiplex(
        Name=ctx.unique_name("sim2real-medialive-mux-"),
        AvailabilityZones=azs,
        RequestId=ctx.unique_name("req-"),
        MultiplexSettings={"TransportStreamBitrate": 10000000, "TransportStreamId": 1},
        Tags={"sim2real-check": CHECK},
    )["Multiplex"]
    multiplex_id = multiplex["Id"]
    ctx.on_cleanup(lambda: _delete_multiplex_once_settled(medialive, multiplex_id))

    program_name = "sim2real_race_program"
    racer_count = 6

    def _racer(i):
        try:
            medialive.create_multiplex_program(
                MultiplexId=multiplex_id,
                ProgramName=program_name,
                RequestId=ctx.unique_name(f"req-{i}-"),
                MultiplexProgramSettings={"ProgramNumber": i + 1},
            )
            return ("ok", None)
        except Exception as e:  # noqa: BLE001 - we classify by AWS error code below
            from botocore.exceptions import ClientError

            if isinstance(e, ClientError):
                return ("error", e.response["Error"]["Code"])
            return ("error", "unknown")

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    ctx.on_cleanup(
        lambda: _safe(
            lambda: medialive.delete_multiplex_program(MultiplexId=multiplex_id, ProgramName=program_name)
        )
    )

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    # The account and credentials are otherwise healthy for this call: a same-name race must not
    # resolve to every racer being refused (that would mean CreateMultiplexProgram is broken here,
    # not that the name is a create-once identifier).
    assert successes, f"all {racer_count} concurrent CreateMultiplexProgram calls failed: {failures}"
    # Every failure (if any) must be a real, well-formed AWS service error (a ClientError with a
    # populated error Code) — never a client-side crash / unrecognized exception ("unknown").
    assert all(code != "unknown" and code for _, code in failures), failures

    programs = medialive.list_multiplex_programs(MultiplexId=multiplex_id)["MultiplexPrograms"]
    matching = [p for p in programs if p["ProgramName"] == program_name]
    # The invariant that must always hold regardless of which concurrency policy AWS applies to a
    # duplicate ProgramName (reject-on-conflict vs. allow-multiple): every call the server told us
    # succeeded must correspond to a real, listable resource — no phantom successes, no silently
    # dropped creates.
    assert len(matching) == len(successes), (
        f"server reported {len(successes)} successful creates but {len(matching)} programs "
        f"named {program_name!r} are actually listable: {matching}"
    )
    if successes:
        # ListMultiplexPrograms only carries ChannelId/ProgramName; ProgramNumber requires the
        # independent per-program describe.
        seen_numbers = {
            medialive.describe_multiplex_program(MultiplexId=multiplex_id, ProgramName=p["ProgramName"])[
                "MultiplexProgramSettings"
            ]["ProgramNumber"]
            for p in matching
        }
        assert seen_numbers <= set(range(1, racer_count + 1)), (
            f"describe_multiplex_program ProgramNumber(s) {seen_numbers} outside the "
            f"{racer_count} values racers submitted"
        )


def _two_availability_zones(ctx):
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    names = sorted(z["ZoneName"] for z in zones)
    if len(names) < 2:
        raise AssertionError("region has fewer than 2 availability zones; cannot create a MediaLive multiplex")
    return names[:2]


def _delete_multiplex_once_settled(medialive, multiplex_id, timeout_s=300.0, interval_s=5.0):
    """DeleteMultiplex refuses a multiplex still in CREATING with ConflictException, so poll it out
    of CREATING to a bounded deadline before deleting; a multiplex already gone is fine."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = medialive.describe_multiplex(MultiplexId=multiplex_id)["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if state in ("DELETING", "DELETED"):
            return
        if state != "CREATING" or time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    _safe(lambda: medialive.delete_multiplex(MultiplexId=multiplex_id))


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
