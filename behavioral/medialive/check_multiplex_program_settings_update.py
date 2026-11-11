"""multiplex-program-settings-update."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "multiplex-program-settings-update"
GROUP = "state"
SERVICES = ["medialive"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMultiplexProgram persists a new program number and DescribeMultiplexProgram reflects
    it; after DeleteMultiplexProgram, that same program is gone and no longer mutable."""
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
    ctx.on_cleanup(lambda: _safe(lambda: medialive.delete_multiplex(MultiplexId=multiplex_id)))

    program = medialive.create_multiplex_program(
        MultiplexId=multiplex_id,
        ProgramName="program1",
        RequestId=ctx.unique_name("req-"),
        MultiplexProgramSettings={"ProgramNumber": 1},
    )["MultiplexProgram"]
    program_name = program["ProgramName"]
    ctx.on_cleanup(
        lambda: _safe(lambda: medialive.delete_multiplex_program(MultiplexId=multiplex_id, ProgramName=program_name))
    )
    got = program["MultiplexProgramSettings"]["ProgramNumber"]
    assert got == 1, f"expected freshly created program to report ProgramNumber 1, got {got}"

    medialive.update_multiplex_program(
        MultiplexId=multiplex_id,
        ProgramName=program_name,
        MultiplexProgramSettings={"ProgramNumber": 42},
    )
    described = medialive.describe_multiplex_program(MultiplexId=multiplex_id, ProgramName=program_name)
    got = described["MultiplexProgramSettings"]["ProgramNumber"]
    assert got == 42, f"expected DescribeMultiplexProgram to reflect the updated ProgramNumber 42, got {got}"

    medialive.delete_multiplex_program(MultiplexId=multiplex_id, ProgramName=program_name)
    code, message = _client_error(
        lambda: medialive.describe_multiplex_program(MultiplexId=multiplex_id, ProgramName=program_name),
        "DescribeMultiplexProgram on a deleted program",
    )
    assert code == "NotFoundException", f"expected NotFoundException reading deleted program, got {code}"
    assert message == f"Multiplex program {multiplex_id}/{program_name} not found", message

    code, message = _client_error(
        lambda: medialive.update_multiplex_program(
            MultiplexId=multiplex_id,
            ProgramName=program_name,
            MultiplexProgramSettings={"ProgramNumber": 7},
        ),
        "UpdateMultiplexProgram on a deleted program",
    )
    assert code == "NotFoundException", f"expected NotFoundException updating deleted program, got {code}"
    assert message == f"Multiplex program {multiplex_id}/{program_name} not found", message


def _client_error(fn, description):
    """Call fn() and return its (code, message). An unexpected success raises, so an emulator
    accepting what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to be rejected, but it succeeded: {result!r}")


def _gc_stale_medialive(ctx):
    """Free account quota by tearing down sim2real- multiplexes left over from previous
    interrupted runs, before creating new ones."""
    from botocore.exceptions import ClientError

    medialive = ctx.client("medialive")
    try:
        for mux in medialive.list_multiplexes().get("Multiplexes", []):
            name = mux.get("Name", "")
            if not name.startswith("sim2real-"):
                continue
            try:
                medialive.delete_multiplex(MultiplexId=mux["Id"])
            except ClientError:
                pass
    except ClientError:
        pass


def _two_availability_zones(ctx):
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    names = sorted(z["ZoneName"] for z in zones)
    if len(names) < 2:
        raise AssertionError("region has fewer than 2 availability zones; cannot create a MediaLive multiplex")
    return names[:2]


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
