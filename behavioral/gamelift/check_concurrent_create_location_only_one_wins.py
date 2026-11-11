"""concurrent-create-location-only-one-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-location-only-one-wins"
GROUP = "concurrency"
SERVICES = ["gamelift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Eight concurrent CreateLocation calls for the same custom location name yield exactly one success and
    seven ConflictExceptions, and ListLocations holds that name once.
    """
    gl = ctx.client("gamelift")
    loc_name = ctx.unique_name("custom-sim2real-race-")
    ctx.on_cleanup(lambda: _safe_delete_location(gl, loc_name))

    racers = 8

    def attempt(_i):
        try:
            gl.create_location(LocationName=loc_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
            return "ok"
        except Exception as exc:  # noqa: BLE001 -- classify below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return exc.response["Error"]["Code"]
            raise

    with ThreadPoolExecutor(max_workers=racers) as pool:
        results = list(pool.map(attempt, range(racers)))

    successes = [r for r in results if r == "ok"]
    conflicts = [r for r in results if r == "ConflictException"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {results}"
    assert len(conflicts) == racers - 1, f"expected {racers - 1} conflicts, got {results}"

    # The location genuinely exists exactly once.
    names = [loc["LocationName"] for loc in gl.list_locations()["Locations"]]
    assert names.count(loc_name) == 1, (
        f"expected {loc_name!r} to appear exactly once in ListLocations, got count "
        f"{names.count(loc_name)} in {names!r}"
    )


def _safe_delete_location(gl, loc_name):
    from botocore.exceptions import ClientError

    try:
        gl.delete_location(LocationName=loc_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
