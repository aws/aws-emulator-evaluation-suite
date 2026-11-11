"""custom-location-create-and-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-location-create-and-list"
GROUP = "state"
SERVICES = ["gamelift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLocation makes a custom location immediately visible in ListLocations;
    DeleteLocation removes it again, a second DeleteLocation on the same name now
    fails with NotFoundException, and the freed name can be recreated."""
    gl = ctx.client("gamelift")
    loc_name = ctx.unique_name("custom-sim2real-loc-")

    created = gl.create_location(
        LocationName=loc_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Location"]
    ctx.on_cleanup(lambda: _safe_delete_location(gl, loc_name))
    assert created["LocationName"] == loc_name, (
        f"expected CreateLocation to echo LocationName {loc_name!r}, got {created['LocationName']!r}"
    )

    names = [loc["LocationName"] for loc in gl.list_locations()["Locations"]]
    assert loc_name in names, f"expected {loc_name!r} in ListLocations, got {names!r}"

    gl.delete_location(LocationName=loc_name)

    names_after = [loc["LocationName"] for loc in gl.list_locations()["Locations"]]
    assert loc_name not in names_after, (
        f"expected {loc_name!r} removed from ListLocations, still present: {names_after!r}"
    )

    code, message = _error(lambda: gl.delete_location(LocationName=loc_name))
    assert code == "NotFoundException", (
        "expected a second DeleteLocation on the already-deleted name to raise "
        f"NotFoundException, got {code!r}"
    )
    expected_message = f"Location ({loc_name}) not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The freed name is reusable, not permanently retired.
    recreated = gl.create_location(
        LocationName=loc_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Location"]
    assert recreated["LocationName"] == loc_name, (
        f"expected the freed name {loc_name!r} to be recreatable, got {recreated['LocationName']!r}"
    )
    names_recreated = [loc["LocationName"] for loc in gl.list_locations()["Locations"]]
    assert loc_name in names_recreated, (
        f"expected recreated {loc_name!r} in ListLocations, got {names_recreated!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


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
