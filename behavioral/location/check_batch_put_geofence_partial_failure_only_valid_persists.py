"""batch-put-geofence-partial-failure-only-valid-persists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-put-geofence-partial-failure-only-valid-persists"
GROUP = 'geofencing'
SERVICES = ['location']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _error_code(fn) -> str:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A batch geofence put with one badly-wound polygon reports that entry's error
    and still creates every other valid geofence in the same batch.

    Reference: https://docs.aws.amazon.com/location/previous/APIReference/API_BatchPutGeofence.html
    """
    loc = ctx.client("location")
    collection = ctx.unique_name("sim2real-behav-location-collection-")
    loc.create_geofence_collection(CollectionName=collection)
    ctx.on_cleanup(_teardown(lambda: loc.delete_geofence_collection(CollectionName=collection),
                              "ResourceNotFoundException"))

    good_poly = [[[-122.34, 47.60], [-122.33, 47.60], [-122.33, 47.61], [-122.34, 47.61], [-122.34, 47.60]]]
    bad_poly = [[[-122.34, 47.60], [-122.34, 47.61], [-122.33, 47.61], [-122.33, 47.60], [-122.34, 47.60]]]

    result = loc.batch_put_geofence(CollectionName=collection, Entries=[
        {"GeofenceId": "good1", "Geometry": {"Polygon": good_poly}},
        {"GeofenceId": "bad1", "Geometry": {"Polygon": bad_poly}},
    ])

    errors = result["Errors"]
    assert len(errors) == 1, f"expected exactly 1 batch error, got {len(errors)}: {errors!r}"
    assert errors[0]["GeofenceId"] == "bad1", f"the error named {errors[0]['GeofenceId']!r}, expected 'bad1'"
    assert errors[0]["Error"]["Code"] == "ValidationError", (
        f"expected ValidationError, got {errors[0]['Error']['Code']!r}"
    )
    assert errors[0]["Error"]["Message"] == "'Geometry.Polygon[0]' must be oriented counter-clockwise.", (
        f"unexpected error message {errors[0]['Error']['Message']!r}"
    )

    successes = result["Successes"]
    assert [s["GeofenceId"] for s in successes] == ["good1"], (
        f"expected only 'good1' to succeed, got {successes!r}"
    )

    good = loc.get_geofence(CollectionName=collection, GeofenceId="good1")
    assert good["Status"] == "ACTIVE", f"the valid geofence's status was {good['Status']!r}, expected ACTIVE"

    code = _error_code(lambda: loc.get_geofence(CollectionName=collection, GeofenceId="bad1"))
    assert code == "ResourceNotFoundException", (
        f"expected the rejected geofence to have never been stored, got code {code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
