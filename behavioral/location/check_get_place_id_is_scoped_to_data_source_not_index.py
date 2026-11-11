"""get-place-id-is-scoped-to-data-source-not-index."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-place-id-is-scoped-to-data-source-not-index"
GROUP = 'places'
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A PlaceId minted by one Here-backed index resolves through GetPlace on any
    other Here-backed index, but is rejected as malformed by an Esri-backed one:
    the id is scoped to its data source provider, not to the index resource.

    Reference: https://docs.aws.amazon.com/location/previous/APIReference/API_GetPlace.html
    """
    loc = ctx.client("location")
    origin_index = ctx.unique_name("sim2real-behav-location-index-origin-")
    same_provider_index = ctx.unique_name("sim2real-behav-location-index-same-")
    other_provider_index = ctx.unique_name("sim2real-behav-location-index-other-")

    loc.create_place_index(IndexName=origin_index, DataSource="Here")
    ctx.on_cleanup(_teardown(lambda: loc.delete_place_index(IndexName=origin_index),
                              "ResourceNotFoundException"))
    loc.create_place_index(IndexName=same_provider_index, DataSource="Here")
    ctx.on_cleanup(_teardown(lambda: loc.delete_place_index(IndexName=same_provider_index),
                              "ResourceNotFoundException"))
    loc.create_place_index(IndexName=other_provider_index, DataSource="Esri")
    ctx.on_cleanup(_teardown(lambda: loc.delete_place_index(IndexName=other_provider_index),
                              "ResourceNotFoundException"))

    search = loc.search_place_index_for_text(IndexName=origin_index, Text="Seattle, WA")
    place_id = search["Results"][0]["PlaceId"]

    resolved = loc.get_place(IndexName=origin_index, PlaceId=place_id)
    assert resolved["Place"]["Label"], "expected GetPlace on the originating index to return a label"

    same_provider = loc.get_place(IndexName=same_provider_index, PlaceId=place_id)
    assert same_provider["Place"]["Label"] == resolved["Place"]["Label"], (
        f"expected the same label from a sibling Here-backed index, got "
        f"{same_provider['Place']['Label']!r} vs {resolved['Place']['Label']!r}"
    )

    try:
        loc.get_place(IndexName=other_provider_index, PlaceId=place_id)
        raise AssertionError("expected GetPlace on an Esri-backed index to reject a Here place id")
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
        assert err["Message"] == "'PlaceId' must be a valid ID.", f"unexpected message {err['Message']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
