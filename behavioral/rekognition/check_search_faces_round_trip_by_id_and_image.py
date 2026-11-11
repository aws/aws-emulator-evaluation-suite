"""search-faces-round-trip-by-id-and-image."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-faces-round-trip-by-id-and-image"
GROUP = "data-plane"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Indexing the same real face twice yields two FaceIds that SearchFaces/SearchFacesByImage match to each other."""
    image_bytes = _fetch_face_image_bytes()
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-search-")
    rek.create_collection(CollectionId=collection_id, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: rek.delete_collection(CollectionId=collection_id))

    # CreateCollection is not synchronously consistent in every account/region: an IndexFaces
    # issued immediately afterward can observe ResourceNotFoundException for a few seconds. Bounded
    # retry, not a sleep before the call, because the inconsistency window is real and variable.
    first = _index_faces_retrying(rek, collection_id, image_bytes, "copy-one")
    second = _index_faces_retrying(rek, collection_id, image_bytes, "copy-two")
    assert len(first["FaceRecords"]) == 1, f"expected exactly 1 face indexed from copy-one, got {len(first['FaceRecords'])}"
    assert len(second["FaceRecords"]) == 1, f"expected exactly 1 face indexed from copy-two, got {len(second['FaceRecords'])}"
    face_id_1 = first["FaceRecords"][0]["Face"]["FaceId"]
    face_id_2 = second["FaceRecords"][0]["Face"]["FaceId"]
    assert face_id_1 != face_id_2, f"two separate IndexFaces calls minted the same FaceId {face_id_1}"

    # A freshly indexed face is not immediately searchable: SearchFaces/SearchFacesByImage can miss
    # a match that IndexFaces just created for several seconds. Poll for the expected match rather
    # than trusting the first read — the absence bar requires a bounded retry here, not a one-shot
    # call, since the index lag is a real and repeatable property of this account/region.
    by_id, matched_ids = _search_faces_until(rek, lambda: rek.search_faces(
        CollectionId=collection_id, FaceId=face_id_1, FaceMatchThreshold=80
    ), face_id_2)
    assert by_id["SearchedFaceId"] == face_id_1, (
        f"SearchFaces echoed SearchedFaceId={by_id['SearchedFaceId']!r}, expected the queried {face_id_1!r}"
    )
    assert face_id_2 in matched_ids, (
        f"SearchFaces by FaceId={face_id_1} did not match the identical second copy {face_id_2}; "
        f"matched {matched_ids}"
    )

    by_image, matched_ids_by_image = _search_faces_until(
        rek,
        lambda: rek.search_faces_by_image(
            CollectionId=collection_id, Image={"Bytes": image_bytes}, FaceMatchThreshold=80
        ),
        face_id_1,
        face_id_2,
    )
    assert {face_id_1, face_id_2} <= matched_ids_by_image, (
        f"SearchFacesByImage on the exact indexed image should match BOTH enrolled copies "
        f"{{{face_id_1}, {face_id_2}}}; matched {matched_ids_by_image}"
    )


def _index_faces_retrying(rek, collection_id: str, image_bytes: bytes, external_image_id: str, deadline_s: float = 15.0):
    import time

    start = time.monotonic()
    while True:
        try:
            return rek.index_faces(
                CollectionId=collection_id, Image={"Bytes": image_bytes}, ExternalImageId=external_image_id
            )
        except rek.exceptions.ResourceNotFoundException:
            if time.monotonic() - start > deadline_s:
                raise
            time.sleep(1)


def _search_faces_until(rek, call, *expected_face_ids: str, deadline_s: float = 20.0):
    """Retry a SearchFaces*-shaped `call` until every id in `expected_face_ids` appears.

    Returns `(response, matched_ids)` from the last attempt regardless of outcome, so a genuine
    non-match still reaches the caller's assertion with real data instead of being swallowed here.
    """
    import time

    start = time.monotonic()
    while True:
        resp = call()
        matched = {m["Face"]["FaceId"] for m in resp["FaceMatches"]}
        if set(expected_face_ids) <= matched or time.monotonic() - start > deadline_s:
            return resp, matched
        time.sleep(1)


#: A photograph of one person's face, shipped with the check so no run fetches media. It is the
#: Metropolitan Museum of Art's "Portrait of an Old Chinese Woman" (DP155400, face detail),
#: released CC0 under the Met's Open Access policy, scaled to 320 px wide.
_FACE_IMAGE = "face.jpg"


def _fetch_face_image_bytes() -> bytes:
    from pathlib import Path

    return (Path(__file__).parent / "deployments" / _FACE_IMAGE).read_bytes()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
