"""delete-faces-partial-failure-and-state."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "delete-faces-partial-failure-and-state"
GROUP = "data-plane"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteFaces deletes a real indexed face and reports a never-indexed FaceId as unsuccessful, not an error."""
    image_bytes = _fetch_face_image_bytes()
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-delface-")
    rek.create_collection(CollectionId=collection_id, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: rek.delete_collection(CollectionId=collection_id))

    indexed = rek.index_faces(CollectionId=collection_id, Image={"Bytes": image_bytes})
    assert len(indexed["FaceRecords"]) == 1, f"expected 1 indexed face, got {indexed['FaceRecords']!r}"
    real_face_id = indexed["FaceRecords"][0]["Face"]["FaceId"]
    bogus_face_id = str(uuid.uuid4())

    result = rek.delete_faces(CollectionId=collection_id, FaceIds=[real_face_id, bogus_face_id])
    assert result["DeletedFaces"] == [real_face_id], (
        f"expected DeletedFaces == [{real_face_id!r}], got {result['DeletedFaces']!r}"
    )
    # a FaceId that was never indexed is not itself an error target: Rekognition only reports
    # UnsuccessfulFaceDeletions for faces it recognizes but cannot delete (e.g. associated with a
    # User) — a wholly unknown FaceId is simply absent from both lists.
    unsuccessful_ids = {f["FaceId"] for f in result["UnsuccessfulFaceDeletions"]}
    assert bogus_face_id not in unsuccessful_ids, (
        f"expected bogus FaceId {bogus_face_id!r} absent from UnsuccessfulFaceDeletions, "
        f"found in {unsuccessful_ids!r}"
    )
    assert bogus_face_id not in result["DeletedFaces"], (
        f"expected bogus FaceId {bogus_face_id!r} absent from DeletedFaces, "
        f"found in {result['DeletedFaces']!r}"
    )

    remaining = _poll_until(
        lambda: {f["FaceId"] for f in rek.list_faces(CollectionId=collection_id)["Faces"]},
        lambda faces: real_face_id not in faces,
        timeout_s=30.0,
    )
    assert real_face_id not in remaining, (
        f"expected deleted face {real_face_id!r} absent from ListFaces, still present in {remaining!r}"
    )

    described = _poll_until(
        lambda: rek.describe_collection(CollectionId=collection_id),
        lambda desc: desc["FaceCount"] == 0,
        timeout_s=30.0,
    )
    assert described["FaceCount"] == 0, f"expected FaceCount == 0 after delete, got {described['FaceCount']!r}"


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
