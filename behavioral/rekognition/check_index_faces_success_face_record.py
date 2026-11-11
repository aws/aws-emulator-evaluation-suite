"""index-faces-success-face-record."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "index-faces-success-face-record"
GROUP = "data-plane"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """IndexFaces on an image containing a real face stores exactly one face and DescribeCollection's FaceCount reflects it."""
    image_bytes = _fetch_face_image_bytes()
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-idx-")
    rek.create_collection(CollectionId=collection_id, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: rek.delete_collection(CollectionId=collection_id))

    result = rek.index_faces(CollectionId=collection_id, Image={"Bytes": image_bytes})
    assert len(result["FaceRecords"]) == 1, f"expected exactly 1 FaceRecord, got {len(result['FaceRecords'])}: {result['FaceRecords']}"
    face = result["FaceRecords"][0]["Face"]
    assert face["Confidence"] > 50, f"expected face Confidence > 50, got {face['Confidence']}"

    described = _poll_until(
        lambda: rek.describe_collection(CollectionId=collection_id),
        lambda desc: desc["FaceCount"] == 1,
        timeout_s=30.0,
    )
    assert described["FaceCount"] == 1, f"expected DescribeCollection FaceCount == 1, got {described['FaceCount']}"
    assert described["FaceModelVersion"] == result["FaceModelVersion"], (
        f"expected DescribeCollection FaceModelVersion to match IndexFaces' own "
        f"{result['FaceModelVersion']!r}, got {described['FaceModelVersion']!r}"
    )


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
