"""list-faces-empty-collection-returns-model-version."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-faces-empty-collection-returns-model-version"
GROUP = "state"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFaces on a freshly created, empty collection returns an empty Faces list but a real FaceModelVersion."""
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-emptylist-")
    created = rek.create_collection(CollectionId=collection_id)
    ctx.on_cleanup(lambda: rek.delete_collection(CollectionId=collection_id))

    listed = rek.list_faces(CollectionId=collection_id)
    assert listed["Faces"] == [], listed["Faces"]
    assert listed["FaceModelVersion"] == created["FaceModelVersion"], (
        listed["FaceModelVersion"] + "|" + created["FaceModelVersion"]
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
