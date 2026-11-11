"""associate-faces-unknown-face-id-partial-failure."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "associate-faces-unknown-face-id-partial-failure"
GROUP = "data-plane"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateFaces reports a FaceId that was never indexed as an UnsuccessfulFaceAssociation with
    reason FACE_NOT_FOUND, not a top-level error, and the destination confirms no association took."""
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-assocfail-")
    rek.create_collection(CollectionId=collection_id, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: rek.delete_collection(CollectionId=collection_id))

    user_id = ctx.unique_name("sim2real-user-")
    rek.create_user(CollectionId=collection_id, UserId=user_id)

    bogus_face_id = str(uuid.uuid4())
    result = rek.associate_faces(CollectionId=collection_id, UserId=user_id, FaceIds=[bogus_face_id])

    assert result["AssociatedFaces"] == [], f"expected no faces associated, got {result['AssociatedFaces']}"
    unsuccessful = {f["FaceId"]: f for f in result["UnsuccessfulFaceAssociations"]}
    assert set(unsuccessful) == {bogus_face_id}, (
        f"expected only {bogus_face_id} to be unsuccessful, got {set(unsuccessful)}"
    )
    reasons = unsuccessful[bogus_face_id]["Reasons"]
    assert reasons == ["FACE_NOT_FOUND"], f"expected reason FACE_NOT_FOUND, got {reasons}"
    assert result["UserStatus"] in ("ACTIVE", "CREATED"), f"unexpected UserStatus {result['UserStatus']!r}"

    faces_for_user = rek.list_faces(CollectionId=collection_id, UserId=user_id)["Faces"]
    assert faces_for_user == [], (
        f"independent read at the destination: expected no faces associated with {user_id}, got {faces_for_user}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
