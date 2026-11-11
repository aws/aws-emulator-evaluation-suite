"""create-user-associate-disassociate-faces-and-search-users."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-user-associate-disassociate-faces-and-search-users"
GROUP = "data-plane"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AssociateFaces/DisassociateFaces drive UserStatus and ListFaces.UserId; SearchUsersByImage finds the user."""
    image_bytes = _fetch_face_image_bytes()
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-user-")
    rek.create_collection(CollectionId=collection_id, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: rek.delete_collection(CollectionId=collection_id))
    # CreateCollection can return before the collection is visible to IndexFaces, so wait
    # until DescribeCollection succeeds.
    _poll_until(
        lambda: rek.describe_collection(CollectionId=collection_id),
        lambda _resp: True,
        timeout_s=20.0,
        retry_on=("ResourceNotFoundException",),
    )

    first = rek.index_faces(CollectionId=collection_id, Image={"Bytes": image_bytes}, ExternalImageId="copy-one")
    second = rek.index_faces(CollectionId=collection_id, Image={"Bytes": image_bytes}, ExternalImageId="copy-two")
    face_id_1 = first["FaceRecords"][0]["Face"]["FaceId"]
    face_id_2 = second["FaceRecords"][0]["Face"]["FaceId"]

    user_id = ctx.unique_name("sim2real-user-")
    rek.create_user(CollectionId=collection_id, UserId=user_id)

    associated = rek.associate_faces(CollectionId=collection_id, UserId=user_id, FaceIds=[face_id_1, face_id_2])
    got_associated = {f["FaceId"] for f in associated["AssociatedFaces"]}
    assert got_associated == {face_id_1, face_id_2}, f"expected both faces associated, got {got_associated!r}"
    assert associated["UserStatus"] in ("ACTIVE", "UPDATING", "CREATED"), (
        f"expected UserStatus in (ACTIVE, UPDATING, CREATED), got {associated['UserStatus']!r}"
    )

    active_users = _poll_until(
        lambda: rek.list_users(CollectionId=collection_id)["Users"],
        lambda users: any(u["UserId"] == user_id and u["UserStatus"] == "ACTIVE" for u in users),
        timeout_s=30.0,
    )
    assert any(u["UserId"] == user_id and u["UserStatus"] == "ACTIVE" for u in active_users), (
        f"expected user {user_id!r} ACTIVE in ListUsers, got {active_users!r}"
    )

    users_by_face_id = {
        f["FaceId"]: f.get("UserId") for f in rek.list_faces(CollectionId=collection_id)["Faces"]
    }
    assert users_by_face_id[face_id_1] == user_id, (
        f"expected face {face_id_1!r} owned by {user_id!r}, got {users_by_face_id[face_id_1]!r}"
    )
    assert users_by_face_id[face_id_2] == user_id, (
        f"expected face {face_id_2!r} owned by {user_id!r}, got {users_by_face_id[face_id_2]!r}"
    )

    found = rek.search_users_by_image(CollectionId=collection_id, Image={"Bytes": image_bytes})
    matched_user_ids = {m["User"]["UserId"] for m in found["UserMatches"]}
    assert user_id in matched_user_ids, f"expected {user_id!r} in SearchUsersByImage matches, got {matched_user_ids!r}"

    disassociated = rek.disassociate_faces(CollectionId=collection_id, UserId=user_id, FaceIds=[face_id_1])
    got_disassociated = {f["FaceId"] for f in disassociated["DisassociatedFaces"]}
    assert got_disassociated == {face_id_1}, f"expected {face_id_1!r} disassociated, got {got_disassociated!r}"
    assert disassociated["UserStatus"] in ("ACTIVE", "UPDATING", "CREATED"), (
        f"expected UserStatus in (ACTIVE, UPDATING, CREATED), got {disassociated['UserStatus']!r}"
    )

    # DisassociateFaces returning UserStatus=UPDATING means ListFaces can still show the old
    # owner for a beat afterward — poll for it to settle, the
    # same way the association side already waits for ListUsers to reach ACTIVE.
    users_by_face_id_after = _poll_until(
        lambda: {f["FaceId"]: f.get("UserId") for f in rek.list_faces(CollectionId=collection_id)["Faces"]},
        lambda mapping: mapping.get(face_id_1) is None,
        timeout_s=30.0,
    )
    assert users_by_face_id_after.get(face_id_1) is None, (
        f"expected face {face_id_1!r} to have no owner after disassociation, got "
        f"{users_by_face_id_after.get(face_id_1)!r}"
    )
    assert users_by_face_id_after[face_id_2] == user_id, (
        f"expected face {face_id_2!r} still owned by {user_id!r}, got {users_by_face_id_after[face_id_2]!r}"
    )


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0, retry_on=()):
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in retry_on:
                time.sleep(interval_s)
                continue
            raise
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

