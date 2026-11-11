"""delete-user-removes-user."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-user-removes-user"
GROUP = "state"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUser removes the user from ListUsers and a subsequent DeleteUser 404s."""
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-deluser-")
    rek.create_collection(CollectionId=collection_id)
    ctx.on_cleanup(lambda: rek.delete_collection(CollectionId=collection_id))

    def listed_user_ids():
        return {u["UserId"] for u in rek.list_users(CollectionId=collection_id)["Users"]}

    user_id = ctx.unique_name("sim2real-user-")
    rek.create_user(CollectionId=collection_id, UserId=user_id)
    # CreateUser is eventually consistent with ListUsers — a bare read right after create can
    # legitimately still see an empty list, so this waits for the positive control rather than
    # asserting on a single read.
    listed_after_create = _poll_until(
        listed_user_ids,
        lambda ids: user_id in ids,
        timeout_s=30.0,
        description=f"user {user_id!r} visible in ListUsers after CreateUser",
    )
    assert user_id in listed_after_create, f"expected {user_id!r} in ListUsers, got {listed_after_create!r}"

    rek.delete_user(CollectionId=collection_id, UserId=user_id)
    listed_after_delete = _poll_until(
        listed_user_ids,
        lambda ids: user_id not in ids,
        timeout_s=30.0,
        description=f"user {user_id!r} absent from ListUsers after DeleteUser",
    )
    assert user_id not in listed_after_delete, (
        f"expected {user_id!r} absent from ListUsers after DeleteUser, got {listed_after_delete!r}"
    )

    # the dead id itself must also reject a further mutation.
    redelete_code, redelete_message = _client_error(lambda: rek.delete_user(CollectionId=collection_id, UserId=user_id))
    assert redelete_code == "InvalidParameterException", (
        f"expected InvalidParameterException re-deleting the already-deleted {user_id!r}, "
        f"got {redelete_code!r}"
    )
    assert redelete_message == "Request has invalid parameters", (
        f"expected the invalid-parameters message re-deleting {user_id!r}, got {redelete_message!r}"
    )

    # a UserId that was never created in this collection is rejected the same way — empirically
    # Rekognition returns InvalidParameterException (not ResourceNotFoundException) for a
    # syntactically valid but unknown UserId on DeleteUser, whether it never existed or was deleted.
    never_created_user_id = ctx.unique_name("sim2real-user-neverexisted-")
    code, message = _client_error(lambda: rek.delete_user(CollectionId=collection_id, UserId=never_created_user_id))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException deleting never-created {never_created_user_id!r}, got {code!r}"
    )
    assert message == "Request has invalid parameters", (
        f"expected the invalid-parameters message deleting never-created {never_created_user_id!r}, got {message!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0, description="condition"):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


def _client_error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
