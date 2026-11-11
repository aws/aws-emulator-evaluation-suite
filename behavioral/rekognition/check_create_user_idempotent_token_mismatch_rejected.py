"""create-user-idempotent-token-mismatch-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-user-idempotent-token-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["rekognition"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientRequestToken with a different UserId is rejected; reusing it with the same UserId is idempotent."""
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-idem-")
    rek.create_collection(CollectionId=collection_id, Tags={"sim2real": "behavioral"})
    ctx.on_cleanup(lambda: rek.delete_collection(CollectionId=collection_id))

    token = ctx.unique_name("tok-")
    user_a = ctx.unique_name("sim2real-user-a-")
    user_b = ctx.unique_name("sim2real-user-b-")

    # positive control: the token is fresh, so this creation must succeed
    rek.create_user(CollectionId=collection_id, UserId=user_a, ClientRequestToken=token)

    code, message = _error(
        lambda: rek.create_user(CollectionId=collection_id, UserId=user_b, ClientRequestToken=token)
    )
    assert code == "IdempotentParameterMismatchException", (
        f"reusing ClientRequestToken with a different UserId: expected "
        f"IdempotentParameterMismatchException, got {code!r}"
    )
    # AWS pairs this code with a generic text rather than a mismatch description
    expected_message = "Service Unavailable"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: user_b was never created
    user_ids = {u["UserId"] for u in rek.list_users(CollectionId=collection_id)["Users"]}
    assert user_a in user_ids, f"expected {user_a!r} in {user_ids!r}"
    assert user_b not in user_ids, f"expected {user_b!r} absent from {user_ids!r}"

    # restore: the identical call (same UserId, same token) is an idempotent no-op success
    rek.create_user(CollectionId=collection_id, UserId=user_a, ClientRequestToken=token)
    user_ids_after = {u["UserId"] for u in rek.list_users(CollectionId=collection_id)["Users"]}
    assert user_ids_after == {user_a}, f"expected only {{{user_a!r}}}, got {user_ids_after!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
