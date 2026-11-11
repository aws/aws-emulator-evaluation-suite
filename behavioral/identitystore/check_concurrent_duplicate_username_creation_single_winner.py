"""concurrent-duplicate-username-creation-single-winner."""
from __future__ import annotations

import threading

from behavioral_harness import tags

CHECK = "concurrent-duplicate-username-creation-single-winner"
GROUP = "concurrency"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Racing CreateUser with an identical UserName yields exactly one surviving user."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-behav-race-user-")

    n_racers = 6
    successes = []
    errors = []
    lock = threading.Lock()
    barrier = threading.Barrier(n_racers)

    def racer():
        barrier.wait()
        try:
            resp = idstore.create_user(
                IdentityStoreId=store_id,
                UserName=username,
                DisplayName=username,
                Name={"GivenName": "Race", "FamilyName": "Username"},
            )

            with lock:
                successes.append(resp["UserId"])
        except ClientError as exc:
            with lock:
                errors.append((exc.response["Error"]["Code"], exc.response["Error"].get("Message")))
        except Exception as exc:  # noqa: BLE001 - classify below
            with lock:
                errors.append((f"non-ClientError:{type(exc).__name__}", str(exc)))

    threads = [threading.Thread(target=racer) for _ in range(n_racers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {successes}"
    assert len(errors) == n_racers - 1, f"expected {n_racers - 1} losers, got {len(errors)}: {errors}"
    assert all(code == "ConflictException" for code, _ in errors), (
        f"expected every loser to be rejected with ConflictException, got {errors}"
    )
    # message varies: a racing loser reads "Duplicate UserName" or "User updated by another
    # request" depending on which write it collides with, so only the code is graded here.

    winning_user_id = successes[0]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=winning_user_id))
    )

    resolved = idstore.get_user_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "userName", "AttributeValue": username}},
    )
    assert resolved["UserId"] == winning_user_id, (
        f"expected the surviving username to resolve to the race winner {winning_user_id}, "
        f"got {resolved['UserId']}"
    )

    idstore.delete_user(IdentityStoreId=store_id, UserId=winning_user_id)
    gone_code, gone_message = _client_error(
        lambda: idstore.get_user_id(
            IdentityStoreId=store_id,
            AlternateIdentifier={"UniqueAttribute": {"AttributePath": "userName", "AttributeValue": username}},
        )
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected the deleted winner's username to no longer resolve, got {gone_code!r}"
    )
    assert gone_message == "USER not found.", (
        f"expected GetUserId on the deleted winner's username to say 'USER not found.', got {gone_message!r}"
    )
    # identitystore's delete family is idempotent: DeleteUser on an already-deleted id succeeds.
    try:
        idstore.delete_user(IdentityStoreId=store_id, UserId=winning_user_id)
    except ClientError as exc:
        raise AssertionError(
            f"expected DeleteUser on an already-deleted user id to be a no-op success, got "
            f"{exc.response['Error']['Code']}: {exc.response['Error'].get('Message')}"
        ) from exc
    still_gone_code, still_gone_message = _client_error(
        lambda: idstore.get_user_id(
            IdentityStoreId=store_id,
            AlternateIdentifier={"UniqueAttribute": {"AttributePath": "userName", "AttributeValue": username}},
        )
    )
    assert still_gone_code == "ResourceNotFoundException", (
        f"a double-deleted user must not have been resurrected, got {still_gone_code!r}"
    )
    assert still_gone_message == "USER not found.", (
        f"expected GetUserId after the double delete to say 'USER not found.', got {still_gone_message!r}"
    )


from botocore.exceptions import ClientError


def _get_identity_store_id(ctx):
    import time
    from botocore.exceptions import ClientError

    sso_admin = ctx.client("sso-admin")

    def _ready_id(insts):
        for inst in insts:
            if inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        return None

    instances = sso_admin.list_instances().get("Instances", [])
    found = _ready_id(instances)
    if found:
        return found
    if not instances:
        try:
            sso_admin.create_instance(Name="sim2real-behav-idc")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ConflictException",):
                raise
    deadline = time.time() + 180
    while time.time() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        found = _ready_id(instances)
        if found:
            return found
        time.sleep(3)
    raise AssertionError(
        "no IAM Identity Center instance could be enabled in this account/region"
    )


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
