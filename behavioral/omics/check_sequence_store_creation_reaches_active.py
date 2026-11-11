"""sequence-store-creation-reaches-active."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sequence-store-creation-reaches-active"
GROUP = "state"
SERVICES = ["omics"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSequenceStore starts CREATING and the store settles into ACTIVE; DeleteSequenceStore
    then makes it unreadable and unusable."""
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-seqstore-")

    created = omics.create_sequence_store(name=name, tags={"sim2real:managed": "true"})
    store_id = created["id"]
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, store_id))

    status = created.get("status")
    deadline = time.monotonic() + 180
    while status not in ("ACTIVE", "FAILED") and time.monotonic() < deadline:
        time.sleep(3)
        status = omics.get_sequence_store(id=store_id)["status"]

    assert status == "ACTIVE", f"sequence store {store_id} ended in status {status!r}"

    described = omics.get_sequence_store(id=store_id)
    assert described["name"] == name, f"expected name {name!r}, got {described['name']!r}"
    assert described["status"] == "ACTIVE", f"expected status ACTIVE, got {described['status']!r}"
    assert described["id"] == store_id, f"expected id {store_id!r}, got {described['id']!r}"

    # the delete this check performs at teardown is a free negative: prove gone, then unusable
    omics.delete_sequence_store(id=store_id)

    expected_message = "The specified sequence store does not exist."
    code, message = _client_error(lambda: omics.get_sequence_store(id=store_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted sequence store, got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    redelete_code, redelete_message = _client_error(lambda: omics.delete_sequence_store(id=store_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted sequence store, got {redelete_code!r}"
    )
    assert redelete_message == expected_message, (
        f"expected message {expected_message!r}, got {redelete_message!r}"
    )


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(ctx, store_id: str) -> None:
    try:
        ctx.client("omics").delete_sequence_store(id=store_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
