"""storage-profile-delete-blocked-by-queue-reference-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "storage-profile-delete-blocked-by-queue-reference-rejected"
GROUP = "overly-permissive"
SERVICES = ["deadline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStorageProfile on a profile still named in a queue's allowedStorageProfileIds is
    rejected and the profile stays intact; the same delete succeeds once the reference is
    removed, and an unreferenced profile deletes cleanly as the positive control."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    # Positive control: an unreferenced storage profile deletes cleanly.
    control_id = deadline.create_storage_profile(
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-sp-control-"),
        osFamily="LINUX",
    )["storageProfileId"]
    deadline.delete_storage_profile(farmId=farm_id, storageProfileId=control_id)
    control_error = _client_error(
        lambda: deadline.get_storage_profile(farmId=farm_id, storageProfileId=control_id)
    )
    assert control_error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {control_error}"
    assert control_error.get("Message") == f"Resource of type storage-profile with id {control_id} does not exist.", (
        f"expected the exact ResourceNotFoundException message, got {control_error.get('Message')!r}"
    )

    # Break exactly one thing: name the profile in a queue's allowedStorageProfileIds.
    storage_profile_id = deadline.create_storage_profile(
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-sp-"),
        osFamily="LINUX",
    )["storageProfileId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: deadline.delete_storage_profile(farmId=farm_id, storageProfileId=storage_profile_id))
    )
    queue_id = deadline.create_queue(
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-queue-"),
        allowedStorageProfileIds=[storage_profile_id],
    )["queueId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_queue(farmId=farm_id, queueId=queue_id)))

    blocked_error = _client_error(
        lambda: deadline.delete_storage_profile(farmId=farm_id, storageProfileId=storage_profile_id)
    )
    assert blocked_error.get("Code") == "ConflictException", f"expected ConflictException, got {blocked_error}"
    assert blocked_error.get("Message") == "Request could not be completed: Storage profile is associated with one or more Queues.", (
        f"expected the exact ConflictException message, got {blocked_error.get('Message')!r}"
    )

    # Effect absent: the referenced profile is untouched by the rejected delete.
    sp = deadline.get_storage_profile(farmId=farm_id, storageProfileId=storage_profile_id)
    assert sp["storageProfileId"] == storage_profile_id, "referenced profile vanished after rejected delete"

    # Restore: drop the queue's reference to the profile.
    deadline.update_queue(
        farmId=farm_id, queueId=queue_id, allowedStorageProfileIdsToRemove=[storage_profile_id]
    )

    # The identical delete call now succeeds.
    deadline.delete_storage_profile(farmId=farm_id, storageProfileId=storage_profile_id)
    final_error = _client_error(
        lambda: deadline.get_storage_profile(farmId=farm_id, storageProfileId=storage_profile_id)
    )
    assert final_error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {final_error}"
    assert final_error.get("Message") == f"Resource of type storage-profile with id {storage_profile_id} does not exist.", (
        f"expected the exact ResourceNotFoundException message, got {final_error.get('Message')!r}"
    )


# ===== helpers =====
def _create_farm_with_retry(ctx, deadline):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 180.0
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_farm(displayName=ctx.unique_name("sim2real-farm-"))["farmId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ServiceQuotaExceededException":
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _safe(fn) -> None:
    """Teardown: done on ResourceNotFoundException; retries ConflictException (a child still
    being released) every 2 s for up to 60 s; raises everything else."""
    from botocore.exceptions import ClientError

    deadline_t = time.monotonic() + 60.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline_t:
                raise
        time.sleep(2)


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not be reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

