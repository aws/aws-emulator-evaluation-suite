"""server-side-account-capacity-limit-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "server-side-account-capacity-limit-enforced"
GROUP = "server-side"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:opensearchserverless-account-settings")
def run(ctx) -> None:
    """GetAccountSettings reflects a capacity ceiling pinned below a standby-enabled collection's
    documented need, yet that collection still reaches ACTIVE: on the collection-group capacity model
    the account-level ceiling does not gate CreateCollection."""
    osc = ctx.client("opensearchserverless")

    original = osc.get_account_settings()["accountSettingsDetail"].get("capacityLimits")

    def _restore():
        if original:
            osc.update_account_settings(capacityLimits=original)

    ctx.on_cleanup(_restore)

    collection_name = ctx.unique_name("sim2real-ocu-")
    enc_name = _short_name(ctx, "sim2real-ocuenc-")
    osc.create_security_policy(
        type="encryption",
        name=enc_name,
        policy=json.dumps(
            {"Rules": [{"ResourceType": "collection", "Resource": [f"collection/{collection_name}"]}], "AWSOwnedKey": True}
        ),
    )
    ctx.on_cleanup(lambda: _teardown(lambda: osc.delete_security_policy(type="encryption", name=enc_name)))

    # Tighten the account ceiling to well below a standby-enabled collection's
    # documented 4-OCU-per-dimension requirement.
    osc.update_account_settings(capacityLimits={"maxIndexingCapacityInOCU": 2, "maxSearchCapacityInOCU": 2})

    # GetAccountSettings faithfully reflects the tightened ceiling immediately.
    reflected = osc.get_account_settings()["accountSettingsDetail"]["capacityLimits"]
    assert reflected["maxIndexingCapacityInOCU"] == 2, f"ceiling not reflected: {reflected!r}"
    assert reflected["maxSearchCapacityInOCU"] == 2, f"ceiling not reflected: {reflected!r}"

    # CreateCollection with standbyReplicas=ENABLED still succeeds and reaches
    # ACTIVE despite the tightened ceiling -- the account is on the NextGen
    # capacity model, where this legacy field does not gate collection creation.
    collection_id = osc.create_collection(
        name=collection_name,
        type="SEARCH",
        standbyReplicas="ENABLED",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["createCollectionDetail"]["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_collection(osc, collection_id))
    _wait_collection_active(osc, collection_id, timeout_s=600)

    detail = osc.batch_get_collection(ids=[collection_id])["collectionDetails"][0]
    assert detail["status"] == "ACTIVE", f"expected ACTIVE, got {detail['status']!r}"

    # Restore the ceiling immediately (not just at teardown).
    _restore()


# ===== self-contained helpers =====
def _short_name(ctx, prefix, maxlen=32):
    name = ctx.unique_name(prefix)
    if len(name) <= maxlen:
        return name
    return name[: maxlen - 1].rstrip("-") + "z"


def _teardown(fn, timeout_s=270.0):
    """Teardown call: an absent resource is done, ConflictException (a collection still CREATING)
    or ValidationException (a policy still in use) is retried every 2 s to the deadline, which
    keeps all of the check's teardowns inside its cleanup budget; every other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _best_effort_delete_collection(osc, collection_id):
    _teardown(lambda: osc.delete_collection(id=collection_id))


def _wait_collection_active(osc, collection_id, timeout_s=600, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = osc.batch_get_collection(ids=[collection_id]).get("collectionDetails", [])
        if details:
            status = details[0]["status"]
            if status == "ACTIVE":
                return
            if status == "FAILED":
                raise AssertionError(f"collection {collection_id} entered FAILED state while creating")
        time.sleep(interval_s)
    raise AssertionError(f"collection {collection_id} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
