"""delete-key-conflict-when-already-pending-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-key-conflict-when-already-pending-rejected"
GROUP = "overly-permissive"
SERVICES = ["payment-cryptography"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteKey on a key already in DELETE_PENDING gets ValidationException with its exact message and
    leaves DeletePendingTimestamp unchanged; RestoreKey returns the key to CREATE_COMPLETE and a second
    DeleteKey makes it DELETE_PENDING again."""
    pc = ctx.client("payment-cryptography")
    key_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    created = pc.create_key(
        KeyAttributes=key_attributes,
        Exportable=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Key"]
    arn = created["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))

    first = pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=5)["Key"]
    assert first["KeyState"] == "DELETE_PENDING", (
        f"the first DeleteKey on a CREATE_COMPLETE key must move it to DELETE_PENDING; "
        f"got {first['KeyState']!r}"
    )
    original_timestamp = first["DeletePendingTimestamp"]

    code, message = _error(lambda: pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=30))
    assert code == "ValidationException", (
        f"scheduling deletion on a key already DELETE_PENDING must be refused with "
        f"ValidationException; got {code!r}"
    )
    expected = f"Key {arn} not in CREATE_COMPLETE state."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = pc.get_key(KeyIdentifier=arn)["Key"]
    assert unchanged["KeyState"] == "DELETE_PENDING", (
        f"the refused second DeleteKey must leave the key DELETE_PENDING; "
        f"an independent GetKey saw {unchanged['KeyState']!r}"
    )
    assert unchanged["DeletePendingTimestamp"] == original_timestamp, (
        f"the refused second DeleteKey must not move the original DeletePendingTimestamp "
        f"{original_timestamp!r}; an independent GetKey saw {unchanged['DeletePendingTimestamp']!r}"
    )

    # positive control: the same key can be restored and deleted again cleanly
    restored = pc.restore_key(KeyIdentifier=arn)["Key"]
    assert restored["KeyState"] == "CREATE_COMPLETE", (
        f"RestoreKey on a DELETE_PENDING key must revert it to CREATE_COMPLETE; "
        f"got {restored['KeyState']!r}"
    )
    redeleted = pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=5)["Key"]
    assert redeleted["KeyState"] == "DELETE_PENDING", (
        f"DeleteKey on the restored (CREATE_COMPLETE) key must succeed identically to the first "
        f"time; got {redeleted['KeyState']!r}"
    )

    # terminal read: independent of the mutating DeleteKey call that just ran
    final = pc.get_key(KeyIdentifier=arn)["Key"]
    assert final["KeyState"] == "DELETE_PENDING", (
        f"an independent GetKey after the restore-then-redelete must also report DELETE_PENDING; "
        f"got {final['KeyState']!r}"
    )


def _error(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected this DeleteKey call to be refused, but it SUCCEEDED and returned {result!r}"
    )


def _safe_delete(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
