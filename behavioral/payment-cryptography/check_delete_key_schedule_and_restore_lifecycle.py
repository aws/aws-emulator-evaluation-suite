"""delete-key-schedule-and-restore-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-key-schedule-and-restore-lifecycle"
GROUP = "state"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteKey moves a key CREATE_COMPLETE -> DELETE_PENDING with a DeletePendingTimestamp,
    and RestoreKey reverts it to CREATE_COMPLETE and clears that timestamp."""
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
    assert created["KeyState"] == "CREATE_COMPLETE"

    deleted = pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)["Key"]
    assert deleted["KeyState"] == "DELETE_PENDING"
    assert "DeletePendingTimestamp" in deleted

    fetched = pc.get_key(KeyIdentifier=arn)["Key"]
    assert fetched["KeyState"] == "DELETE_PENDING"
    assert "DeletePendingTimestamp" in fetched

    restored = pc.restore_key(KeyIdentifier=arn)["Key"]
    assert restored["KeyState"] == "CREATE_COMPLETE"
    assert "DeletePendingTimestamp" not in restored

    fetched2 = pc.get_key(KeyIdentifier=arn)["Key"]
    assert fetched2["KeyState"] == "CREATE_COMPLETE"
    assert "DeletePendingTimestamp" not in fetched2


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
