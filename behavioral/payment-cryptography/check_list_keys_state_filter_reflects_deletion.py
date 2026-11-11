"""list-keys-state-filter-reflects-deletion."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-keys-state-filter-reflects-deletion"
GROUP = "state"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListKeys filtered by KeyState tracks a key's transition: it appears under
    CREATE_COMPLETE right after creation and moves to DELETE_PENDING once DeleteKey schedules
    its removal, disappearing from the CREATE_COMPLETE filter."""
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

    assert _poll_until(
        lambda: arn in _list_arns(pc, "CREATE_COMPLETE"),
        timeout_s=30.0,
    ), "key never appeared under the CREATE_COMPLETE filter"

    pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)

    assert _poll_until(
        lambda: arn in _list_arns(pc, "DELETE_PENDING"),
        timeout_s=30.0,
    ), "key never appeared under the DELETE_PENDING filter"

    after_delete = _list_arns(pc, "CREATE_COMPLETE")
    assert arn not in after_delete, (
        f"key {arn} still listed under CREATE_COMPLETE after DeleteKey scheduled its removal"
    )


def _list_arns(pc, key_state: str) -> set:
    arns: set = set()
    kwargs = {"KeyState": key_state, "MaxResults": 100}
    while True:
        resp = pc.list_keys(**kwargs)
        arns.update(k["KeyArn"] for k in resp.get("Keys", []))
        token = resp.get("NextToken")
        if not token:
            return arns
        kwargs["NextToken"] = token


def _poll_until(predicate, timeout_s: float = 30.0, interval_s: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


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
