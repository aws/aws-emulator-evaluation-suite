"""namespace-creation-reaches-created-state."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "namespace-creation-reaches-created-state"
GROUP = "state-machine"
SERVICES = ["quicksight"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNamespace's async CreationStatus eventually settles on CREATED."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    namespace = ctx.unique_name("s2rns")

    qs.create_namespace(
        AwsAccountId=account_id, Namespace=namespace, IdentityStore="QUICKSIGHT"
    )
    ctx.on_cleanup(lambda: _best_effort_delete_namespace(qs, account_id, namespace))

    info = _poll_namespace(qs, account_id, namespace, timeout_s=180.0)
    assert info["CreationStatus"] == "CREATED", info
    assert info["Name"] == namespace, f"expected Name={namespace!r}, got {info.get('Name')!r}"
    assert info["IdentityStore"] == "QUICKSIGHT", (
        f"expected IdentityStore='QUICKSIGHT', got {info.get('IdentityStore')!r}"
    )


def _best_effort_delete_namespace(qs, account_id, namespace) -> None:
    try:
        qs.delete_namespace(AwsAccountId=account_id, Namespace=namespace)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_namespace(qs, account_id, namespace, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = qs.describe_namespace(AwsAccountId=account_id, Namespace=namespace)
        last = resp["Namespace"]
        if last["CreationStatus"] in ("CREATED", "RETRYABLE_FAILURE", "NON_RETRYABLE_FAILURE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"namespace never reached a terminal status: {last}")


def _ensure_quicksight_subscribed(qs, account_id) -> None:
    """QuickSight requires a one-time account subscription before any resource
    operation succeeds. Idempotently create it (ENTERPRISE / IAM_ONLY) and wait
    for ACCOUNT_CREATED if the account hasn't been subscribed yet."""
    import time

    from botocore.exceptions import ClientError

    try:
        info = qs.describe_account_subscription(AwsAccountId=account_id)["AccountInfo"]
        if info.get("AccountSubscriptionStatus") in ("ACCOUNT_CREATED", "ENABLED"):
            return
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

    try:
        qs.create_account_subscription(
            AwsAccountId=account_id,
            AccountName=f"sim2real-behav-qs-{account_id}",
            NotificationEmail="sim2real-probe@example.com",
            AuthenticationMethod="IAM_ONLY",
            Edition="ENTERPRISE",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceExistsException",):
            raise

    deadline = time.monotonic() + 300.0
    last = None
    while time.monotonic() < deadline:
        info = qs.describe_account_subscription(AwsAccountId=account_id)["AccountInfo"]
        last = info.get("AccountSubscriptionStatus")
        if last in ("ACCOUNT_CREATED", "ENABLED"):
            return
        if last == "ACCOUNT_CREATION_FAILED":
            raise AssertionError(f"quicksight account subscription failed: {info}")
        time.sleep(2)
    raise AssertionError(f"quicksight account subscription never became ready: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
