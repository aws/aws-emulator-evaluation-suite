"""duplicate-namespace-creation-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "duplicate-namespace-creation-rejected"
GROUP = "overly-permissive"
SERVICES = ["quicksight"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateNamespace for an already-taken name is rejected, without
    disturbing the original namespace, while creating a distinct namespace still works."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    ns1 = ctx.unique_name("s2rdup")

    qs.create_namespace(
        AwsAccountId=account_id,
        Namespace=ns1,
        IdentityStore="QUICKSIGHT",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete_namespace(qs, account_id, ns1))
    _poll_namespace_created(qs, account_id, ns1)

    err = _client_error(
        lambda: qs.create_namespace(
            AwsAccountId=account_id, Namespace=ns1, IdentityStore="QUICKSIGHT"
        )
    )
    assert err["Code"] == "ConflictException", f"expected ConflictException, got {err!r}"
    assert err["Message"] == (
        f"Cannot create a namespace when status is CREATED. Failed to create namespace {ns1} "
        f"for account {account_id}. "
    ), err

    # effect absent: the original namespace is untouched (still exactly one, still CREATED)
    still_there = qs.describe_namespace(AwsAccountId=account_id, Namespace=ns1)["Namespace"]
    assert still_there["CreationStatus"] == "CREATED", (
        f"expected original namespace to remain CREATED, got {still_there['CreationStatus']!r}"
    )

    # positive control: a distinct namespace name still succeeds
    ns2 = ctx.unique_name("s2rdup2")
    qs.create_namespace(
        AwsAccountId=account_id,
        Namespace=ns2,
        IdentityStore="QUICKSIGHT",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete_namespace(qs, account_id, ns2))
    info2 = _poll_namespace_created(qs, account_id, ns2)
    assert info2["CreationStatus"] == "CREATED", (
        f"expected distinct namespace to reach CREATED, got {info2['CreationStatus']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected AWS to reject this call, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete_namespace(qs, account_id, namespace) -> None:
    try:
        qs.delete_namespace(AwsAccountId=account_id, Namespace=namespace)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_namespace_created(qs, account_id, namespace, timeout_s=180.0, interval_s=5.0):
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
