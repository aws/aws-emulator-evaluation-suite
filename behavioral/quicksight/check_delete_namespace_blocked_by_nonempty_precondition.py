"""delete-namespace-blocked-by-nonempty-precondition."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-namespace-blocked-by-nonempty-precondition"
GROUP = "overly-permissive"
SERVICES = ["quicksight"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteNamespace on "default" fails with InvalidParameterValueException ("Cannot delete the
    default namespace.") and leaves it CREATED, while a fresh namespace, once CREATED, is
    deleted and then reported as not found."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)

    # "default" always exists once the account is subscribed.
    default_info = qs.describe_namespace(AwsAccountId=account_id, Namespace="default")["Namespace"]
    assert default_info["CreationStatus"] == "CREATED", (
        f"expected the default namespace to already be CREATED, got {default_info!r}"
    )

    err = _client_error(
        lambda: qs.delete_namespace(AwsAccountId=account_id, Namespace="default")
    )
    assert err["Code"] == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException deleting the default namespace, got {err!r}"
    )
    assert err["Message"] == "Cannot delete the default namespace.", err

    # effect absent: default namespace is still there, untouched
    still_there = qs.describe_namespace(AwsAccountId=account_id, Namespace="default")["Namespace"]
    assert still_there["CreationStatus"] == "CREATED", (
        f"expected default namespace to remain CREATED, got {still_there['CreationStatus']!r}"
    )

    # positive control: an unrelated, freshly created namespace can be deleted
    namespace = ctx.unique_name("s2rprec")
    qs.create_namespace(
        AwsAccountId=account_id,
        Namespace=namespace,
        IdentityStore="QUICKSIGHT",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete_namespace(qs, account_id, namespace))
    _poll_namespace_created(qs, account_id, namespace)

    qs.delete_namespace(AwsAccountId=account_id, Namespace=namespace)
    gone = _poll_namespace_gone(qs, account_id, namespace)
    assert gone, f"expected {namespace!r} to become unreachable after delete, still present"

    # deletes prove gone and unusable: a mutation on the dead id fails specifically
    dead_err = _client_error(
        lambda: qs.delete_namespace(AwsAccountId=account_id, Namespace=namespace)
    )
    assert dead_err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException re-deleting a gone namespace, got {dead_err!r}"
    )
    assert dead_err["Message"] == (
        f"Namespace {namespace} not found Failed to delete namespace {namespace} "
        f"for account {account_id}. "
    ), dead_err


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


def _poll_namespace_gone(qs, account_id, namespace, timeout_s=180.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = qs.describe_namespace(AwsAccountId=account_id, Namespace=namespace)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise
        last_status = resp["Namespace"]["CreationStatus"]
        time.sleep(interval_s)
    raise AssertionError(
        f"{namespace!r} never became unreachable after delete; last status {last_status!r}"
    )


def _ensure_quicksight_subscribed(qs, account_id) -> None:
    """QuickSight requires a one-time account subscription before any resource
    operation succeeds: create it (ENTERPRISE / IAM_ONLY) when the account has none
    and wait for ACCOUNT_CREATED."""
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
