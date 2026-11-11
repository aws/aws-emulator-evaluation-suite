"""iam-policy-assignment-status-transitions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "iam-policy-assignment-status-transitions"
GROUP = "state-machine"
SERVICES = ["quicksight"]

_READ_ONLY_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected AWS to reject this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An IAMPolicyAssignment's AssignmentStatus moves DRAFT -> ENABLED -> DISABLED as
    driven by UpdateIAMPolicyAssignment, and each transition is visible on describe."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    namespace = "default"
    name = ctx.unique_name("s2r-assign-")

    created = qs.create_iam_policy_assignment(
        AwsAccountId=account_id,
        Namespace=namespace,
        AssignmentName=name,
        AssignmentStatus="DRAFT",
        PolicyArn=_READ_ONLY_POLICY_ARN,
    )
    assert created["AssignmentStatus"] == "DRAFT", (
        f"expected CreateIAMPolicyAssignment to echo DRAFT, got {created.get('AssignmentStatus')!r}"
    )
    ctx.on_cleanup(lambda: _delete_assignment_if_present(qs, account_id, namespace, name))

    described = _poll_iam_policy_assignment(qs, account_id, namespace, name)
    assert described["AssignmentStatus"] == "DRAFT", (
        f"expected an independent describe to see DRAFT, got {described.get('AssignmentStatus')!r}"
    )

    enabled = qs.update_iam_policy_assignment(
        AwsAccountId=account_id,
        Namespace=namespace,
        AssignmentName=name,
        AssignmentStatus="ENABLED",
    )
    assert enabled["AssignmentStatus"] == "ENABLED", (
        f"expected UpdateIAMPolicyAssignment to echo ENABLED, got {enabled.get('AssignmentStatus')!r}"
    )
    described_enabled = qs.describe_iam_policy_assignment(
        AwsAccountId=account_id, Namespace=namespace, AssignmentName=name
    )["IAMPolicyAssignment"]
    assert described_enabled["AssignmentStatus"] == "ENABLED", (
        f"expected an independent describe to see ENABLED, got {described_enabled.get('AssignmentStatus')!r}"
    )

    disabled = qs.update_iam_policy_assignment(
        AwsAccountId=account_id,
        Namespace=namespace,
        AssignmentName=name,
        AssignmentStatus="DISABLED",
    )
    assert disabled["AssignmentStatus"] == "DISABLED", (
        f"expected UpdateIAMPolicyAssignment to echo DISABLED, got {disabled.get('AssignmentStatus')!r}"
    )
    described_disabled = qs.describe_iam_policy_assignment(
        AwsAccountId=account_id, Namespace=namespace, AssignmentName=name
    )["IAMPolicyAssignment"]
    assert described_disabled["AssignmentStatus"] == "DISABLED", (
        f"expected an independent describe to see DISABLED, got {described_disabled.get('AssignmentStatus')!r}"
    )

    qs.delete_iam_policy_assignment(AwsAccountId=account_id, Namespace=namespace, AssignmentName=name)
    _poll_until_not_found(qs, account_id, namespace, name)
    mutation_err = _client_error(
        lambda: qs.update_iam_policy_assignment(
            AwsAccountId=account_id,
            Namespace=namespace,
            AssignmentName=name,
            AssignmentStatus="ENABLED",
        )
    )
    assert mutation_err["Code"] == "ResourceNotFoundException", (
        f"expected a mutation on the deleted assignment to fail not-found, got {mutation_err!r}"
    )
    assert mutation_err["Message"] == f"Cannot find an assignment named {name}.", mutation_err


def _delete_assignment_if_present(qs, account_id, namespace, name) -> None:
    from botocore.exceptions import ClientError

    try:
        qs.delete_iam_policy_assignment(AwsAccountId=account_id, Namespace=namespace, AssignmentName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_iam_policy_assignment(qs, account_id, namespace, name, timeout_s=60.0, interval_s=2.0):
    """CreateIAMPolicyAssignment is eventually consistent -- an immediate Describe can
    race ahead of the write, so poll past a transient ResourceNotFoundException."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return qs.describe_iam_policy_assignment(
                AwsAccountId=account_id, Namespace=namespace, AssignmentName=name
            )["IAMPolicyAssignment"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException" or _time.monotonic() >= deadline:
                raise
            _time.sleep(interval_s)


def _poll_until_not_found(qs, account_id, namespace, name, timeout_s=60.0, interval_s=2.0):
    """DeleteIAMPolicyAssignment is eventually consistent too -- an immediate Describe can
    still return the just-deleted assignment, so poll until it genuinely 404s."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            qs.describe_iam_policy_assignment(
                AwsAccountId=account_id, Namespace=namespace, AssignmentName=name
            )
            code = None
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        if _time.monotonic() >= deadline:
            raise AssertionError(
                f"deleted assignment never read back not-found within {timeout_s}s; last describe code={code!r}"
            )
        _time.sleep(interval_s)


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

