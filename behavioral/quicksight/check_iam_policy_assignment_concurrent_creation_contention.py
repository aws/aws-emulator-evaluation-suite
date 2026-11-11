"""iam-policy-assignment-concurrent-creation-contention."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "iam-policy-assignment-concurrent-creation-contention"
GROUP = "concurrency"
SERVICES = ["quicksight"]

_READ_ONLY_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateIAMPolicyAssignment calls in one namespace either succeed or fail with
    ConcurrentUpdatingException, and every assignment reported as created is then describable as
    a DRAFT with the requested policy."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    namespace = "default"
    names = [ctx.unique_name(f"s2r-race-{i}-") for i in range(6)]

    def _create(name: str):
        from botocore.exceptions import ClientError

        try:
            resp = qs.create_iam_policy_assignment(
                AwsAccountId=account_id,
                Namespace=namespace,
                AssignmentName=name,
                AssignmentStatus="DRAFT",
                PolicyArn=_READ_ONLY_POLICY_ARN,
            )
            return name, "success", resp
        except ClientError as e:
            return name, e.response["Error"]["Code"], e.response["Error"].get("Message")

    results = []
    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        futures = [pool.submit(_create, n) for n in names]
        for f in as_completed(futures):
            results.append(f.result())

    succeeded = [name for name, outcome, _ in results if outcome == "success"]
    for name in succeeded:
        ctx.on_cleanup(lambda n=name: _delete_assignment_if_present(qs, account_id, namespace, n))

    for name, outcome, message in results:
        if outcome != "success":
            assert outcome == "ConcurrentUpdatingException", (
                f"racer {name} must either succeed or get ConcurrentUpdatingException, got {outcome} {message!r}"
            )

    assert len(succeeded) >= 1, "no racer ever succeeded"

    for name in succeeded:
        described = _poll_iam_policy_assignment(qs, account_id, namespace, name)
        assert described["AssignmentName"] == name, (name, described.get("AssignmentName"))
        assert described["AssignmentStatus"] == "DRAFT", (name, described.get("AssignmentStatus"))
        assert described["PolicyArn"] == _READ_ONLY_POLICY_ARN, (name, described.get("PolicyArn"))

    rejected = [name for name, outcome, _ in results if outcome == "ConcurrentUpdatingException"]
    for name in rejected:
        from botocore.exceptions import ClientError

        try:
            qs.describe_iam_policy_assignment(
                AwsAccountId=account_id, Namespace=namespace, AssignmentName=name
            )
        except ClientError as e:
            assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
                f"rejected racer {name} should leave no assignment behind, "
                f"got describe error {e.response['Error']['Code']} instead"
            )
            assert e.response["Error"]["Message"] == f"Cannot find an assignment named {name}.", (
                e.response["Error"]
            )
        else:
            raise AssertionError(
                f"rejected racer {name} got ConcurrentUpdatingException on create "
                "but describe found it anyway -- the store is corrupted"
            )


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
