"""register-user-quicksight-identity-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-user-quicksight-identity-lifecycle"
GROUP = "state"
SERVICES = ["quicksight"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterUser creates an IAM-identity READER that UpdateUser turns into an AUTHOR and that
    DescribeUser reports not found after DeleteUser, while a QUICKSIGHT-identity RegisterUser on an
    IAM_ONLY account fails with AccessDeniedException and leaves no user."""
    qs = ctx.client("quicksight")
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    namespace = "default"
    user_name = ctx.unique_name("s2r-reguser-")
    email = f"{user_name}@example.com"

    iam_user_name = ctx.unique_name("s2r-reguser-iam")
    iam.create_user(UserName=iam_user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=iam_user_name))
    iam_arn = iam.get_user(UserName=iam_user_name)["User"]["Arn"]

    registered = _register_iam_user_with_retry(
        qs,
        AwsAccountId=account_id,
        Namespace=namespace,
        IdentityType="IAM",
        IamArn=iam_arn,
        Email=email,
        UserRole="READER",
    )["User"]
    assert registered["Role"] == "READER"
    assert registered["IdentityType"] == "IAM"
    user_name = registered["UserName"]

    described = qs.describe_user(AwsAccountId=account_id, Namespace=namespace, UserName=user_name)[
        "User"
    ]
    assert described["Role"] == "READER", described

    # With IAM_ONLY authentication the native QUICKSIGHT identity type must be rejected, not
    # silently accepted, while the IAM identity type above (the positive control) succeeds.
    native_user_name = ctx.unique_name("s2r-reguser-native-")
    native_email = f"{native_user_name}@example.com"
    native_err = _client_error(
        lambda: qs.register_user(
            AwsAccountId=account_id,
            Namespace=namespace,
            IdentityType="QUICKSIGHT",
            UserName=native_user_name,
            Email=native_email,
            UserRole="READER",
        )
    )
    assert native_err["Code"] == "AccessDeniedException", native_err
    assert native_err["Message"] == (
        f"Account {account_id} is not authorized to create QuickSight IdentityType user."
        f"AWS account id: {account_id}, Namespace: {namespace}. "
    ), native_err

    native_described_err = _client_error(
        lambda: qs.describe_user(
            AwsAccountId=account_id, Namespace=namespace, UserName=native_user_name
        )
    )
    assert native_described_err["Code"] == "ResourceNotFoundException", native_described_err
    assert native_described_err["Message"] == (
        f"AWS account id: {account_id}, Namespace: {namespace}, Username: {native_user_name}. "
    ), native_described_err

    updated = qs.update_user(
        AwsAccountId=account_id,
        Namespace=namespace,
        UserName=user_name,
        Email=email,
        Role="AUTHOR",
    )["User"]
    assert updated["Role"] == "AUTHOR"

    described_after_update = qs.describe_user(
        AwsAccountId=account_id, Namespace=namespace, UserName=user_name
    )["User"]
    assert described_after_update["Role"] == "AUTHOR", described_after_update

    qs.delete_user(AwsAccountId=account_id, Namespace=namespace, UserName=user_name)

    gone_err = _client_error(
        lambda: qs.describe_user(
            AwsAccountId=account_id, Namespace=namespace, UserName=user_name
        )
    )
    assert gone_err["Code"] == "ResourceNotFoundException", gone_err
    assert gone_err["Message"] == (
        f"User {user_name} does not exist."
        f"AWS account id: {account_id}, Namespace: {namespace}, Username: {user_name}. "
    ), gone_err


def _register_iam_user_with_retry(qs, timeout_s=60.0, interval_s=3.0, **kwargs):
    """A freshly created IAM user can take a few seconds to propagate to other AWS
    services; retry past QuickSight's transient ResourceNotFoundException for it."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return qs.register_user(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException" or _time.monotonic() >= deadline:
                raise
            _time.sleep(interval_s)


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected AWS to reject this call, but it SUCCEEDED and returned {result!r}")


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
