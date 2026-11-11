"""group-membership-add-remove-reflected-in-listing."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "group-membership-add-remove-reflected-in-listing"
GROUP = "state"
SERVICES = ["quicksight"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Adding then removing a user from a group is reflected in ListGroupMemberships."""
    qs = ctx.client("quicksight")
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    namespace = "default"
    group_name = ctx.unique_name("s2r-grp-")
    user_name = ctx.unique_name("s2r-usr-")

    qs.create_group(AwsAccountId=account_id, Namespace=namespace, GroupName=group_name)
    ctx.on_cleanup(
        lambda: qs.delete_group(AwsAccountId=account_id, Namespace=namespace, GroupName=group_name)
    )

    iam_user_name = ctx.unique_name("s2r-usr-iam")
    iam.create_user(UserName=iam_user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=iam_user_name))
    iam_arn = iam.get_user(UserName=iam_user_name)["User"]["Arn"]

    registered = _register_iam_user_with_retry(
        qs,
        AwsAccountId=account_id,
        Namespace=namespace,
        IdentityType="IAM",
        IamArn=iam_arn,
        Email=f"{user_name}@example.com",
        UserRole="READER",
    )["User"]
    user_name = registered["UserName"]
    ctx.on_cleanup(
        lambda: qs.delete_user(AwsAccountId=account_id, Namespace=namespace, UserName=user_name)
    )

    qs.create_group_membership(
        AwsAccountId=account_id, Namespace=namespace, GroupName=group_name, MemberName=user_name
    )
    members = qs.list_group_memberships(
        AwsAccountId=account_id, Namespace=namespace, GroupName=group_name
    )["GroupMemberList"]
    assert any(m["MemberName"] == user_name for m in members), members

    qs.delete_group_membership(
        AwsAccountId=account_id, Namespace=namespace, GroupName=group_name, MemberName=user_name
    )
    members_after = qs.list_group_memberships(
        AwsAccountId=account_id, Namespace=namespace, GroupName=group_name
    )["GroupMemberList"]
    assert not any(m["MemberName"] == user_name for m in members_after), members_after


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

