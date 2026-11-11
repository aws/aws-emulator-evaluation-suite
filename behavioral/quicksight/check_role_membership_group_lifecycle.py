"""role-membership-group-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "role-membership-group-lifecycle"
GROUP = "overly-permissive"
SERVICES = ["quicksight"]

_IDENTITY_STORE_DENIAL = "Operation is disabled for identities managed by QuickSight. "


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRoleMembership and ListRoleMemberships fail with AccessDeniedException naming the
    identity store restriction on an IAM_ONLY account, while a group is created, described,
    deleted and then reported gone."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    namespace = "default"
    group_name = ctx.unique_name("s2r-role-grp-")
    role = "READER"

    # positive control: group management itself works on a healthy account/credentials
    qs.create_group(AwsAccountId=account_id, Namespace=namespace, GroupName=group_name)
    ctx.on_cleanup(lambda: _delete_group_if_present(qs, account_id, namespace, group_name))

    list_err = _client_error(
        lambda: qs.list_role_memberships(AwsAccountId=account_id, Namespace=namespace, Role=role)
    )
    assert list_err["Code"] == "AccessDeniedException", (
        f"expected ListRoleMemberships to be denied for an IAM_ONLY identity store, got {list_err}"
    )
    assert list_err["Message"] == _IDENTITY_STORE_DENIAL, (
        f"expected the denial to name the identity-store restriction, not a bare "
        f"permissions denial, got message: {list_err['Message']!r}"
    )

    create_err = _client_error(
        lambda: qs.create_role_membership(
            AwsAccountId=account_id, Namespace=namespace, Role=role, MemberName=group_name
        )
    )
    assert create_err["Code"] == "AccessDeniedException", (
        f"expected CreateRoleMembership to be denied for an IAM_ONLY identity store, got {create_err}"
    )
    assert create_err["Message"] == _IDENTITY_STORE_DENIAL, (
        f"expected the denial to name the identity-store restriction, not a bare "
        f"permissions denial, got message: {create_err['Message']!r}"
    )

    # effect absent: the group itself is unaffected and still describable
    described = qs.describe_group(AwsAccountId=account_id, Namespace=namespace, GroupName=group_name)[
        "Group"
    ]
    assert described["GroupName"] == group_name, (
        f"expected the group untouched by the denied calls, got {described}"
    )

    # the group's own delete: proves gone, and a mutation on the dead id also fails
    qs.delete_group(AwsAccountId=account_id, Namespace=namespace, GroupName=group_name)
    not_found_err = _client_error(
        lambda: qs.describe_group(AwsAccountId=account_id, Namespace=namespace, GroupName=group_name)
    )
    assert not_found_err["Code"] == "ResourceNotFoundException", (
        f"expected a deleted group to be independently unreadable, got {not_found_err}"
    )
    group_gone = (
        f"Group {group_name} does not exist in the namespace {namespace} of account {account_id}. "
        f"AWS account id: {account_id}, groupName: {group_name}. "
    )
    assert not_found_err["Message"] == group_gone, not_found_err
    update_err = _client_error(
        lambda: qs.update_group(
            AwsAccountId=account_id, Namespace=namespace, GroupName=group_name, Description="dead"
        )
    )
    assert update_err["Code"] == "ResourceNotFoundException", (
        f"expected a mutation on the deleted group to also fail not-found, got {update_err}"
    )
    assert update_err["Message"] == group_gone, update_err


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected AWS to reject this call, but it SUCCEEDED and returned {result!r}")


def _delete_group_if_present(qs, account_id, namespace, group_name) -> None:
    from botocore.exceptions import ClientError

    try:
        qs.delete_group(AwsAccountId=account_id, Namespace=namespace, GroupName=group_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
