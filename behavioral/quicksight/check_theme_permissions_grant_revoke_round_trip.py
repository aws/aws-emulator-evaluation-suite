"""theme-permissions-grant-revoke-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "theme-permissions-grant-revoke-round-trip"
GROUP = "data-plane"
SERVICES = ["quicksight"]

_GRANTED_ACTIONS = [
    "quicksight:DescribeTheme",
    "quicksight:ListThemeVersions",
    "quicksight:DescribeThemeAlias",
    "quicksight:ListThemeAliases",
]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateThemePermissions grants are visible on DescribeThemePermissions, and a
    subsequent revoke actually removes that principal's entry."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    namespace = "default"
    group_name = ctx.unique_name("s2r-thperm-grp-")
    theme_id = ctx.unique_name("s2r-thperm-")

    group = qs.create_group(AwsAccountId=account_id, Namespace=namespace, GroupName=group_name)[
        "Group"
    ]
    ctx.on_cleanup(
        lambda: qs.delete_group(AwsAccountId=account_id, Namespace=namespace, GroupName=group_name)
    )
    group_arn = group["Arn"]

    qs.create_theme(
        AwsAccountId=account_id,
        ThemeId=theme_id,
        Name=theme_id,
        BaseThemeId="MIDNIGHT",
        Configuration={
            "DataColorPalette": {
                "Colors": [
                    "#222222",
                    "#333333",
                    "#444444",
                    "#555555",
                    "#666666",
                    "#777777",
                    "#888888",
                    "#999999",
                ]
            }
        },
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "s2r-thperm-"},
        ],
    )
    ctx.on_cleanup(lambda: qs.delete_theme(AwsAccountId=account_id, ThemeId=theme_id))
    _poll_theme_creation_terminal(qs, account_id, theme_id)

    before = qs.describe_theme_permissions(AwsAccountId=account_id, ThemeId=theme_id)[
        "Permissions"
    ]
    assert not any(p["Principal"] == group_arn for p in before), before

    qs.update_theme_permissions(
        AwsAccountId=account_id,
        ThemeId=theme_id,
        GrantPermissions=[{"Principal": group_arn, "Actions": _GRANTED_ACTIONS}],
    )
    after_grant = qs.describe_theme_permissions(AwsAccountId=account_id, ThemeId=theme_id)[
        "Permissions"
    ]
    matching = [p for p in after_grant if p["Principal"] == group_arn]
    assert len(matching) == 1, after_grant
    assert set(matching[0]["Actions"]) == set(_GRANTED_ACTIONS), matching[0]

    qs.update_theme_permissions(
        AwsAccountId=account_id,
        ThemeId=theme_id,
        RevokePermissions=[{"Principal": group_arn, "Actions": _GRANTED_ACTIONS}],
    )
    after_revoke = qs.describe_theme_permissions(AwsAccountId=account_id, ThemeId=theme_id)[
        "Permissions"
    ]
    assert not any(p["Principal"] == group_arn for p in after_revoke), after_revoke


def _poll_theme_creation_terminal(qs, account_id, theme_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    terminal = {"CREATION_SUCCESSFUL", "CREATION_FAILED"}
    while time.monotonic() < deadline:
        resp = qs.describe_theme(AwsAccountId=account_id, ThemeId=theme_id)
        last = resp["Theme"]["Version"].get("Status")
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"theme never reached a terminal creation status: {last}")


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
