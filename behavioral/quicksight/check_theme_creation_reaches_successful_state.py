"""theme-creation-reaches-successful-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "theme-creation-reaches-successful-state"
GROUP = "state-machine"
SERVICES = ["quicksight"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTheme's CreationStatus settles on CREATION_SUCCESSFUL and the configured
    color palette round-trips exactly through DescribeTheme."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    theme_id = ctx.unique_name("s2r-theme-")
    colors = ["#1B2631", "#2C3E50", "#154360", "#0B5345", "#7D6608", "#78281F", "#4A235A", "#1B4F72"]

    created = qs.create_theme(
        AwsAccountId=account_id,
        ThemeId=theme_id,
        Name=theme_id,
        BaseThemeId="MIDNIGHT",
        Configuration={"DataColorPalette": {"Colors": colors}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_theme_if_present(qs, account_id, theme_id))

    status = _poll_theme_creation_terminal(qs, account_id, theme_id, timeout_s=120.0)
    assert status == "CREATION_SUCCESSFUL", status
    assert created["ThemeId"] == theme_id, (theme_id, created)

    described = qs.describe_theme(AwsAccountId=account_id, ThemeId=theme_id)["Theme"]
    palette = described["Version"]["Configuration"]["DataColorPalette"]["Colors"]
    assert palette == colors, palette

    qs.delete_theme(AwsAccountId=account_id, ThemeId=theme_id)
    not_found_err = _client_error(
        lambda: qs.describe_theme(AwsAccountId=account_id, ThemeId=theme_id)
    )
    theme_gone = f"Theme arn:aws:quicksight:{ctx.region}:{account_id}:theme/{theme_id} is not found"
    assert not_found_err["Code"] == "ResourceNotFoundException", not_found_err
    assert not_found_err["Message"] == theme_gone, not_found_err
    alias_err = _client_error(
        lambda: qs.create_theme_alias(
            AwsAccountId=account_id, ThemeId=theme_id, AliasName="POSTDELETE", ThemeVersionNumber=1
        )
    )
    assert alias_err["Code"] == "ResourceNotFoundException", alias_err
    assert alias_err["Message"] == theme_gone, alias_err


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected AWS to reject this call, but it SUCCEEDED and returned {result!r}")


def _delete_theme_if_present(qs, account_id, theme_id) -> None:
    from botocore.exceptions import ClientError

    try:
        qs.delete_theme(AwsAccountId=account_id, ThemeId=theme_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
