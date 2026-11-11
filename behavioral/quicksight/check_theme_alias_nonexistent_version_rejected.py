"""theme-alias-nonexistent-version-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "theme-alias-nonexistent-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["quicksight"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateThemeAlias pointing at a version number that was never published is
    rejected with ResourceNotFoundException, no alias is created for it, while an
    alias for the real (version 1) theme still succeeds (positive control)."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    theme_id = ctx.unique_name("s2r-thalias-")

    qs.create_theme(
        AwsAccountId=account_id,
        ThemeId=theme_id,
        Name=theme_id,
        BaseThemeId="MIDNIGHT",
        Configuration={
            "DataColorPalette": {
                "Colors": [
                    "#111111",
                    "#222222",
                    "#333333",
                    "#444444",
                    "#555555",
                    "#666666",
                    "#777777",
                    "#888888",
                ]
            }
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: qs.delete_theme(AwsAccountId=account_id, ThemeId=theme_id))
    _poll_theme_creation_terminal(qs, account_id, theme_id)

    # positive control: aliasing the real version 1 succeeds
    good_alias = "GOODALIAS"
    qs.create_theme_alias(
        AwsAccountId=account_id, ThemeId=theme_id, AliasName=good_alias, ThemeVersionNumber=1
    )
    good = qs.describe_theme_alias(
        AwsAccountId=account_id, ThemeId=theme_id, AliasName=good_alias
    )["ThemeAlias"]
    assert good["ThemeVersionNumber"] == 1, good

    # negative: aliasing a version that was never published is rejected
    bad_alias = "BADALIAS"
    bad_err = _client_error(
        lambda: qs.create_theme_alias(
            AwsAccountId=account_id, ThemeId=theme_id, AliasName=bad_alias, ThemeVersionNumber=99
        )
    )
    assert bad_err["Code"] == "ResourceNotFoundException", bad_err
    theme_arn = f"arn:aws:quicksight:{ctx.region}:{account_id}:theme/{theme_id}"
    assert bad_err["Message"] == f"Theme {theme_arn}/version/99 is not found", bad_err

    # effect absent: the bad alias was never created
    not_found_err = _client_error(
        lambda: qs.describe_theme_alias(
            AwsAccountId=account_id, ThemeId=theme_id, AliasName=bad_alias
        )
    )
    assert not_found_err["Code"] == "ResourceNotFoundException", not_found_err
    assert not_found_err["Message"] == f"Alias {bad_alias} is not found", not_found_err


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected AWS to reject this call, but it SUCCEEDED and returned {result!r}")


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
