"""security-hub-auto-enable-controls-toggle-refused-after-disable."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-hub-auto-enable-controls-toggle-refused-after-disable"
GROUP = "overly-permissive"
SERVICES = ["securityhub"]

_NOT_SUBSCRIBED = ("ResourceNotFoundException", "Account is not subscribed to Security Hub")


def expect_error(fn, code: str, message: str) -> None:
    """Call fn(); assert it raises exactly (code, message). An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        actual_code = exc.response["Error"]["Code"]
        actual_message = exc.response["Error"].get("Message")
        assert actual_code == code, f"expected error code {code!r}, got {actual_code!r}"
        assert actual_message == message, f"expected message {message!r}, got {actual_message!r}"
        return
    raise AssertionError(f"expected {code!r} to be refused, but it SUCCEEDED and returned {result!r}")


def _poll_auto_enable_controls(sh, want: bool, *, budget_s: float = 60.0, interval_s: float = 1.0) -> dict:
    """DescribeHub until AutoEnableControls reads back `want`; the response that shows it."""
    deadline = time.monotonic() + budget_s
    while True:
        hub = sh.describe_hub()
        if hub["AutoEnableControls"] == want:
            return hub
        if time.monotonic() > deadline:
            raise AssertionError(
                f"AutoEnableControls still {hub['AutoEnableControls']!r} after {budget_s}s, expected {want!r}"
            )
        time.sleep(interval_s)


def _capture_prior(sh) -> dict:
    """The account's Security Hub subscription (if any) before this check touches it."""
    try:
        hub = sh.describe_hub()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidAccessException":
            return {"subscribed": False}
        raise
    standards: list[str] = []
    paginator = sh.get_paginator("get_enabled_standards")
    for page in paginator.paginate():
        standards.extend(sub["StandardsArn"] for sub in page["StandardsSubscriptions"])
    return {
        "subscribed": True,
        "auto_enable_controls": hub["AutoEnableControls"],
        "standards": standards,
    }


def _restore(sh, prior: dict) -> None:
    """Bring the account's Security Hub subscription back to exactly `prior`."""
    try:
        sh.describe_hub()
        currently_subscribed = True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidAccessException":
            raise
        currently_subscribed = False

    if prior["subscribed"]:
        if not currently_subscribed:
            sh.enable_security_hub(EnableDefaultStandards=False)
        sh.update_security_hub_configuration(AutoEnableControls=prior["auto_enable_controls"])
        if prior["standards"]:
            sh.batch_enable_standards(
                StandardsSubscriptionRequests=[{"StandardsArn": arn} for arn in prior["standards"]]
            )
    elif currently_subscribed:
        sh.disable_security_hub()


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
    "resource:account-singleton:securityhub",
)
def run(ctx) -> None:
    """UpdateSecurityHubConfiguration toggles AutoEnableControls, read back by DescribeHub, and
    is refused once DisableSecurityHub removes the account's subscription.
    """
    sh = ctx.client("securityhub")

    # The prior subscription (if any) is not the graded assertion -- it only lets the
    # restore below put the account back exactly as it found it.
    prior = _capture_prior(sh)
    ctx.on_cleanup(lambda: _restore(sh, prior))

    if not prior["subscribed"]:
        sh.enable_security_hub(EnableDefaultStandards=False)

    hub = sh.describe_hub()
    baseline = hub["AutoEnableControls"]
    toggled = not baseline

    sh.update_security_hub_configuration(AutoEnableControls=toggled)
    _poll_auto_enable_controls(sh, toggled)

    # The positive control for the refusal below: the same call, subscribed, toggling back.
    sh.update_security_hub_configuration(AutoEnableControls=baseline)
    _poll_auto_enable_controls(sh, baseline)

    sh.disable_security_hub()

    expect_error(
        lambda: sh.update_security_hub_configuration(AutoEnableControls=toggled), *_NOT_SUBSCRIBED
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
