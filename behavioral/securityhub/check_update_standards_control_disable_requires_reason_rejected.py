"""update-standards-control-disable-requires-reason-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-standards-control-disable-requires-reason-rejected"
GROUP = "overly-permissive"
SERVICES = ["securityhub"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """UpdateStandardsControl to DISABLED without DisabledReason is rejected with InvalidInputException."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(ctx, sh)

    subs = sh.get_enabled_standards()["StandardsSubscriptions"]
    ready_subs = [s for s in subs if s["StandardsStatus"] == "READY"]
    if ready_subs:
        sub_arn = ready_subs[0]["StandardsSubscriptionArn"]
    else:
        all_standards = sh.describe_standards()["Standards"]
        if not all_standards:
            raise AssertionError("no security standards are available in this account/region to enable for this test")
        sub = sh.batch_enable_standards(StandardsSubscriptionRequests=[{"StandardsArn": all_standards[0]["StandardsArn"]}])[
            "StandardsSubscriptions"
        ][0]
        sub_arn = sub["StandardsSubscriptionArn"]
        ctx.on_cleanup(lambda: sh.batch_disable_standards(StandardsSubscriptionArns=[sub_arn]))
        _poll_until(
            lambda: sh.get_enabled_standards(StandardsSubscriptionArns=[sub_arn])["StandardsSubscriptions"][0][
                "StandardsStatus"
            ],
            lambda s: s in ("READY", "FAILED", "INCOMPLETE"),
            timeout_s=180,
            interval_s=5,
        )

    control = sh.describe_standards_controls(StandardsSubscriptionArn=sub_arn)["Controls"][0]
    control_arn = control["StandardsControlArn"]
    original_status = control["ControlStatus"]
    original_reason = control.get("DisabledReason")

    code, message = _error_code(
        lambda: sh.update_standards_control(StandardsControlArn=control_arn, ControlStatus="DISABLED")
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    expected = f"DisabledReason must be given when disabling control: {control_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the control's status is unchanged.
    unchanged = next(
        c for c in sh.describe_standards_controls(StandardsSubscriptionArn=sub_arn)["Controls"]
        if c["StandardsControlArn"] == control_arn
    )
    assert unchanged["ControlStatus"] == original_status, (
        f"expected status to remain {original_status!r} after the rejected call, got {unchanged['ControlStatus']!r}"
    )

    # Positive control: disabling WITH a DisabledReason succeeds.
    sh.update_standards_control(
        StandardsControlArn=control_arn, ControlStatus="DISABLED", DisabledReason="sim2real-behavioral-test-disable"
    )

    def _restore():
        if original_status == "DISABLED":
            sh.update_standards_control(
                StandardsControlArn=control_arn, ControlStatus="DISABLED", DisabledReason=original_reason
            )
        else:
            sh.update_standards_control(StandardsControlArn=control_arn, ControlStatus="ENABLED")

    ctx.on_cleanup(_restore)

    disabled = next(
        c for c in sh.describe_standards_controls(StandardsSubscriptionArn=sub_arn)["Controls"]
        if c["StandardsControlArn"] == control_arn
    )
    assert disabled["ControlStatus"] == "DISABLED", f"expected DISABLED, got {disabled['ControlStatus']!r}"
    assert disabled["DisabledReason"] == "sim2real-behavioral-test-disable", (
        f"expected the given DisabledReason to round-trip, got {disabled['DisabledReason']!r}"
    )


def _ensure_hub_enabled(ctx, sh):
    """Enable Security Hub for this check. When this call is what turned the hub on, cleanup
    turns it back off, so the account's hub subscription ends in the state it started in."""
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise
        return
    ctx.on_cleanup(sh.disable_security_hub)


def _error_code(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
