"""batch-enable-standards-invalid-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-enable-standards-invalid-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["securityhub"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """BatchEnableStandards with a bogus StandardsArn alongside a real, not-yet-enabled one rejects the
    whole call with InvalidInputException naming the bad entry, and neither standard is enabled; the
    real standard then enables on its own in a separate call."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(ctx, sh)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:securityhub:{ctx.region}:{account_id}:standards/sim2real-does-not-exist/v/1.0.0"

    standards_arn = _unenabled_standard(ctx, sh)

    code, message = _error_code(
        lambda: sh.batch_enable_standards(
            StandardsSubscriptionRequests=[{"StandardsArn": bogus_arn}, {"StandardsArn": standards_arn}]
        )
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code} ({message})"
    expected_message = f'Invalid StandardsSubscriptionRequest(s): [{{"standardsArn":"{bogus_arn}"}}]'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the whole mixed-batch call was rejected atomically, so neither entry --
    # not the bogus one, and not the real one bundled alongside it -- was enabled.
    subs_after_reject = {s["StandardsArn"] for s in sh.get_enabled_standards()["StandardsSubscriptions"]}
    assert bogus_arn not in subs_after_reject, "bogus standard must not have been enabled"
    assert standards_arn not in subs_after_reject, (
        "real standard must not have been silently enabled from the rejected mixed batch"
    )

    # Positive control: the same real standard, alone in its own call, still enables fine --
    # the mixed-batch rejection above is about the bogus entry, not a broken API.
    sub = sh.batch_enable_standards(StandardsSubscriptionRequests=[{"StandardsArn": standards_arn}])[
        "StandardsSubscriptions"
    ][0]
    sub_arn = sub["StandardsSubscriptionArn"]
    ctx.on_cleanup(lambda: sh.batch_disable_standards(StandardsSubscriptionArns=[sub_arn]))

    ready = _poll_until(
        lambda: sh.get_enabled_standards(StandardsSubscriptionArns=[sub_arn])["StandardsSubscriptions"][0],
        lambda s: s["StandardsStatus"] in ("READY", "FAILED", "INCOMPLETE"),
        timeout_s=180,
        interval_s=5,
    )
    status = ready["StandardsStatus"]
    reason = ready.get("StandardsStatusReason", {})
    if status in ("FAILED", "INCOMPLETE"):
        assert reason.get("StatusReasonCode") == "NO_AVAILABLE_CONFIGURATION_RECORDER", (
            f"unexpected non-READY reason for the positive control: status={status}, reason={reason}"
        )
    subs_for_arn = [s for s in sh.get_enabled_standards()["StandardsSubscriptions"] if s["StandardsArn"] == standards_arn]
    assert len(subs_for_arn) == 1 and subs_for_arn[0]["StandardsSubscriptionArn"] == sub_arn, (
        f"expected exactly one subscription for {standards_arn} matching {sub_arn}, got {subs_for_arn}"
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


def _unenabled_standard(ctx, sh):
    """A standard ARN that is not enabled. When every standard is already enabled, the first one
    is disabled for the duration of the check and re-enabled by cleanup."""
    all_standards = sh.describe_standards()["Standards"]
    assert all_standards, "DescribeStandards returned no standards"
    subs = sh.get_enabled_standards()["StandardsSubscriptions"]
    enabled = {s["StandardsArn"]: s["StandardsSubscriptionArn"] for s in subs}
    for standard in all_standards:
        if standard["StandardsArn"] not in enabled:
            return standard["StandardsArn"]
    standards_arn = all_standards[0]["StandardsArn"]
    sub_arn = enabled[standards_arn]
    sh.batch_disable_standards(StandardsSubscriptionArns=[sub_arn])
    ctx.on_cleanup(
        lambda: sh.batch_enable_standards(StandardsSubscriptionRequests=[{"StandardsArn": standards_arn}])
    )
    _poll_until(
        lambda: {s["StandardsArn"] for s in sh.get_enabled_standards()["StandardsSubscriptions"]},
        lambda arns: standards_arn not in arns,
        timeout_s=180,
        interval_s=5,
    )
    return standards_arn


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        raise AssertionError("expected the call to be rejected, but it succeeded")
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")


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
