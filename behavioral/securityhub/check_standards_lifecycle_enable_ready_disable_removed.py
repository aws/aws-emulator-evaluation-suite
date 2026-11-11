"""standards-lifecycle-enable-ready-disable-removed."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "standards-lifecycle-enable-ready-disable-removed"
GROUP = "state"
SERVICES = ["securityhub"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """BatchEnableStandards drives a subscription PENDING->READY with populated controls, then removes it on disable."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    all_standards = sh.describe_standards()["Standards"]
    enabled_arns = {s["StandardsArn"] for s in sh.get_enabled_standards()["StandardsSubscriptions"]}
    candidate = next((s for s in all_standards if s["StandardsArn"] not in enabled_arns), None)
    if candidate is None:
        raise AssertionError(
            "every available security standard is already enabled in this account/region; "
            "there is no free standard to exercise the enable/disable lifecycle without "
            "disturbing a subscription this suite doesn't own"
        )
    standards_arn = candidate["StandardsArn"]

    sub = sh.batch_enable_standards(StandardsSubscriptionRequests=[{"StandardsArn": standards_arn}])[
        "StandardsSubscriptions"
    ][0]
    sub_arn = sub["StandardsSubscriptionArn"]

    def _cleanup():
        try:
            sh.batch_disable_standards(StandardsSubscriptionArns=[sub_arn])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInputException":
                raise

    ctx.on_cleanup(_cleanup)

    ready = _poll_until(
        lambda: sh.get_enabled_standards(StandardsSubscriptionArns=[sub_arn])["StandardsSubscriptions"][0],
        lambda s: s["StandardsStatus"] in ("READY", "FAILED", "INCOMPLETE"),
        timeout_s=180,
        interval_s=5,
    )
    # The subscription must leave PENDING deterministically. READY is the common case; FAILED
    # with NO_AVAILABLE_CONFIGURATION_RECORDER is an accepted terminal state in a sandbox account
    # that has no AWS Config recorder (Security Hub standards require Config to evaluate controls) --
    # any other status or reason indicates a divergent state machine.
    status = ready["StandardsStatus"]
    reason = ready.get("StandardsStatusReason", {})
    assert status in ("READY", "FAILED", "INCOMPLETE"), f"unexpected terminal status: {status}, reason: {reason}"
    if status in ("FAILED", "INCOMPLETE"):
        assert reason.get("StatusReasonCode") == "NO_AVAILABLE_CONFIGURATION_RECORDER", reason
    else:
        controls = sh.describe_standards_controls(StandardsSubscriptionArn=sub_arn)["Controls"]
        assert len(controls) > 0, f"READY subscription {sub_arn} reported zero controls"
        assert all(c["ControlStatus"] in ("ENABLED", "DISABLED") for c in controls), (
            f"a control on {sub_arn} reported a status outside the modelled enum: {controls}"
        )

    sh.batch_disable_standards(StandardsSubscriptionArns=[sub_arn])
    remaining = _poll_until(
        lambda: sh.get_enabled_standards()["StandardsSubscriptions"],
        lambda subs: sub_arn not in {s["StandardsSubscriptionArn"] for s in subs},
        timeout_s=120,
        interval_s=5,
    )
    remaining_arns = {s["StandardsSubscriptionArn"] for s in remaining}
    assert sub_arn not in remaining_arns, f"{sub_arn} still listed among enabled standards after disable: {remaining_arns}"

    # The subscription is gone, and BatchDisableStandards on an already-removed arn is an idempotent
    # no-op rather than a rejection (measured against real AWS, not assumed).
    try:
        sh.batch_disable_standards(StandardsSubscriptionArns=[sub_arn])
    except ClientError as exc:
        raise AssertionError(
            "expected a silent no-op disabling an already-removed subscription, got error "
            f"{exc.response['Error']['Code']}"
        ) from exc


def _ensure_hub_enabled(sh):
    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise


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
