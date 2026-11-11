"""alarm-mute-rule-status-computed-from-dates."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-mute-rule-status-computed-from-dates"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAlarmMuteRule computes the mute rule's Status (SCHEDULED vs ACTIVE) from
    its StartDate/ExpireDate rather than treating it as an opaque stored field,
    and DeleteAlarmMuteRule removes it immediately."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "put_alarm_mute_rule"):
        raise AssertionError("this botocore/emulator does not expose the AlarmMuteRule API")

    # PutAlarmMuteRule's StartDate/ExpireDate only support minute-level precision;
    # passing seconds/microseconds is rejected outright with a ValidationError.
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    rule_body = {
        "Schedule": {
            # PutAlarmMuteRule only supports cron() expressions ("Only cron expressions
            # are supported"); rate()/at() forms are rejected outright. Dates are honored
            # for recurring cron() schedules, so use a daily cron to exercise the
            # SCHEDULED-vs-ACTIVE computation.
            #
            # AlarmMuteRule cron expressions are 5-field (minute hour day-of-month month
            # day-of-week), unlike EventBridge's 6-field form with a trailing year; a
            # 6-field expression (e.g. with a trailing "*" year) is rejected outright by
            # real CloudWatch with a ValidationError.
            #
            # A rule's "Status" isn't just derived from whether "now" falls within
            # [StartDate, ExpireDate) -- it also requires "now" to fall within one of
            # the recurring cron-triggered mute windows (each of length Duration). A
            # once-daily "cron(0 0 * * ?)" trigger only produces a 1-hour mute window
            # per day, so a rule with an in-window StartDate/ExpireDate would still
            # report SCHEDULED (not ACTIVE) outside that specific hour. Use an
            # hourly-on-the-hour trigger with a 1-hour duration so the mute windows
            # tile back-to-back and cover every moment, making "now" always fall
            # inside one of them whenever the test happens to run.
            "Expression": "cron(0 * * * ?)",
            "Duration": "PT1H",
            "Timezone": "UTC",
        }
    }

    active_name = ctx.unique_name("sim2real-behav-mute-active-")
    scheduled_name = ctx.unique_name("sim2real-behav-mute-sched-")

    # Active now: StartDate in the past, ExpireDate well in the future.
    cw.put_alarm_mute_rule(
        Name=active_name,
        Rule=rule_body,
        StartDate=now - timedelta(hours=1),
        ExpireDate=now + timedelta(days=1),
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=active_name))

    # Not yet active: StartDate well in the future.
    cw.put_alarm_mute_rule(
        Name=scheduled_name,
        Rule=rule_body,
        StartDate=now + timedelta(days=2),
        ExpireDate=now + timedelta(days=3),
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=scheduled_name))

    def _get(name: str) -> dict:
        return cw.get_alarm_mute_rule(AlarmMuteRuleName=name)

    def _status(name: str) -> str:
        return _get(name)["Status"]

    got_active = _poll_until(lambda: _status(active_name), lambda s: s in ("ACTIVE", "SCHEDULED"), timeout_s=30, interval_s=2)
    assert got_active == "ACTIVE", f"expected an in-window mute rule to be ACTIVE, got {got_active}"

    got_scheduled = _poll_until(lambda: _status(scheduled_name), lambda s: s in ("ACTIVE", "SCHEDULED"), timeout_s=30, interval_s=2)
    assert got_scheduled == "SCHEDULED", f"expected a future-dated mute rule to be SCHEDULED, got {got_scheduled}"

    # ListAlarmMuteRules summaries (AlarmMuteRuleSummary) do not carry the rule's
    # *name* at all -- only its ARN, Status, ExpireDate, MuteType, and
    # LastUpdatedTimestamp are returned per-summary. So identify our rules in the
    # listing by ARN (fetched from GetAlarmMuteRule) rather than by name. The
    # listing is also paginated (a real account may already have other mute
    # rules ahead of ours in the result set), so walk every page via NextToken
    # rather than trusting a single unpaginated call to contain both
    # freshly-created rules.
    active_arn = _get(active_name)["AlarmMuteRuleArn"]
    scheduled_arn = _get(scheduled_name)["AlarmMuteRuleArn"]

    arns = _list_all_mute_rule_arns(cw)
    assert {active_arn, scheduled_arn} <= arns, f"both rules should be listed, got {arns}"

    cw.delete_alarm_mute_rule(AlarmMuteRuleName=active_name)
    remaining = _list_all_mute_rule_arns(cw)
    assert active_arn not in remaining, "deleted mute rule is still listed"


def _list_all_mute_rule_arns(cw) -> set:
    arns: set = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cw.list_alarm_mute_rules(**kwargs)
        arns |= {s["AlarmMuteRuleArn"] for s in resp.get("AlarmMuteRuleSummaries", [])}
        token = resp.get("NextToken")
        if not token:
            break
    return arns


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for condition; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
