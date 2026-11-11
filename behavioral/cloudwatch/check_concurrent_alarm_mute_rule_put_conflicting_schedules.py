"""concurrent-alarm-mute-rule-put-conflicting-schedules."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-alarm-mute-rule-put-conflicting-schedules"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutAlarmMuteRule calls on one rule name with different schedules both
    succeed, and GetAlarmMuteRule then returns one caller's rule in full (description and every
    schedule field from the same writer), never a field-level merge."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-mute-")
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=name))

    writes = {
        "rule-a": {"Schedule": {"Expression": "cron(0 2 * * ?)", "Duration": "PT2H", "Timezone": "UTC"}},
        "rule-b": {"Schedule": {"Expression": "cron(0 3 * * ?)", "Duration": "PT1H", "Timezone": "Europe/London"}},
    }

    # PutAlarmMuteRule is create-or-overwrite and declares no conflict error, so both calls must
    # succeed; which one commits last is not observable from the client.
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(lambda d=desc, r=rule: cw.put_alarm_mute_rule(Name=name, Description=d, Rule=r))
            for desc, rule in writes.items()
        ]
        for fut in futures:
            fut.result()

    def _writer(resp):
        desc = resp.get("Description")
        rule = writes.get(desc)
        if rule is None:
            return None
        got = resp.get("Rule", {}).get("Schedule", {})
        if any(got.get(k) != v for k, v in rule["Schedule"].items()):
            return None
        return desc

    observed = _poll_until(
        lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=name),
        lambda resp: _writer(resp) is not None,
        timeout_s=_wait_s(ctx, 20),
        interval_s=1,
    )
    assert _writer(observed) in writes, f"mute rule is not one writer's rule in full: {observed!r}"


def _wait_s(ctx, cap_s):
    """cap_s, shortened so the wait ends before the runner's budget does."""
    left = ctx.time_left()
    if left is None:
        return cap_s
    return max(1.0, min(cap_s, left - 10.0))


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(
        f"mute rule never matched one writer's rule in full within {timeout_s}s; last value: {value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
