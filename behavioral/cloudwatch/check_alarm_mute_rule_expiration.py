"""alarm-mute-rule-expiration."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-mute-rule-expiration"
GROUP = 'alarms'
SERVICES = ['cloudwatch']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """Call fn() expecting a ClientError; return (code, message); raise if it unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected an error, call unexpectedly succeeded with {result!r}")


# timing:real-time — ttl: 70 s
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A PutAlarmMuteRule with a short ExpireDate transitions from ACTIVE to
    EXPIRED once that TTL passes, as observed via GetAlarmMuteRule; after that,
    DeleteAlarmMuteRule removes it so a subsequent GetAlarmMuteRule 404s."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-cwprobe-mute-ttl-")
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    # ExpireDate only supports minute-level precision (no seconds); round up to
    # the next full minute boundary so the TTL is short (60-120s) but valid.
    expire = now + timedelta(minutes=2)

    ctx.on_cleanup(lambda _n=name: cw.delete_alarm_mute_rule(AlarmMuteRuleName=_n))
    cw.put_alarm_mute_rule(
        Name=name,
        Rule={"Schedule": {"Expression": "cron(0 2 * * ?)", "Duration": "PT2H", "Timezone": "UTC"}},
        ExpireDate=expire,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    def get():
        return cw.get_alarm_mute_rule(AlarmMuteRuleName=name)

    rule = _poll_until(get, lambda r: r.get("Status") is not None, timeout_s=30, interval_s=2, description="mute rule visible")
    assert rule["Status"] in ("SCHEDULED", "ACTIVE"), (
        f"expected a not-yet-expired mute rule to be SCHEDULED or ACTIVE before its "
        f"ExpireDate TTL elapses, got {rule['Status']}"
    )

    rule = _poll_until(
        get,
        lambda r: r["Status"] == "EXPIRED",
        timeout_s=180,
        interval_s=10,
        description="mute rule status becomes EXPIRED once its ExpireDate TTL passes",
    )
    assert rule["Status"] == "EXPIRED", f"expected EXPIRED after the TTL passed, got {rule['Status']}"

    cw.delete_alarm_mute_rule(AlarmMuteRuleName=name)
    code, message = _error(get)
    assert code == "ResourceNotFoundException", (
        f"expected GetAlarmMuteRule to 404 after DeleteAlarmMuteRule, got {code!r}"
    )
    expected = ""  # real AWS returns an empty message for this code
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
