"""data-protection-policy-masks-log-events."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "data-protection-policy-masks-log-events"
GROUP = 'data-protection'
SERVICES = ['logs']

_EMAIL = "jane.doe@example.com"
_MASKED_MARKER = "*"


# ===== helpers =====
def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


# ===== end helpers =====


def _policy_document(name):
    """Audit-free Deidentify policy: mask the built-in EmailAddress identifier."""
    return json.dumps(
        {
            "Name": name,
            "Version": "2021-06-01",
            "Statement": [
                {
                    "Sid": "audit-email",
                    "DataIdentifier": [
                        "arn:aws:dataprotection::aws:data-identifier/EmailAddress"
                    ],
                    "Operation": {"Audit": {"FindingsDestination": {}}},
                },
                {
                    "Sid": "mask-email",
                    "DataIdentifier": [
                        "arn:aws:dataprotection::aws:data-identifier/EmailAddress"
                    ],
                    "Operation": {"Deidentify": {"MaskConfig": {}}},
                },
            ],
        }
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A data protection policy MASKS matched data on both read paths (GetLogEvents, FilterLogEvents)
    and ``unmask=True`` returns the original, while a non-matching event and an unprotected control
    group are returned verbatim, so the policy is the discriminator and nothing is over-masked.
    """
    svc = ctx.client("logs")

    protected = ctx.unique_name("sim2real-behav-lg-dpp-")
    control = ctx.unique_name("sim2real-behav-lg-dppctl-")
    stream = ctx.unique_name("sim2real-behav-stream-")

    svc.create_log_group(logGroupName=protected)
    ctx.on_cleanup(lambda _n=protected: svc.delete_log_group(logGroupName=_n))
    svc.create_log_group(logGroupName=control)
    ctx.on_cleanup(lambda _n=control: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=protected, logStreamName=stream)
    svc.create_log_stream(logGroupName=control, logStreamName=stream)

    # The policy must be in place BEFORE ingest -- detection happens at ingest.
    policy_name = ctx.unique_name("sim2real-behav-dpp-")
    svc.put_data_protection_policy(
        logGroupIdentifier=protected, policyDocument=_policy_document(policy_name)
    )
    ctx.on_cleanup(
        lambda _n=protected: svc.delete_data_protection_policy(logGroupIdentifier=_n)
    )

    sensitive = f"login attempt from user {_EMAIL} failed"
    benign = "login attempt from user with no address failed"

    # Masking is applied at INGEST, so an event ingested before the freshly-written
    # policy is live is stored unredacted and no amount of read-path polling will
    # ever mask it. PutDataProtectionPolicy returns (and GetDataProtectionPolicy
    # echoes) before that happens, so the only reliable barrier is to ingest a
    # canary into a throwaway stream until it comes back masked -- measured on real
    # AWS at roughly 10-20s after the put.
    canary_stream = ctx.unique_name("sim2real-behav-canary-")
    svc.create_log_stream(logGroupName=protected, logStreamName=canary_stream)

    def _canary():
        svc.put_log_events(
            logGroupName=protected,
            logStreamName=canary_stream,
            logEvents=[{"timestamp": _now_ms(), "message": f"canary {_EMAIL} canary"}],
        )
        resp = svc.get_log_events(
            logGroupName=protected, logStreamName=canary_stream, startFromHead=True
        )
        return [e["message"] for e in resp.get("events", [])]

    _poll_until(
        _canary,
        lambda msgs: any(_EMAIL not in m and _MASKED_MARKER in m for m in msgs),
        timeout_s=180,
        interval_s=5.0,
        description="the data protection policy becomes live on the ingest path",
    )

    base = _now_ms()
    for group in (protected, control):
        svc.put_log_events(
            logGroupName=group,
            logStreamName=stream,
            logEvents=[
                {"timestamp": base, "message": sensitive},
                {"timestamp": base + 1000, "message": benign},
            ],
        )

    def _get(group, **kwargs):
        resp = svc.get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True, **kwargs
        )
        return [e["message"] for e in resp.get("events", [])]

    # --- 1. Masked on the default GetLogEvents read path.
    masked = _poll_until(
        lambda: _get(protected),
        lambda msgs: len(msgs) == 2 and _EMAIL not in msgs[0],
        timeout_s=90,
        interval_s=3.0,
        description="the protected group returns the sensitive event with the address masked",
    )
    assert _EMAIL not in masked[0], (
        "GetLogEvents on a log group with a Deidentify/MaskConfig policy must NOT return the "
        f"raw email address, got {masked[0]!r}"
    )
    assert _MASKED_MARKER in masked[0], (
        f"the masked event must contain the mask character {_MASKED_MARKER!r}, got {masked[0]!r}"
    )
    assert masked[0].startswith("login attempt from user "), (
        f"only the matched data identifier may be redacted, got {masked[0]!r}"
    )

    # --- 2. No over-masking: the event with nothing sensitive is verbatim.
    assert masked[1] == benign, (
        "an event containing no matched data identifier must be returned verbatim from a "
        f"protected log group, got {masked[1]!r}"
    )

    # --- 3. unmask=True recovers the original -- the data was masked on read,
    # not destroyed at ingest.
    unmasked = _get(protected, unmask=True)
    assert unmasked[0] == sensitive, (
        "GetLogEvents(unmask=True) must return the original event verbatim, got "
        f"{unmasked[0]!r}"
    )
    assert unmasked[1] == benign, f"unmask must not alter unmatched events, got {unmasked[1]!r}"

    # --- 4. FilterLogEvents is masked too, and unmaskable -- both read paths.
    def _filter(**kwargs):
        resp = svc.filter_log_events(logGroupName=protected, **kwargs)
        return sorted(e["message"] for e in resp.get("events", []))

    filtered = _filter()
    filtered_sensitive = [m for m in filtered if m.startswith("login attempt from user ") and m != benign]
    assert filtered_sensitive and _EMAIL not in filtered_sensitive[0], (
        f"FilterLogEvents must mask the address on a protected log group, got {filtered!r}"
    )
    filtered_unmasked = _filter(unmask=True)
    assert sensitive in filtered_unmasked, (
        f"FilterLogEvents(unmask=True) must return the original event, got {filtered_unmasked!r}"
    )

    # --- 5. Control: the identical event in a group with NO policy is verbatim,
    # so the policy is provably the discriminator.
    control_msgs = _poll_until(
        lambda: _get(control),
        lambda msgs: len(msgs) == 2,
        timeout_s=90,
        interval_s=3.0,
        description="the control group returns both events",
    )
    assert control_msgs == [sensitive, benign], (
        "a log group with no data protection policy must return events verbatim -- masking "
        f"here means the policy is being applied account-wide; got {control_msgs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
