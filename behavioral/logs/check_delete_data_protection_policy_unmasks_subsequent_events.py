"""delete-data-protection-policy-unmasks-subsequent-events."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "delete-data-protection-policy-unmasks-subsequent-events"
GROUP = "data-plane"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After DeleteDataProtectionPolicy, new events with the previously-masked pattern
    are stored/read back unmasked, while events ingested while the policy was active
    stay masked at read time.
    """
    logs = ctx.client("logs")
    log_group = ctx.unique_name("sim2real-dpp-lg")
    log_stream = ctx.unique_name("sim2real-dpp-ls")

    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    policy_document = {
        "Name": "sim2real-dpp",
        "Version": "2021-06-01",
        "Statement": [
            {
                "Sid": "audit",
                "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                "Operation": {"Audit": {"FindingsDestination": {}}},
            },
            {
                "Sid": "redact",
                "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                "Operation": {"Deidentify": {"MaskConfig": {}}},
            },
        ],
    }
    logs.put_data_protection_policy(
        logGroupIdentifier=log_group, policyDocument=json.dumps(policy_document)
    )

    # The policy applies only to events ingested *after* it takes effect, and
    # activation is not instantaneous (eventual consistency). Poll by writing
    # fresh, uniquely-correlated events until one comes back masked, bounded.
    email_masked, seen_masked = _poll_until_masked(ctx, log_group, log_stream)

    logs.delete_data_protection_policy(logGroupIdentifier=log_group)

    # Deactivation on the ingest path is not instantaneous either -- symmetric to
    # _poll_until_masked above. A single write-then-read would return the FIRST
    # sighting of the correlator regardless of mask state, so a target that is
    # correctly-but-slowly eventually consistent would be scored as having failed
    # to unmask. Retry with a fresh, uniquely-correlated event each attempt until
    # one actually comes back unmasked, bounded.
    email_plain, message_plain = _poll_until_unmasked(ctx, log_group, log_stream)
    assert email_plain in message_plain, message_plain


def _poll_get_event_containing(ctx, log_group: str, log_stream: str, correlator: str, timeout_s: float = 60.0) -> str:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = logs.get_log_events(logGroupName=log_group, logStreamName=log_stream, startFromHead=True)
        for event in resp.get("events", []):
            if correlator in event["message"]:
                return event["message"]
        time.sleep(3)
    raise AssertionError(f"no event containing {correlator!r} appeared within {timeout_s}s")


def _poll_until_masked(ctx, log_group: str, log_stream: str, timeout_s: float = 120.0):
    """Repeatedly write a fresh event with a unique email and poll for it, until
    one comes back with the email redacted (policy activation is eventually
    consistent -- masking only applies to events ingested after activation
    completes). Returns (email_used, masked_message)."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        local_part = ctx.unique_name(f"sim2real-dpp-masked{attempt}").replace("_", "-")
        email = f"{local_part}@example.com"
        correlator = f"order=42-masked-{attempt}"
        message = f"contact email is {email}, {correlator}"
        logs.put_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": message}],
        )
        seen = _poll_get_event_containing(ctx, log_group, log_stream, correlator, timeout_s=20.0)
        if email not in seen and seen != message:
            return email, seen
        time.sleep(5)
    raise AssertionError(
        f"data protection policy never masked any event within {timeout_s}s (last seen: {seen!r})"
    )


def _poll_until_unmasked(ctx, log_group: str, log_stream: str, timeout_s: float = 120.0):
    """Mirror of _poll_until_masked: after DeleteDataProtectionPolicy, write a fresh
    event with a unique email each attempt until one comes back with the email intact
    (deletion's effect on the ingest path is eventually consistent too). Returns
    (email_used, message_used)."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    attempt = 0
    seen = None
    while time.monotonic() < deadline:
        attempt += 1
        local_part = ctx.unique_name(f"sim2real-dpp-plain{attempt}").replace("_", "-")
        email = f"{local_part}@example.com"
        correlator = f"order=43-plain-{attempt}"
        message = f"contact email is {email}, {correlator}"
        logs.put_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": message}],
        )
        seen = _poll_get_event_containing(ctx, log_group, log_stream, correlator, timeout_s=20.0)
        if seen == message:
            return email, message
        time.sleep(5)
    raise AssertionError(
        f"data protection policy deletion never unmasked any new event within {timeout_s}s "
        f"(last seen: {seen!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
