"""data-protection-audit-findings-delivered-to-the-findings-destination."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "data-protection-audit-findings-delivered-to-the-findings-destination"
GROUP = 'data-protection'
SERVICES = ['logs']

_EMAIL = "jane.doe@example.com"
_MASKED_MARKER = "*"
_SENSITIVE_PREFIX = "login attempt from user "
_IDENTIFIER_ARN = "arn:aws:dataprotection::aws:data-identifier/EmailAddress"


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


def _policy_document(name, destination_group):
    return json.dumps(
        {
            "Name": name,
            "Version": "2021-06-01",
            "Statement": [
                {
                    "Sid": "audit-email",
                    "DataIdentifier": [_IDENTIFIER_ARN],
                    "Operation": {
                        "Audit": {
                            "FindingsDestination": {
                                "CloudWatchLogs": {"LogGroup": destination_group}
                            }
                        }
                    },
                },
                {
                    "Sid": "mask-email",
                    "DataIdentifier": [_IDENTIFIER_ARN],
                    "Operation": {"Deidentify": {"MaskConfig": {}}},
                },
            ],
        }
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A data-protection Audit statement delivers a finding naming EmailAddress, without the raw
    value, to the findings log group, while the Deidentify statement masks the source event.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data.html
    """
    svc = ctx.client("logs")

    # The destination is created FIRST, so it exists before any finding can be routed to
    # it, and its cleanup is registered first -- which means LIFO deletes it LAST, after
    # the source group and its policy are gone and no further findings can arrive.
    destination = ctx.unique_name("sim2real-behav-lg-findings-")
    svc.create_log_group(logGroupName=destination, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=destination: svc.delete_log_group(logGroupName=_n))

    source = ctx.unique_name("sim2real-behav-lg-audited-")
    svc.create_log_group(logGroupName=source, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=source: svc.delete_log_group(logGroupName=_n))
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_stream(logGroupName=source, logStreamName=stream)

    policy_name = ctx.unique_name("sim2real-behav-dpp-audit-")
    svc.put_data_protection_policy(
        logGroupIdentifier=source,
        policyDocument=_policy_document(policy_name, destination),
    )
    ctx.on_cleanup(
        lambda _n=source: svc.delete_data_protection_policy(logGroupIdentifier=_n)
    )

    # Detection happens at INGEST and PutDataProtectionPolicy returns before the ingest
    # path is necessarily using the policy, so a canary in a throwaway stream is the only
    # reliable barrier: once it comes back masked, the policy is live for both halves.
    canary_stream = ctx.unique_name("sim2real-behav-canary-")
    svc.create_log_stream(logGroupName=source, logStreamName=canary_stream)

    def _canary():
        svc.put_log_events(
            logGroupName=source,
            logStreamName=canary_stream,
            logEvents=[{"timestamp": _now_ms(), "message": f"canary {_EMAIL} canary"}],
        )
        resp = svc.get_log_events(
            logGroupName=source, logStreamName=canary_stream, startFromHead=True
        )
        return [e["message"] for e in resp.get("events", [])]

    _poll_until(
        _canary,
        lambda msgs: any(_EMAIL not in m and _MASKED_MARKER in m for m in msgs),
        timeout_s=180,
        interval_s=5.0,
        description="the data protection policy becomes live on the ingest path",
    )

    sensitive = f"{_SENSITIVE_PREFIX}{_EMAIL} failed"
    benign = f"{_SENSITIVE_PREFIX}with no address failed"
    base = _now_ms()
    svc.put_log_events(
        logGroupName=source,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base, "message": sensitive},
            {"timestamp": base + 1000, "message": benign},
        ],
    )

    def _findings():
        """Every event of the destination group that parses as JSON (a finding is a JSON document)."""
        out = []
        token = None
        while True:
            kwargs = {"logGroupName": destination}
            if token is not None:
                kwargs["nextToken"] = token
            page = svc.filter_log_events(**kwargs)
            for event in page.get("events", []):
                try:
                    out.append(json.loads(event["message"]))
                except ValueError:
                    continue
            token = page.get("nextToken")
            if not token:
                break
        return out

    started = time.monotonic()
    findings = _poll_until(
        _findings,
        lambda fs: len(fs) > 0,
        timeout_s=240,
        interval_s=10.0,
        description=(
            "an audit finding is delivered to the findings destination log group"
        ),
    )
    elapsed = time.monotonic() - started

    naming_the_identifier = [f for f in findings if "EmailAddress" in json.dumps(f)]
    assert naming_the_identifier, (
        f"delivered findings did not name the detected identifier type EmailAddress: {findings!r} "
        f"(destination {destination!r}, delivery took {elapsed:.0f}s)"
    )
    finding = naming_the_identifier[0]

    assert _EMAIL not in json.dumps(finding), (
        f"the audit finding leaked the raw identifier it detected: {finding!r} -- a findings report "
        "must DESCRIBE the detection, not reproduce the secret (delivery took "
        f"{elapsed:.0f}s)"
    )

    # The Deidentify half, on the same event that produced the finding: audit and mask
    # are two statements over one ingestion and both must have fired.
    def _source_messages():
        resp = svc.get_log_events(
            logGroupName=source, logStreamName=stream, startFromHead=True
        )
        return [e["message"] for e in resp.get("events", [])]

    stored = _poll_until(
        _source_messages,
        lambda msgs: len(msgs) == 2,
        timeout_s=90,
        interval_s=3.0,
        description="both source events are readable",
    )
    assert _EMAIL not in stored[0], (
        f"the Deidentify statement did not mask the source event: {stored[0]!r}"
    )
    assert stored[0].startswith(_SENSITIVE_PREFIX), (
        f"only the matched data identifier may be redacted, got {stored[0]!r}"
    )
    assert stored[1] == benign, (
        f"an event containing no matched identifier must be stored verbatim, got {stored[1]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
