"""data-protection-policy-masks-sensitive-data-server-side."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "data-protection-policy-masks-sensitive-data-server-side"
GROUP = "server-side"
SERVICES = ["logs"]

_SENTINEL_EMAIL = "sim2real.behav.sentinel@example.com"
_MASKED_MARKER = "*"
_PREFIX = "user contact email is "
_SUFFIX = " for this ticket"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Once a log-group data protection policy is active, PutLogEvents containing
    a matching sensitive pattern are masked server-side; only an unmask=True read
    reveals the original value."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-dpmask-")
    stream = "sim2real-stream"
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    policy_doc = _dp_policy_doc("mask-test")
    logs.put_data_protection_policy(logGroupIdentifier=group, policyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _delete_dpp_best_effort(logs, group))

    message = f"{_PREFIX}{_SENTINEL_EMAIL}{_SUFFIX}"

    def _masked_candidate():
        ts = int(time.time() * 1000)
        logs.put_log_events(
            logGroupName=group,
            logStreamName=stream,
            logEvents=[{"timestamp": ts, "message": message}],
        )
        masked = logs.get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True, unmask=False
        )["events"]
        for e in masked:
            if _SENTINEL_EMAIL not in e["message"] and _MASKED_MARKER in e["message"]:
                return e["message"]
        return None

    deadline = time.monotonic() + 90.0
    masked_message = None
    while time.monotonic() < deadline:
        masked_message = _masked_candidate()
        if masked_message is not None:
            break
        time.sleep(5.0)
    assert masked_message is not None, (
        "sensitive email was never masked (raw value absent AND a mask marker "
        f"{_MASKED_MARKER!r} present) in plain GetLogEvents within the timeout"
    )
    assert masked_message.startswith(_PREFIX) and masked_message.endswith(_SUFFIX), (
        "masking must redact only the matched data identifier, leaving the surrounding "
        f"message intact, got {masked_message!r}"
    )

    unmasked = logs.get_log_events(
        logGroupName=group, logStreamName=stream, startFromHead=True, unmask=True
    )["events"]
    assert any(e["message"] == message for e in unmasked), (
        "expected GetLogEvents(unmask=True) to return the original, byte-identical "
        f"message, got {[e['message'] for e in unmasked]!r}"
    )


def _dp_policy_doc(name: str) -> dict:
    identifiers = ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"]
    return {
        "Name": name,
        "Version": "2021-06-01",
        "Statement": [
            {"Sid": "audit", "DataIdentifier": identifiers, "Operation": {"Audit": {"FindingsDestination": {}}}},
            {"Sid": "redact", "DataIdentifier": identifiers, "Operation": {"Deidentify": {"MaskConfig": {}}}},
        ],
    }


def _delete_dpp_best_effort(logs, group: str) -> None:
    try:
        logs.delete_data_protection_policy(logGroupIdentifier=group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
