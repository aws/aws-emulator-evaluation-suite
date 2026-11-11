"""deploy-log-group-cfn-data-protection-policy-masks-events."""
from __future__ import annotations

import json
import sys
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-log-group-cfn-data-protection-policy-masks-events"
GROUP = "deploy"
SERVICES = ["logs"]

_EMAIL = "jane.doe.sim2real@example.com"
_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DataProtectionPolicy on a CFN AWS::Logs::LogGroup masks an email at ingest (unmask=True
    recovers it), leaves a benign event verbatim, and does not apply to a sibling group in the stack.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    protected = ctx.unique_name("sim2real-behav-logs-cfndpp-")
    control = ctx.unique_name("sim2real-behav-logs-cfndpp-ctl-")
    stream = ctx.unique_name("sim2real-behav-logs-cfndpp-s-")
    canary = ctx.unique_name("sim2real-behav-logs-cfndpp-c-")
    stack = ctx.unique_name("sim2real-behav-logs-cfndpp-")
    ident = "arn:aws:dataprotection::aws:data-identifier/EmailAddress"
    policy = {
        "Name": f"{CHECK}-policy",
        "Version": "2021-06-01",
        "Statement": [
            {"Sid": "audit", "DataIdentifier": [ident],
             "Operation": {"Audit": {"FindingsDestination": {}}}},
            {"Sid": "mask", "DataIdentifier": [ident],
             "Operation": {"Deidentify": {"MaskConfig": {}}}},
        ],
    }
    tag = [{"Key": "sim2real", "Value": CHECK}]
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Protected": {"Type": "AWS::Logs::LogGroup",
                          "Properties": {"LogGroupName": protected, "RetentionInDays": 1,
                                         "DataProtectionPolicy": policy, "Tags": tag}},
            "Control": {"Type": "AWS::Logs::LogGroup",
                        "Properties": {"LogGroupName": control, "RetentionInDays": 1, "Tags": tag}},
            "PStream": {"Type": "AWS::Logs::LogStream",
                        "Properties": {"LogGroupName": {"Ref": "Protected"}, "LogStreamName": stream}},
            "PCanary": {"Type": "AWS::Logs::LogStream",
                        "Properties": {"LogGroupName": {"Ref": "Protected"}, "LogStreamName": canary}},
            "CStream": {"Type": "AWS::Logs::LogStream",
                        "Properties": {"LogGroupName": {"Ref": "Control"}, "LogStreamName": stream}},
        },
    }
    stack_id = cfn.create_stack(StackName=stack, TemplateBody=json.dumps(template), Tags=tag)["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"

    got_policy = logs.get_data_protection_policy(logGroupIdentifier=protected)
    assert json.loads(got_policy.get("policyDocument") or "{}").get("Name") == policy["Name"], (
        f"the template's DataProtectionPolicy is not attached: {got_policy!r}"
    )

    # Masking applies at ingest and goes live some seconds after the policy lands; a canary in
    # a separate stream is the barrier, so the asserted events are never ingested pre-policy.
    def _canary_msgs():
        logs.put_log_events(logGroupName=protected, logStreamName=canary,
                            logEvents=[{"timestamp": int(time.time() * 1000),
                                        "message": f"canary {_EMAIL}"}])
        return _messages(logs, protected, canary)

    live = _poll(_canary_msgs, lambda ms: any(_EMAIL not in m and "*" in m for m in ms), 180, 5)
    assert any(_EMAIL not in m and "*" in m for m in live), (
        f"the CFN-declared policy never masked a canary within 180s: {live!r}"
    )

    sensitive = f"signup from {_EMAIL} accepted"
    benign = "signup from an anonymous user accepted"
    base = int(time.time() * 1000)
    for g in (protected, control):
        logs.put_log_events(logGroupName=g, logStreamName=stream,
                            logEvents=[{"timestamp": base, "message": sensitive},
                                       {"timestamp": base + 1, "message": benign}])

    masked = _poll(lambda: _messages(logs, protected, stream), lambda ms: len(ms) >= 2, 60, 2)
    assert len(masked) == 2 and _EMAIL not in masked[0] and "*" in masked[0], (
        f"protected group returned {masked!r}; the address must be masked"
    )
    assert masked[0].startswith("signup from ") and masked[0].endswith(" accepted"), (
        f"only the matched identifier may be redacted, got {masked[0]!r}"
    )
    assert masked[1] == benign, f"benign event was altered: {masked[1]!r}"

    unmasked = _messages(logs, protected, stream, unmask=True)
    assert unmasked == [sensitive, benign], (
        f"unmask=True returned {unmasked!r}, expected the original {[sensitive, benign]!r}"
    )
    plain = _poll(lambda: _messages(logs, control, stream), lambda ms: len(ms) >= 2, 60, 2)
    assert plain == [sensitive, benign], (
        f"control group (no policy, same stack) returned {plain!r}; it must be verbatim"
    )


def _messages(logs: Any, group: str, stream: str, **kw) -> list[str]:
    resp = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True, **kw)
    return [e["message"] for e in resp["events"]]


def _poll(fn, cond, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not cond(last) and time.monotonic() < deadline:
        time.sleep(interval_s)
        last = fn()
    return last


def _wait_stack(cfn: Any, stack_id: str, timeout_s: float = 900.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s}s")


def _teardown_stack(cfn: Any, stack_id: str) -> None:
    try:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status != "DELETE_COMPLETE":
            cfn.delete_stack(StackName=stack_id)
            status = _wait_stack(cfn, stack_id)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"{CHECK}: stack {stack_id} delete failed: {exc!r}") from exc
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"{CHECK}: stack {stack_id} ended {status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
