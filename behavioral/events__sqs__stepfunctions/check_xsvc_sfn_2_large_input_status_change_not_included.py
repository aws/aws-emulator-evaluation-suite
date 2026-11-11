"""xsvc-sfn-2-large-input-status-change-not-included."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-2-large-input-status-change-not-included"
GROUP = "event-propagation"
SERVICES = ["events", "stepfunctions", "sqs"]

_SOURCE = "aws.states"
_DETAIL_TYPE = "Step Functions Execution Status Change"
_EVENT_WAIT_S = 150.0
_RELAUNCH_EVERY_S = 45.0
_LARGE_BYTES = 250 * 1024

_DEFINITION = {
    "Comment": "sim2real xsvc-sfn-2 large input",
    "StartAt": "Done",
    "States": {"Done": {"Type": "Pass", "End": True}},
}


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """An execution with a ~250 KiB input is announced on the default bus with input and output
    elided (null, inputDetails/outputDetails {"included": false}) while a small-input twin carries
    both inline; DescribeExecution still returns the full large input."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role(
        ctx, "states.amazonaws.com",
        {"Effect": "Deny", "Action": "states:SendTaskSuccess", "Resource": "*"},
    )
    sm_arn = _create_state_machine(ctx, _xname(ctx, "sm")[:80], _DEFINITION, role_arn)
    q_events = _create_queue(ctx)
    _rule_to_queue(
        ctx, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE], "detail": {"stateMachineArn": [sm_arn]}},
        q_events,
    )

    tok = ctx.unique_name("t")[-12:]
    inputs = {"small": {"size": "small", "token": tok}, "large": {"size": "large", "token": tok, "blob": ""}}
    inputs["large"]["blob"] = "x" * (_LARGE_BYTES - len(json.dumps(inputs["large"])))
    assert len(json.dumps(inputs["large"])) == _LARGE_BYTES

    # Both twins launched together, relaunched together, until the bus has delivered a RUNNING and
    # a SUCCEEDED event for each kind (a default-bus rule is not live the instant PutRule returns).
    launched: dict[str, str] = {}
    sink: list[dict] = []
    want = {(k, st) for k in inputs for st in ("RUNNING", "SUCCEEDED")}

    def _seen() -> dict:
        out: dict = {}
        for b in sink:
            kind = launched.get(b["detail"]["executionArn"])
            if kind:
                out.setdefault((kind, b["detail"]["status"]), b["detail"])
        return out

    t0 = time.monotonic()
    last = float("-inf")
    while time.monotonic() - t0 < _EVENT_WAIT_S and not want <= set(_seen()):
        if time.monotonic() - last > _RELAUNCH_EVERY_S:
            for kind, inp in inputs.items():
                arn = sfn.start_execution(stateMachineArn=sm_arn, name=_xname(ctx, kind)[:80],
                                          input=json.dumps(inp))["executionArn"]
                launched[arn] = kind
            last = time.monotonic()
        _drain_once(ctx, q_events["url"], sink)
    seen = _seen()
    assert want <= set(seen), (
        f"within {_EVENT_WAIT_S:.0f}s the bus must deliver RUNNING and SUCCEEDED for both the small "
        f"and the large execution; saw {sorted(seen)!r}"
    )

    for status in ("RUNNING", "SUCCEEDED"):
        small, large = seen[("small", status)], seen[("large", status)]
        assert small["inputDetails"] == {"included": True} and json.loads(small["input"]) == inputs["small"], (
            f"the small twin's {status} event must carry its input inline with included=true; got "
            f"inputDetails {small.get('inputDetails')!r}, input {str(small.get('input'))[:120]!r}"
        )
        assert large["inputDetails"] == {"included": False}, (
            f"the ~250 KiB execution's {status} event must mark its input as not included; got "
            f"inputDetails {large.get('inputDetails')!r}"
        )
        assert large.get("input") is None, (
            f"the ~250 KiB execution's {status} event must not carry the input; got "
            f"{len(large['input'])} characters"
        )
        for d in (small, large):
            assert d["stateMachineAliasArn"] is None and d["stateMachineVersionArn"] is None, (
                f"an execution started on the unqualified machine ARN has no alias/version; got "
                f"{(d.get('stateMachineAliasArn'), d.get('stateMachineVersionArn'))!r}"
            )

    small_ok, large_ok = seen[("small", "SUCCEEDED")], seen[("large", "SUCCEEDED")]
    assert small_ok["outputDetails"] == {"included": True} and json.loads(small_ok["output"]) == inputs["small"], (
        f"the small twin's SUCCEEDED event must carry its Pass output inline; got outputDetails "
        f"{small_ok.get('outputDetails')!r}, output {str(small_ok.get('output'))[:120]!r}"
    )
    assert large_ok["outputDetails"] == {"included": False} and large_ok.get("output") is None, (
        f"the large execution's SUCCEEDED event must elide its ~250 KiB output; got outputDetails "
        f"{large_ok.get('outputDetails')!r}, output length "
        f"{None if large_ok.get('output') is None else len(large_ok['output'])}"
    )
    # The event elides the input; the execution keeps it.
    described = sfn.describe_execution(executionArn=large_ok["executionArn"])
    assert described["inputDetails"] == {"included": True} and json.loads(described["input"]) == inputs["large"], (
        f"DescribeExecution must return the full {_LARGE_BYTES}-byte input; got inputDetails "
        f"{described.get('inputDetails')!r}, input length {len(described.get('input') or '')}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _tolerate(fn, *tolerated: str, leak: str = "") -> None:
    """Run a teardown call. With a leak label, an error code outside `tolerated` is reported as a
    leak; without one, a refused teardown call is ignored."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if leak and code not in tolerated:
            raise RuntimeError(f"{leak}: {code}") from exc


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll until predicate holds; RAISE on timeout (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_role(ctx, principal: str, statement: dict) -> str:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]

    def _delete(n=name):
        _tolerate(lambda: iam.delete_role_policy(RoleName=n, PolicyName="inline"))
        _tolerate(lambda: iam.delete_role(RoleName=n), "NoSuchEntity", leak=f"could not delete role {n}")

    ctx.on_cleanup(_delete)
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
    )
    return arn


def _create_state_machine(ctx, name: str, definition: dict, role_arn: str) -> str:
    """Create the machine, retrying only through the IAM role-propagation window."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 90
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": k, "value": v} for k, v in _TAGS.items()],
            )["stateMachineArn"]
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if last != "AccessDeniedException":
                raise
            time.sleep(3)
            continue

        def _delete(a=arn):
            _tolerate(lambda: sfn.delete_state_machine(stateMachineArn=a), "StateMachineDoesNotExist", leak=f"could not delete state machine {a}")

        ctx.on_cleanup(_delete)
        return arn
    raise AssertionError(
        f"CreateStateMachine({name}) never succeeded within the IAM role-propagation window; "
        f"last error code {last!r}"
    )


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _xname(ctx, "q")[:80]
    url = sqs.create_queue(QueueName=name, tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _rule_to_queue(ctx, pattern: dict, queue: dict) -> str:
    """A rule on the DEFAULT bus (where AWS service events land) with this queue as sole target."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")[:64]
    arn = events.put_rule(
        Name=name, EventPattern=json.dumps(pattern),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["RuleArn"]

    def _teardown(n=name):
        _tolerate(lambda: events.remove_targets(Rule=n, Ids=["q"], Force=True), "ResourceNotFoundException", leak=f"could not remove target from rule {n}")
        _tolerate(lambda: events.delete_rule(Name=n, Force=True), "ResourceNotFoundException", leak=f"could not delete rule {n}")

    ctx.on_cleanup(_teardown)
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={"Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                           "Action": "sqs:SendMessage", "Resource": queue["arn"],
                           "Condition": {"ArnEquals": {"aws:SourceArn": arn}}}],
        })},
    )
    ctx.client("events").put_targets(Rule=name, Targets=[{"Id": "q", "Arn": queue["arn"]}])
    return arn


def _drain_once(ctx, url: str, sink: list) -> list:
    """One long-poll receive; every Step Functions status-change body is appended to sink."""
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        body = json.loads(msg["Body"])
        if body.get("source") == _SOURCE and body.get("detail-type") == _DETAIL_TYPE:
            sink.append(body)
    return sink


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
