"""status-change-event-for-qualified-execution-carries-version-and-alias-arns."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "status-change-event-for-qualified-execution-carries-version-and-alias-arns"
GROUP = "event-propagation"
SERVICES = ["events", "sqs", "stepfunctions"]

_SOURCE = "aws.states"
_DETAIL_TYPE = "Step Functions Execution Status Change"
_EVENT_WAIT_S = 150.0
_RELAUNCH_EVERY_S = 45.0

_DEFINITION = {
    "Comment": "sim2real status-change qualified execution",
    "StartAt": "Done",
    "States": {"Done": {"Type": "Pass", "End": True}},
}


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A version- or alias-qualified start's status-change events carry the resolved
    stateMachineVersionArn and, for an alias start, stateMachineAliasArn too; an unqualified
    start keeps both null."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_states_role(ctx)
    sm_arn = _create_state_machine(ctx, _xname(ctx, "sm")[:80], _DEFINITION, role_arn)
    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]

    alias_name = _xname(ctx, "alias")[:80]
    alias_arn = sfn.create_state_machine_alias(
        name=alias_name,
        routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )["stateMachineAliasArn"]

    def _delete_alias(a=alias_arn):
        _tolerate(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=a),
                  "ResourceNotFound", leak=f"could not delete alias {a}")

    ctx.on_cleanup(_delete_alias)

    q_events = _create_queue(ctx)
    _rule_to_queue(
        ctx, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE], "detail": {"stateMachineArn": [sm_arn]}},
        q_events,
    )

    launched: dict[str, str] = {}
    sink: list[dict] = []
    want = {(k, "SUCCEEDED") for k in ("plain", "version", "alias")}

    def _seen() -> dict:
        out: dict = {}
        for b in sink:
            kind = launched.get(b["detail"]["executionArn"])
            if kind:
                out.setdefault((kind, b["detail"]["status"]), b["detail"])
        return out

    # Launched together, relaunched together, until the bus has delivered a SUCCEEDED event
    # for each start kind (a default-bus rule is not live the instant PutRule returns).
    t0 = time.monotonic()
    last = float("-inf")
    while time.monotonic() - t0 < _EVENT_WAIT_S and not want <= set(_seen()):
        if time.monotonic() - last > _RELAUNCH_EVERY_S:
            for kind, start_arn in (("plain", sm_arn), ("version", version_arn), ("alias", alias_arn)):
                arn = sfn.start_execution(stateMachineArn=start_arn, name=_xname(ctx, kind)[:80],
                                          input=json.dumps({"kind": kind}))["executionArn"]
                launched[arn] = kind
            last = time.monotonic()
        _drain_once(ctx, q_events["url"], sink)
    seen = _seen()
    assert want <= set(seen), (
        f"within {_EVENT_WAIT_S:.0f}s the bus must deliver SUCCEEDED for the plain, version "
        f"and alias starts; saw {sorted(seen)!r}"
    )

    plain, version_ev, alias_ev = seen[("plain", "SUCCEEDED")], seen[("version", "SUCCEEDED")], seen[("alias", "SUCCEEDED")]

    assert (plain["stateMachineVersionArn"], plain["stateMachineAliasArn"]) == (None, None), (
        f"an unqualified start must carry null version/alias arns; got "
        f"{(plain.get('stateMachineVersionArn'), plain.get('stateMachineAliasArn'))!r}"
    )
    assert version_ev["stateMachineVersionArn"] == version_arn, (
        f"a version-qualified start's event must carry stateMachineVersionArn {version_arn!r}; "
        f"got {version_ev.get('stateMachineVersionArn')!r}"
    )
    assert version_ev["stateMachineAliasArn"] is None, (
        f"a version-qualified start has no alias; got stateMachineAliasArn "
        f"{version_ev.get('stateMachineAliasArn')!r}"
    )
    assert alias_ev["stateMachineAliasArn"] == alias_arn, (
        f"an alias-qualified start's event must carry stateMachineAliasArn {alias_arn!r}; "
        f"got {alias_ev.get('stateMachineAliasArn')!r}"
    )
    assert alias_ev["stateMachineVersionArn"] == version_arn, (
        f"an alias-qualified start's event must also carry the version the alias routed it "
        f"to, {version_arn!r}; got {alias_ev.get('stateMachineVersionArn')!r}"
    )

    # DescribeExecution of the execution each captured event names agrees with that event.
    for kind, ev in (("plain", plain), ("version", version_ev), ("alias", alias_ev)):
        described = sfn.describe_execution(executionArn=ev["executionArn"])
        assert described.get("stateMachineVersionArn") == ev["stateMachineVersionArn"], (
            f"{kind}: DescribeExecution stateMachineVersionArn {described.get('stateMachineVersionArn')!r} "
            f"disagrees with the event's {ev['stateMachineVersionArn']!r}"
        )
        assert described.get("stateMachineAliasArn") == ev["stateMachineAliasArn"], (
            f"{kind}: DescribeExecution stateMachineAliasArn {described.get('stateMachineAliasArn')!r} "
            f"disagrees with the event's {ev['stateMachineAliasArn']!r}"
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


def _create_states_role(ctx) -> str:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]

    def _delete(n=name):
        _tolerate(lambda: iam.delete_role(RoleName=n), "NoSuchEntity", leak=f"could not delete role {n}")

    ctx.on_cleanup(_delete)
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
            time.sleep(2)
            continue

        def _delete(a=arn):
            _tolerate(lambda: sfn.delete_state_machine(stateMachineArn=a), "StateMachineDoesNotExist",
                      leak=f"could not delete state machine {a}")

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
        _tolerate(lambda: events.remove_targets(Rule=n, Ids=["q"], Force=True),
                  "ResourceNotFoundException", leak=f"could not remove target from rule {n}")
        _tolerate(lambda: events.delete_rule(Name=n, Force=True),
                  "ResourceNotFoundException", leak=f"could not delete rule {n}")

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
    events.put_targets(Rule=name, Targets=[{"Id": "q", "Arn": queue["arn"]}])
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
