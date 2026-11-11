"""express-and-standard-state-machine-targets-start-with-the-envelope-as-input-named-after-the-event-id."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "express-and-standard-state-machine-targets-start-with-the-envelope-as-input-named-after-the-event-id"
GROUP = "stepfunctions-target"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 180.0
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """One event on a rule with EXPRESS and STANDARD state machine targets starts one execution of
    each, whose input is exactly the envelope and whose name is `<event id>_<uuid>`, distinct per
    target.
    """
    events = ctx.client("events")
    sfn = ctx.client("stepfunctions")
    queue_url, queue_arn = _create_queue(ctx)

    sm_role = _role(ctx, "states.amazonaws.com", ["sqs:SendMessage"], [queue_arn])
    definition = json.dumps({"StartAt": "Report", "States": {"Report": {
        "Type": "Task", "Resource": "arn:aws:states:::sqs:sendMessage",
        "Parameters": {"QueueUrl": queue_url, "MessageBody": {
            "input.$": "$$.Execution.Input", "name.$": "$$.Execution.Name",
            "execution.$": "$$.Execution.Id", "machine.$": "$$.StateMachine.Name"}},
        "End": True}}})
    machines = {kind: _create_state_machine(ctx, sfn, definition, sm_role, kind)
                for kind in ("EXPRESS", "STANDARD")}
    names = {kind: arn.rsplit(":", 1)[1] for kind, arn in machines.items()}
    ev_role = _role(ctx, "events.amazonaws.com", ["states:StartExecution"], list(machines.values()))

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.sfn.")
    rule = _create_rule(ctx, events, bus, {"source": [source]})
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": "express", "Arn": machines["EXPRESS"], "RoleArn": ev_role},
        {"Id": "standard", "Arn": machines["STANDARD"], "RoleArn": ev_role},
    ])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    detail = {"order": ctx.unique_name("o-"), "qty": 2}
    sent: set[str] = set()
    reports: list[dict] = []

    def _complete() -> bool:
        return any({r["machine"] for r in reports if r["input"].get("id") == eid} == set(names.values())
                   for eid in sent)

    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    next_put = 0.0
    while time.monotonic() < deadline and not _complete():
        if time.monotonic() >= next_put:
            # A just-created rule (or a just-created role) can drop events until delivery is
            # live; re-publish fresh events until one reaches both machines.
            resp = events.put_events(Entries=[{"EventBusName": bus, "Source": source,
                                               "DetailType": "order.placed",
                                               "Detail": json.dumps(detail)}])
            assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
            sent.add(resp["Entries"][0]["EventId"])
            next_put = time.monotonic() + 20.0
        reports += _receive(ctx, queue_url)
    assert _complete(), (
        f"no single event started both state machines within {_DELIVERY_TIMEOUT_S}s; "
        f"{len(sent)} event(s) sent, reports from "
        f"{sorted({r['machine'] == names['EXPRESS'] and 'express' or 'standard' for r in reports})!r}"
    )
    event_id = next(eid for eid in sent
                    if {r["machine"] for r in reports if r["input"].get("id") == eid} == set(names.values()))
    by_kind = {kind: next(r for r in reports if r["input"].get("id") == event_id and r["machine"] == n)
               for kind, n in names.items()}

    for kind, rep in by_kind.items():
        env = rep["input"]
        assert sorted(env) == ["account", "detail", "detail-type", "id", "region", "resources",
                               "source", "time", "version"], (
            f"the {kind} execution input carries keys {sorted(env)!r}"
        )
        assert (env["source"], env["detail-type"], env["detail"], env["account"], env["region"],
                env["resources"]) == (source, "order.placed", detail, ctx.account, ctx.region, []), (
            f"the {kind} execution input is not the published envelope: {env!r}"
        )
        assert re.fullmatch(re.escape(event_id) + "_" + _UUID, rep["name"]), (
            f"the {kind} execution name must be '<event id>_<uuid>'; got one of length "
            f"{len(rep['name'])} starting with the event id: {rep['name'].startswith(event_id)!r}"
        )
    assert by_kind["EXPRESS"]["name"] != by_kind["STANDARD"]["name"], (
        "the two targets' executions of one event share a name"
    )
    express_id = by_kind["EXPRESS"]["execution"]
    assert express_id.startswith(
        f"arn:aws:states:{ctx.region}:{ctx.account}:express:{names['EXPRESS']}:"
        f"{by_kind['EXPRESS']['name']}:"), (
        f"the express execution id is not an express execution ARN of its machine and name "
        f"(prefix {express_id.split(':')[5]!r})"
    )
    std_arn = by_kind["STANDARD"]["execution"]
    assert std_arn == (f"arn:aws:states:{ctx.region}:{ctx.account}:execution:"
                       f"{names['STANDARD']}:{by_kind['STANDARD']['name']}"), (
        f"the standard execution id is not the execution ARN of its machine and name "
        f"(kind {std_arn.split(':')[5]!r})"
    )
    listed = set()
    for page in sfn.get_paginator("list_executions").paginate(stateMachineArn=machines["STANDARD"]):
        listed |= {e["name"] for e in page["executions"]}
    assert by_kind["STANDARD"]["name"] in listed, (
        f"ListExecutions on the standard machine does not list the execution that reported "
        f"itself; {len(listed)} execution(s) listed"
    )


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _role(ctx, principal: str, actions: list[str], resources: list[str]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="access", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": actions, "Resource": resources}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="access"))
    return arn


def _create_state_machine(ctx, sfn, definition: str, role_arn: str, kind: str) -> str:
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn,
                                           type=kind, tags=[{"key": "sim2real", "value": CHECK}])["stateMachineArn"]
            break
        except ClientError as exc:
            # A just-created role is not yet assumable by Step Functions; nothing to poll.
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _create_bus(ctx, events) -> str:
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    return bus


def _create_rule(ctx, events, bus: str, pattern: dict) -> str:
    name = ctx.unique_name("sim2real-behav-rule-")
    events.put_rule(Name=name, EventBusName=bus, EventPattern=json.dumps(pattern))

    def _delete() -> None:
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name, EventBusName=bus)["Targets"]]
        if ids:
            events.remove_targets(Rule=name, EventBusName=bus, Ids=ids)
        events.delete_rule(Name=name, EventBusName=bus)

    ctx.on_cleanup(_delete)
    return name


def _receive(ctx, url: str) -> list[dict]:
    sqs = ctx.client("sqs")
    out = []
    for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=5).get("Messages", []):
        out.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
