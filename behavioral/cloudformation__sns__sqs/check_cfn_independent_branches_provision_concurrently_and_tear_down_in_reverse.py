"""cfn-independent-branches-provision-concurrently-and-tear-down-in-reverse."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-independent-branches-provision-concurrently-and-tear-down-in-reverse"

GROUP = "deploy_scheduler"

SERVICES = ["cloudformation", "sns", "sqs"]

# After both branch heads are seen CREATE_IN_PROGRESS the check holds them open for HOLD_S of
# monotonic time before signalling either, so the true overlap is >= HOLD_S and OVERLAP_FLOOR_S
# carries a ~4x margin.
HOLD_S = 20.0
OVERLAP_FLOOR_S = 5.0
# CloudFormation stamps the ready-set pick and the last dependency's completion from one clock,
# so the only error term is its millisecond granularity; 1s absorbs a same-second pair.
SLACK_S = 1.0


def _template() -> str:
    """A diamond: two independent branches (Gate -> Queue -> Sub) joining at one QueuePolicy.

    Each Gate is a WaitCondition only this check signals, so a serial engine deadlocks on the gate
    it picked first and rolls back on the PT10M ResourceSignal timeout.
    """
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "QA": {"Type": "String"},
            "QB": {"Type": "String"},
            "TopicN": {"Type": "String"},
        },
        "Resources": {
            "GateA": {
                "Type": "AWS::CloudFormation::WaitCondition",
                "CreationPolicy": {"ResourceSignal": {"Timeout": "PT10M", "Count": 1}},
            },
            "GateB": {
                "Type": "AWS::CloudFormation::WaitCondition",
                "CreationPolicy": {"ResourceSignal": {"Timeout": "PT10M", "Count": 1}},
            },
            "QueueA": {
                "Type": "AWS::SQS::Queue",
                "DependsOn": "GateA",
                "Properties": {"QueueName": {"Ref": "QA"}, "VisibilityTimeout": 30},
            },
            "QueueB": {
                "Type": "AWS::SQS::Queue",
                "DependsOn": "GateB",
                "Properties": {"QueueName": {"Ref": "QB"}, "VisibilityTimeout": 30},
            },
            "Fanout": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"TopicName": {"Ref": "TopicN"}},
            },
            "SubA": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "Protocol": "sqs",
                    "TopicArn": {"Ref": "Fanout"},
                    "Endpoint": {"Fn::GetAtt": ["QueueA", "Arn"]},
                    "RawMessageDelivery": True,
                },
            },
            "SubB": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "Protocol": "sqs",
                    "TopicArn": {"Ref": "Fanout"},
                    "Endpoint": {"Fn::GetAtt": ["QueueB", "Arn"]},
                    "RawMessageDelivery": True,
                },
            },
            "JoinPolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "DependsOn": ["SubA", "SubB"],
                "Properties": {
                    "Queues": [{"Ref": "QueueA"}, {"Ref": "QueueB"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": "*",
                            "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Fanout"}}},
                        }],
                    },
                },
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Fanout"}},
            "UrlA": {"Value": {"Ref": "QueueA"}},
            "UrlB": {"Value": {"Ref": "QueueB"}},
        },
    })


_NO_SUCH_QUEUE = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")

_NO_SUCH_TOPIC = ("NotFound", "Topic does not exist")


def _error_code(fn):
    """The botocore (Code, Message) fn() raises. Raises AssertionError if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("call unexpectedly succeeded; expected it to raise a ClientError")


def _stack_events(cfn, stack: str) -> list[dict[str, Any]]:
    """Every event for a stack, oldest first, paginated (both phases overrun one page)."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page.get("StackEvents", []))
        token = page.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _stack_resources(cfn, stack: str) -> list[dict[str, Any]]:
    """Every resource CloudFormation records for a stack, paginated."""
    out: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack}
        if token:
            kwargs["NextToken"] = token
        page = cfn.list_stack_resources(**kwargs)
        out.extend(page.get("StackResourceSummaries", []))
        token = page.get("NextToken")
        if not token:
            return out


def _stamp(events, logical: str, status: str, *, reason_initiated: bool | None, pick) -> float:
    """The epoch seconds of one lifecycle stamp for one logical id.

    CloudFormation emits two CREATE_IN_PROGRESS events per resource: one with no reason (picked off
    the ready set) and one reading "Resource creation Initiated"; reason_initiated picks one.
    """
    hits = []
    for e in events:
        if e.get("LogicalResourceId") != logical or e.get("ResourceStatus") != status:
            continue
        initiated = "Resource creation Initiated" in (e.get("ResourceStatusReason") or "")
        if reason_initiated is None or initiated == reason_initiated:
            hits.append(e["Timestamp"].timestamp())
    assert hits, (
        f"no {status} event for {logical!r} with reason_initiated={reason_initiated!r}; the events "
        f"recorded were {[(e.get('LogicalResourceId'), e.get('ResourceStatus'), (e.get('ResourceStatusReason') or '')[:40]) for e in events]!r}"
    )
    return pick(hits)


def _sched(events, logical: str) -> float:
    """When the scheduler picked `logical` off the ready set."""
    return _stamp(events, logical, "CREATE_IN_PROGRESS", reason_initiated=False, pick=min)


def _done(events, logical: str) -> float:
    return _stamp(events, logical, "CREATE_COMPLETE", reason_initiated=None, pick=max)


def _delstart(events, logical: str) -> float:
    return _stamp(events, logical, "DELETE_IN_PROGRESS", reason_initiated=None, pick=min)


def _deldone(events, logical: str) -> float:
    return _stamp(events, logical, "DELETE_COMPLETE", reason_initiated=None, pick=max)


def _resource_status(cfn, stack: str, logical: str) -> str:
    """The current ResourceStatus of one logical id, or a named absence."""
    try:
        return cfn.describe_stack_resource(
            StackName=stack, LogicalResourceId=logical
        )["StackResourceDetail"]["ResourceStatus"]
    except ClientError as exc:
        return f"ABSENT({exc.response.get('Error', {}).get('Code')})"


def _poll_until(ctx, probe, predicate, what: str, timeout_s=1200.0, interval_s=2.0):
    """Poll probe() until predicate(result); return the last result. AssertionError on timeout.

    The deadline is capped by the run's remaining budget so a slow target fails with this message.
    """
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} not observed within {timeout_s}s (last observation: {last!r})")


def _wait_stack_status(ctx, cfn, stack: str, targets: set[str], timeout_s=1200.0) -> dict[str, Any]:
    def probe():
        try:
            return cfn.describe_stacks(StackName=stack)["Stacks"][0]
        except ClientError:
            return None

    return _poll_until(
        ctx,
        probe,
        lambda s: s is not None and s.get("StackStatus") in targets,
        f"stack {stack!r} reaching one of {sorted(targets)}",
        timeout_s=timeout_s,
        interval_s=2.0,
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c5", "concern:deploy", "concern:e2e",
      "concern:eventing", "concern:data-plane", "plane:control", "plane:data", "dp:api")
def run(ctx) -> None:
    """CloudFormation creates a diamond's independent branches concurrently, starts the join only
    after all its predecessors, tears down in reverse topological order, and the fan-out works.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    name = ctx.unique_name("sim2real-behav-cfn-diamond-")
    qa = ctx.unique_name("sim2real-behav-diamond-a-")
    qb = ctx.unique_name("sim2real-behav-diamond-b-")
    topic_name = ctx.unique_name("sim2real-behav-diamond-t-")

    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=_template(),
        Parameters=[
            {"ParameterKey": "QA", "ParameterValue": qa},
            {"ParameterKey": "QB", "ParameterValue": qb},
            {"ParameterKey": "TopicN", "ParameterValue": topic_name},
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    # Registered before the first assertion: DeleteStack is idempotent, so the in-band delete
    # below leaves this a no-op, and any early failure still tears the diamond down.
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))

    # --- the parallelism gate: BOTH heads in progress in the SAME poll -----------------------
    def both_gates():
        return {g: _resource_status(cfn, stack_id, g) for g in ("GateA", "GateB")}

    observed = _poll_until(
        ctx,
        both_gates,
        lambda st: st["GateA"] == "CREATE_IN_PROGRESS" and st["GateB"] == "CREATE_IN_PROGRESS",
        "GateA and GateB both CREATE_IN_PROGRESS in one poll -- a serial engine never shows this, "
        "it blocks on the gate it picked first",
        timeout_s=300.0,
    )
    assert observed == {"GateA": "CREATE_IN_PROGRESS", "GateB": "CREATE_IN_PROGRESS"}, (
        f"poll that was supposed to show both gates in flight reported {observed!r}"
    )

    # Hold both gates open for HOLD_S of monotonic time, re-reading them so neither may close
    # unsignalled; a pace-capped sleep cannot shorten the overlap this way.
    hold_end = time.monotonic() + HOLD_S
    while time.monotonic() < hold_end:
        time.sleep(2.0)
        held = both_gates()
        assert held == {"GateA": "CREATE_IN_PROGRESS", "GateB": "CREATE_IN_PROGRESS"}, (
            f"an unsignalled gate left CREATE_IN_PROGRESS during the hold: {held!r}"
        )
    cfn.signal_resource(
        StackName=stack_id, LogicalResourceId="GateA",
        UniqueId="sim2real-behav-diamond-gate-a", Status="SUCCESS",
    )

    # Branch A's TAIL must start while branch B is still open, or the engine serialized whole
    # branches. Gate the GateB signal on that observation so assertion 3 cannot be a race.
    def tail_a_and_open_b():
        return {
            "QueueA": _resource_status(cfn, stack_id, "QueueA"),
            "GateB": _resource_status(cfn, stack_id, "GateB"),
        }

    tail = _poll_until(
        ctx,
        tail_a_and_open_b,
        lambda st: st["QueueA"] == "CREATE_COMPLETE" and st["GateB"] == "CREATE_IN_PROGRESS",
        "QueueA CREATE_COMPLETE while the held GateB is still CREATE_IN_PROGRESS -- an engine that "
        "finishes one whole branch before starting the other never shows this",
        timeout_s=300.0,
    )
    assert tail["GateB"] == "CREATE_IN_PROGRESS", (
        f"GateB was {tail['GateB']!r} when branch A's tail started; it must still be open"
    )

    cfn.signal_resource(
        StackName=stack_id, LogicalResourceId="GateB",
        UniqueId="sim2real-behav-diamond-gate-b", Status="SUCCESS",
    )

    stack = _wait_stack_status(
        ctx, cfn, stack_id, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    )
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"diamond stack ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )

    create_events = _stack_events(cfn, stack_id)
    graph = ["GateA", "GateB", "QueueA", "QueueB", "Fanout", "SubA", "SubB", "JoinPolicy"]
    sched = {r: _sched(create_events, r) for r in graph}
    done = {r: _done(create_events, r) for r in graph}

    # 1. the two independent branch heads were in flight at once (also seen live in one poll above)
    overlap = min(done["GateA"], done["GateB"]) - max(sched["GateA"], sched["GateB"])
    assert overlap >= OVERLAP_FLOOR_S, (
        f"GateA and GateB overlapped for only {overlap:.3f}s (floor {OVERLAP_FLOOR_S}s, held "
        f"{HOLD_S}s before signalling): sched={ {k: sched[k] for k in ('GateA', 'GateB')} !r} "
        f"done={ {k: done[k] for k in ('GateA', 'GateB')} !r}"
    )
    # 2. a DependsOn child is not scheduled before its parent completes
    for child, parent in (("QueueA", "GateA"), ("QueueB", "GateB")):
        assert sched[child] >= done[parent] - SLACK_S, (
            f"{child} was scheduled {done[parent] - sched[child]:.3f}s BEFORE its DependsOn "
            f"parent {parent} completed"
        )

    # 3. branch A's tail advanced while branch B was still open
    assert sched["QueueA"] < done["GateB"], (
        f"QueueA was scheduled at {sched['QueueA']!r}, after GateB completed at "
        f"{done['GateB']!r} -- the engine serialized whole branches instead of overlapping them"
    )

    # 4. the join waited on ALL its predecessors, not just the first-listed one
    preds = {r: done[r] for r in ("SubA", "SubB", "QueueA", "QueueB")}
    assert sched["JoinPolicy"] >= max(preds.values()) - SLACK_S, (
        f"JoinPolicy was scheduled at {sched['JoinPolicy']!r} before its predecessors finished "
        f"({preds!r}) -- DependsOn:[SubA,SubB] plus the Ref edges to both queues must all gate it"
    )

    # 5. the join is the last thing to finish; a template-order engine finishes Fanout last
    latest = max(done, key=lambda r: done[r])
    assert latest == "JoinPolicy", (
        f"the last resource to complete was {latest!r} at {done[latest]!r}, not the join "
        f"JoinPolicy at {done['JoinPolicy']!r}: done={done!r}"
    )

    # 6. negative space: exactly the eight logical ids, no extras
    ids = {r["LogicalResourceId"] for r in _stack_resources(cfn, stack_id)}
    assert ids == set(graph), f"stack records logical ids {sorted(ids)!r}, expected {sorted(graph)!r}"

    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    topic_arn, url_a, url_b = outputs["TopicArn"], outputs["UrlA"], outputs["UrlB"]

    # 7. data plane: the join resource is what made the fan-out work, not merely what was ordered
    marker = f"sim2real-diamond-{qa}"
    sns.publish(TopicArn=topic_arn, Message=marker)
    for label, url in (("UrlA", url_a), ("UrlB", url_b)):
        got = _poll_until(
            ctx,
            lambda url=url: sqs.receive_message(
                QueueUrl=url, WaitTimeSeconds=5, MaxNumberOfMessages=1
            ).get("Messages", []),
            lambda msgs: bool(msgs),
            f"a fan-out message on {label}",
            timeout_s=90.0,
            interval_s=1.0,
        )
        assert got[0]["Body"] == marker, (
            f"{label} received {got[0]['Body']!r}, expected the published marker {marker!r}"
        )

    # --- teardown IN BAND: the ordering assertions need the delete phase's events -------------
    cfn.delete_stack(StackName=stack_id)
    deleted = _wait_stack_status(ctx, cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert deleted["StackStatus"] == "DELETE_COMPLETE", (
        f"delete ended {deleted['StackStatus']!r}: {deleted.get('StackStatusReason')!r}"
    )

    del_events = _stack_events(cfn, stack_id)
    delstart = {r: _delstart(del_events, r) for r in graph}
    deldone = {r: _deldone(del_events, r) for r in graph}

    # 8. reverse topological teardown: the join dies before either branch's delete begins
    for branch in ("QueueA", "QueueB"):
        assert deldone["JoinPolicy"] <= delstart[branch], (
            f"{branch}'s delete began at {delstart[branch]!r}, "
            f"{delstart[branch] - deldone['JoinPolicy']:.3f}s relative to JoinPolicy's "
            f"DELETE_COMPLETE at {deldone['JoinPolicy']!r} -- the join must be gone first"
        )

    # 9. and the reverse order holds at every level of the graph, not just the top
    for sub, queue in (("SubA", "QueueA"), ("SubB", "QueueB")):
        assert deldone[sub] <= delstart[queue], (
            f"{queue}'s delete began at {delstart[queue]!r} before {sub} finished deleting at "
            f"{deldone[sub]!r}"
        )

    # 10. the two independent branches were torn down concurrently
    overlap_delete = (min(deldone["QueueA"], deldone["QueueB"])
                      - max(delstart["QueueA"], delstart["QueueB"]))
    assert overlap_delete >= 0.0, (
        f"QueueA and QueueB delete intervals did not overlap ({overlap_delete:.3f}s): "
        f"delstart={ {k: delstart[k] for k in ('QueueA', 'QueueB')} !r} "
        f"deldone={ {k: deldone[k] for k in ('QueueA', 'QueueB')} !r}"
    )

    # 11. effect-absent: everything the diamond built is really gone. DeleteQueue is asynchronous
    #     on the SQS side, so this is a bounded poll for the absence, not a single read.
    def _queue_state(queue_name: str) -> tuple:
        try:
            sqs.get_queue_url(QueueName=queue_name)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        return ("EXISTS", None)

    for label, queue_name in (("QueueA", qa), ("QueueB", qb)):
        code = _poll_until(
            ctx,
            lambda queue_name=queue_name: _queue_state(queue_name),
            lambda c: c[0] != "EXISTS",
            f"{label} reporting NonExistentQueue after DELETE_COMPLETE",
            timeout_s=180.0,
            interval_s=2.0,
        )
        assert code == _NO_SUCH_QUEUE, (
            f"{label} still resolves after the stack was deleted (GetQueueUrl -> {code!r})"
        )
    topic_code = _error_code(lambda: sns.get_topic_attributes(TopicArn=topic_arn))
    assert topic_code == _NO_SUCH_TOPIC, (
        f"the fan-out topic still exists after DELETE_COMPLETE (get_topic_attributes -> "
        f"{topic_code!r}, expected {_NO_SUCH_TOPIC!r})"
    )

    # 12. gone means unusable, not merely unlisted: a mutation against the dead id must also fail
    for label, url in (("UrlA", url_a), ("UrlB", url_b)):
        send_code = _error_code(
            lambda url=url: sqs.send_message(QueueUrl=url, MessageBody="sim2real-dead-id-probe")
        )
        assert send_code == _NO_SUCH_QUEUE, (
            f"SendMessage against deleted {label} returned {send_code!r}, expected "
            f"{_NO_SUCH_QUEUE!r}"
        )
    publish_code = _error_code(
        lambda: sns.publish(TopicArn=topic_arn, Message="sim2real-dead-id-probe")
    )
    assert publish_code == _NO_SUCH_TOPIC, (
        f"Publish against the deleted topic returned {publish_code!r}, expected {_NO_SUCH_TOPIC!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
