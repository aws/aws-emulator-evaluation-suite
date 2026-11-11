"""xsvc-cloudformation-2-drift-detection-status."""
# A detection emits TWO events: DETECTION_IN_PROGRESS (stack-drift-status "" and count -1) and
# DETECTION_COMPLETE. Both can carry the same second-granularity `time`, and SQS does not preserve
# their order, so nothing here asserts arrival order.
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudformation-2-drift-detection-status"
GROUP = "eventing"
SERVICES = ["cloudformation", "events", "sqs"]

DT = "CloudFormation Drift Detection Status Change"
STACK_TIMEOUT_S = 180.0
DETECT_TIMEOUT_S = 120.0
DELIVERY_TIMEOUT_S = 90.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:eventing", "concern:deploy",
      "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectStackDrift publishes IN_SYNC, then DRIFTED (one resource, VisibilityTimeout 30 -> 45) after
    an out-of-band SQS change, to EventBridge: a control rule receives both completions, and a rule
    matching only DRIFTED receives nothing for the IN_SYNC detection and then the DRIFTED event."""
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    stack_name = ctx.unique_name("sim2real-xsvc-drift-s-")
    stack_prefix = f"arn:aws:cloudformation:{ctx.region}:{account}:stack/{stack_name}/"

    # --- Same wiring twice: control (all drift events for the stack) and claim (DRIFTED only) ----
    # Created BEFORE the stack, so the rules have the whole stack-create time to become effective:
    # DETECTION_IN_PROGRESS is published the instant DetectStackDrift returns, and a rule created
    # just before that call measurably missed it. The prefix is unique because the name is.
    base = {"source": ["aws.cloudformation"], "detail-type": [DT]}
    control_q = _wired_queue(ctx, sqs, events, "ctl", dict(base, detail={
        "stack-id": [{"prefix": stack_prefix}]}))
    claim_q = _wired_queue(ctx, sqs, events, "drf", dict(base, detail={
        "stack-id": [{"prefix": stack_prefix}],
        "status-details": {"stack-drift-status": ["DRIFTED"]}}))

    # --- The subject stack: one SQS queue whose attribute we will later change out of band -------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Subject": {"Type": "AWS::SQS::Queue",
                                      "Properties": {"VisibilityTimeout": 30}}},
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _poll_stack(cfn, stack_id, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"})
    assert status == "CREATE_COMPLETE", f"stack {stack_name!r}: expected CREATE_COMPLETE, got {status!r}"
    subject_url = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Subject")[
        "StackResourceDetail"]["PhysicalResourceId"]
    assert stack_id.startswith(stack_prefix), (
        f"StackId {stack_id!r} must start with {stack_prefix!r} for the rules to match it"
    )

    # --- Phase 1: an untouched stack is IN_SYNC, and the control proves the pipe -----------------
    started = time.monotonic()
    first_id, first_status = _detect(cfn, stack_id)
    assert first_status["StackDriftStatus"] == "IN_SYNC", (
        f"first detection of an untouched stack: expected IN_SYNC, got {first_status!r}"
    )
    first = _drain_until(sqs, control_q, lambda evs: _by(evs, first_id, "DETECTION_COMPLETE")
                         and _by(evs, first_id, "DETECTION_IN_PROGRESS"),
                         why=f"IN_PROGRESS + COMPLETE events for detection {first_id!r}")
    latency_s = time.monotonic() - started
    done = _by(first, first_id, "DETECTION_COMPLETE")
    _assert_envelope(done, stack_id, account, ctx.region)
    assert done["detail"]["status-details"]["stack-drift-status"] == "IN_SYNC", (
        f"control COMPLETE event: expected stack-drift-status 'IN_SYNC', got {done['detail']!r}"
    )
    assert done["detail"]["drift-detection-details"]["drifted-stack-resource-count"] == 0, (
        f"IN_SYNC event must report 0 drifted resources, got {done['detail']!r}"
    )
    pending = _by(first, first_id, "DETECTION_IN_PROGRESS")
    assert pending["detail"]["status-details"]["stack-drift-status"] == "", (
        f"IN_PROGRESS event carries no verdict yet: expected stack-drift-status '', got "
        f"{pending['detail']!r}"
    )
    assert pending["detail"]["drift-detection-details"]["drifted-stack-resource-count"] == -1, (
        f"IN_PROGRESS event: expected drifted-stack-resource-count -1, got {pending['detail']!r}"
    )

    # Barrier passed: the same two IN_SYNC-detection events were evaluated against the claim rule.
    stray = _drain_for(sqs, claim_q, seconds=max(2.0 * latency_s, 20.0))
    assert not stray, (
        f"the claim rule matches only stack-drift-status DRIFTED, but an IN_SYNC stack delivered "
        f"{len(stray)} event(s) to it: {[e.get('detail') for e in stray]!r}"
    )

    # --- Phase 2: modify the deployed queue through SQS, outside CloudFormation ------------------
    sqs.set_queue_attributes(QueueUrl=subject_url, Attributes={"VisibilityTimeout": "45"})
    second_id, second_status = _detect(cfn, stack_id)
    assert second_id != first_id, f"a new detection must mint a new id, got {second_id!r} twice"
    assert second_status["StackDriftStatus"] == "DRIFTED", (
        f"detection after an out-of-band change: expected DRIFTED, got {second_status!r}"
    )
    assert second_status["DriftedStackResourceCount"] == 1, (
        f"expected exactly 1 drifted resource, got {second_status!r}"
    )

    claimed = _drain_until(sqs, claim_q, lambda evs: _by(evs, second_id, "DETECTION_COMPLETE"),
                           why=f"DRIFTED event for detection {second_id!r} on the CLAIM queue")
    drifted = _by(claimed, second_id, "DETECTION_COMPLETE")
    _assert_envelope(drifted, stack_id, account, ctx.region)
    assert drifted["detail"]["status-details"]["stack-drift-status"] == "DRIFTED", (
        f"claim event: expected stack-drift-status 'DRIFTED', got {drifted['detail']!r}"
    )
    assert drifted["detail"]["drift-detection-details"]["drifted-stack-resource-count"] == 1, (
        f"DRIFTED event must report 1 drifted resource, got {drifted['detail']!r}"
    )
    wrong = [e["detail"] for e in claimed
             if e["detail"]["status-details"]["stack-drift-status"] != "DRIFTED"]
    assert not wrong, f"the claim queue received non-DRIFTED events: {wrong!r}"

    ctl = _drain_until(sqs, control_q, lambda evs: _by(evs, second_id, "DETECTION_COMPLETE"),
                       why=f"DRIFTED event for detection {second_id!r} on the CONTROL queue")
    assert _by(ctl, second_id, "DETECTION_COMPLETE")["detail"]["status-details"][
        "stack-drift-status"] == "DRIFTED", f"control queue saw a different verdict: {ctl!r}"

    # The event's verdict names the change we made, read back from the drift record.
    diffs = [d for d in cfn.describe_stack_resource_drifts(
        StackName=stack_id, StackResourceDriftStatusFilters=["MODIFIED"])["StackResourceDrifts"]]
    assert [d["LogicalResourceId"] for d in diffs] == ["Subject"], (
        f"expected only 'Subject' MODIFIED, got {[d['LogicalResourceId'] for d in diffs]!r}"
    )
    props = {p["PropertyPath"]: (p["ExpectedValue"], p["ActualValue"])
             for p in diffs[0]["PropertyDifferences"]}
    assert props.get("/VisibilityTimeout") == ("30", "45"), (
        f"expected /VisibilityTimeout 30 -> 45 in the drift record, got {props!r}"
    )


def _assert_envelope(event: dict, stack_id: str, account: str, region: str) -> None:
    assert event["source"] == "aws.cloudformation", f"source: got {event['source']!r}"
    assert event["detail-type"] == DT, f"detail-type: got {event['detail-type']!r}"
    assert event["account"] == account, f"account: expected {account!r}, got {event['account']!r}"
    assert event["region"] == region, f"region: expected {region!r}, got {event['region']!r}"
    assert event["resources"] == [stack_id], (
        f"resources: expected [{stack_id!r}], got {event['resources']!r}"
    )
    assert event["detail"]["stack-id"] == stack_id, (
        f"detail.stack-id: expected {stack_id!r}, got {event['detail'].get('stack-id')!r}"
    )


def _detect(cfn, stack_id: str) -> tuple[str, dict]:
    did = cfn.detect_stack_drift(StackName=stack_id)["StackDriftDetectionId"]
    deadline = time.monotonic() + DETECT_TIMEOUT_S
    while time.monotonic() < deadline:
        st = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=did)
        if st["DetectionStatus"] != "DETECTION_IN_PROGRESS":
            assert st["DetectionStatus"] == "DETECTION_COMPLETE", (
                f"detection {did!r}: expected DETECTION_COMPLETE, got {st['DetectionStatus']!r} "
                f"({st.get('DetectionStatusReason')!r})"
            )
            return did, st
        time.sleep(3.0)
    raise AssertionError(f"drift detection {did!r} still in progress after {DETECT_TIMEOUT_S}s")


def _by(events_seen: list[dict], detection_id: str, detection_status: str) -> dict | None:
    for e in events_seen:
        d = e.get("detail", {})
        if (d.get("stack-drift-detection-id") == detection_id
                and d.get("status-details", {}).get("detection-status") == detection_status):
            return e
    return None


def _wired_queue(ctx, sqs, events, label: str, pattern: dict) -> str:
    """One SQS queue fed by one EventBridge rule on the default bus; both torn down LIFO."""
    queue_url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-xsvc-drift-{label}-"),
                                 tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: sqs.delete_queue(QueueUrl=queue_url)))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    rule = ctx.unique_name(f"sim2real-xsvc-drift-{label}-")
    rule_arn = events.put_rule(Name=rule, State="ENABLED", EventPattern=json.dumps(pattern),
                               Tags=[{"Key": "sim2real", "Value": CHECK}])["RuleArn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: events.delete_rule(Name=rule)))
    ctx.on_cleanup(lambda: _ignore_missing(lambda: events.remove_targets(Rule=rule, Ids=["q"])))
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": queue_arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}],
    })})
    put = events.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": queue_arn}])
    assert put["FailedEntryCount"] == 0, f"PutTargets {label!r}: expected 0 failures, got {put!r}"
    return queue_url


def _receive(sqs, queue_url: str) -> list[dict]:
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                               VisibilityTimeout=30)
    out = []
    for msg in resp.get("Messages", []):
        out.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _drain_until(sqs, queue_url: str, want, *, why: str) -> list[dict]:
    """Accumulate events until want(events); RAISES on timeout."""
    deadline = time.monotonic() + DELIVERY_TIMEOUT_S
    seen: list[dict] = []
    while time.monotonic() < deadline:
        seen.extend(_receive(sqs, queue_url))
        if want(seen):
            return seen
    raise AssertionError(
        f"queue never yielded [{why}] within {DELIVERY_TIMEOUT_S}s; got {len(seen)} events: "
        f"{[e.get('detail') for e in seen]!r}"
    )


def _drain_for(sqs, queue_url: str, *, seconds: float) -> list[dict]:
    """Drain for a window calibrated by the caller against the measured control latency."""
    deadline = time.monotonic() + seconds
    seen: list[dict] = []
    while time.monotonic() < deadline:
        seen.extend(_receive(sqs, queue_url))
    return seen


def _poll_stack(cfn, stack_id: str, terminal: set[str]) -> str:
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(4.0)
    raise AssertionError(f"stack {stack_id!r} not in {sorted(terminal)!r} after "
                         f"{STACK_TIMEOUT_S}s (last={last!r})")


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete and wait, so the stack-owned queue is gone before the run reports clean."""
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + STACK_TIMEOUT_S
    while time.monotonic() < deadline:
        st = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if st == "DELETE_COMPLETE":
            return
        if st == "DELETE_FAILED":
            raise RuntimeError(f"stack {stack_id} DELETE_FAILED")
        time.sleep(4.0)
    raise RuntimeError(f"stack {stack_id} not deleted within {STACK_TIMEOUT_S}s")


def _ignore_missing(fn) -> None:
    """Teardown helper: tolerate a resource already gone, and nothing else."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in {"ResourceNotFoundException", "AWS.SimpleQueueService.NonExistentQueue"}:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
