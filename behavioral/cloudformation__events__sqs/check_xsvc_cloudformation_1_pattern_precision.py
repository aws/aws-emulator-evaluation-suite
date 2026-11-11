"""xsvc-cloudformation-1-pattern-precision."""
# Three default-bus rules watch the SAME stacks (one stack-id prefix only this run can occupy):
#   main     — Resource + Stack Status Change      (positive control and the latency reference)
#   complete — Stack Status Change, status CREATE_COMPLETE only
#   drift    — Drift Detection Status Change only
# On AWS a failing create delivers ~15 events to `main` and
# nothing to the other two; a succeeding create delivers exactly one event to `complete`; and
# DetectStackDrift delivers DETECTION_IN_PROGRESS and DETECTION_COMPLETE (carrying stack-id) to
# `drift`. Each near-miss queue is therefore proven reachable by the same run that proves it quiet.
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudformation-1-pattern-precision"
GROUP = "eventing"
SERVICES = ["cloudformation", "events", "sqs"]

STACK_TIMEOUT_S = 420.0
DELIVERY_TIMEOUT_S = 120.0
MIN_QUIET_S = 20.0
_RESOURCE_DT = "CloudFormation Resource Status Change"
_STACK_DT = "CloudFormation Stack Status Change"
_DRIFT_DT = "CloudFormation Drift Detection Status Change"


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:eventing",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """EventBridge delivers CloudFormation events only to rules whose pattern matches: a rolled-back
    create reaches only the broad rule, a successful create the CREATE_COMPLETE rule, and only a
    DetectStackDrift the drift rule; each quiet queue is then shown reachable.
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    ident = ctx.client("sts").get_caller_identity()
    partition = ident["Arn"].split(":")[1]

    base = ctx.unique_name("sim2real-xsvc-cfn1-pp-")
    prefix = f"arn:{partition}:cloudformation:{ctx.region}:{ident['Account']}:stack/{base}-"
    scope = {"stack-id": [{"prefix": prefix}]}

    # Every queue is proven LIVE by one canary before the subject act (see _eb_channels), so an
    # empty near-miss queue below cannot be an unwired one.
    q = _eb_channels(ctx, events, sqs, ident, {
        "main": {"source": ["aws.cloudformation"], "detail-type": [_RESOURCE_DT, _STACK_DT],
                 "detail": dict(scope)},
        "complete": {"source": ["aws.cloudformation"], "detail-type": [_STACK_DT],
                     "detail": {**scope, "status-details": {"status": ["CREATE_COMPLETE"]}}},
        "drift": {"source": ["aws.cloudformation"], "detail-type": [_DRIFT_DT], "detail": dict(scope)},
    })
    seen = {k: [] for k in q}

    # --- Phase 1: a create that fails and rolls back -------------------------------------------
    failing = f"{base}-f"
    t0 = time.monotonic()
    f_id = cfn.create_stack(
        StackName=failing,
        TemplateBody=_failing_template("/" + failing),
        ClientRequestToken=ctx.unique_name("sim2real-xsvc-cfn1-ft-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=f_id))
    assert f_id.startswith(prefix), f"StackId {f_id!r} is outside the rules' prefix {prefix!r}"
    status = _poll_status(cfn, f_id, why="failing create")
    assert status == "ROLLBACK_COMPLETE", f"failing create: expected ROLLBACK_COMPLETE, got {status!r}"
    _drain_until(sqs, q["main"], seen["main"],
                 want=lambda evs: _has(evs, _STACK_DT, "ROLLBACK_COMPLETE", f_id)
                 and _has(evs, _RESOURCE_DT, "CREATE_FAILED", f_id),
                 why="positive control: main rule receives CREATE_FAILED and ROLLBACK_COMPLETE")
    latency = time.monotonic() - t0
    window = max(2.0 * latency, MIN_QUIET_S)
    _drain_for(sqs, q, seen, ["complete", "drift"], seconds=window)
    assert not seen["complete"], (
        f"no status of a rolled-back create matches status CREATE_COMPLETE, yet the CREATE_COMPLETE rule "
        f"received {[_brief(e) for e in seen['complete']]!r} within {window:.0f}s"
    )
    assert not seen["drift"], (
        f"no drift detection ran, yet the drift rule received {[_brief(e) for e in seen['drift']]!r} "
        f"within {window:.0f}s (main-path latency {latency:.1f}s)"
    )

    # --- Phase 2: a create that succeeds — the CREATE_COMPLETE rule must now receive -----------
    good = f"{base}-g"
    t1 = time.monotonic()
    g_id = cfn.create_stack(
        StackName=good,
        TemplateBody=_good_template("/" + good),
        ClientRequestToken=ctx.unique_name("sim2real-xsvc-cfn1-gt-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=g_id))
    status = _poll_status(cfn, g_id, why="good create")
    assert status == "CREATE_COMPLETE", f"good create: expected CREATE_COMPLETE, got {status!r}"
    _drain_until(sqs, q["main"], seen["main"],
                 want=lambda evs: _has(evs, _STACK_DT, "CREATE_COMPLETE", g_id),
                 why="main rule receives the good stack's CREATE_COMPLETE")
    _drain_until(sqs, q["complete"], seen["complete"],
                 want=lambda evs: _has(evs, _STACK_DT, "CREATE_COMPLETE", g_id),
                 why="CREATE_COMPLETE rule receives the good stack's CREATE_COMPLETE")
    window = max(2.0 * (time.monotonic() - t1), MIN_QUIET_S)
    _drain_for(sqs, q, seen, ["complete", "drift"], seconds=window)
    off = [e for e in seen["complete"]
           if not (e.get("detail-type") == _STACK_DT and _status(e) == "CREATE_COMPLETE" and e["detail"]["stack-id"] == g_id)]
    assert not off, (
        f"the CREATE_COMPLETE rule may receive only the good stack's CREATE_COMPLETE; it also got "
        f"{[_brief(e) for e in off]!r}"
    )
    assert len({e["id"] for e in seen["complete"]}) == 1, (
        f"exactly one distinct CREATE_COMPLETE event is expected; got ids {sorted({e['id'] for e in seen['complete']})!r}"
    )
    assert not seen["drift"], (
        f"two full stack lifecycles later, still no drift detection ran, yet the drift rule received "
        f"{[_brief(e) for e in seen['drift']]!r}"
    )

    # --- Phase 3: close the loop — a real DetectStackDrift must reach the drift rule ----------------
    detection_id = cfn.detect_stack_drift(StackName=g_id)["StackDriftDetectionId"]
    _drain_until(sqs, q["drift"], seen["drift"],
                 want=lambda evs: any(e["detail"].get("stack-drift-detection-id") == detection_id
                                      and e["detail"].get("status-details", {}).get("detection-status") == "DETECTION_COMPLETE"
                                      for e in evs),
                 why="drift rule receives DETECTION_COMPLETE for the detection this check started")
    done = [e for e in seen["drift"] if e["detail"].get("stack-drift-detection-id") == detection_id
            and e["detail"]["status-details"].get("detection-status") == "DETECTION_COMPLETE"][0]
    assert done["detail-type"] == _DRIFT_DT, f"drift event detail-type: got {done['detail-type']!r}"
    assert done["detail"]["stack-id"] == g_id, (
        f"drift event stack-id: expected {g_id!r}, got {done['detail']['stack-id']!r}"
    )
    assert done["detail"]["status-details"].get("stack-drift-status") == "IN_SYNC", (
        f"an untouched stack must report stack-drift-status IN_SYNC; got {done['detail']['status-details']!r}"
    )
    # ...and the broad rule, which lists two detail-types, must not have picked the drift event up.
    _drain_for(sqs, q, seen, ["main"], seconds=MIN_QUIET_S)
    drift_in_main = [e for e in seen["main"] if e.get("detail-type") == _DRIFT_DT]
    assert not drift_in_main, (
        f"the main rule does not list {_DRIFT_DT!r}, yet received {[_brief(e) for e in drift_in_main]!r}"
    )


# ===== helpers =====

_CANARY_SOURCE = "sim2real.canary"
_CANARY_MARK = "sim2real.canary "
WARMUP_TIMEOUT_S = 120.0


def _queue_with_policy(ctx, sqs, ident, prefix: str, principal: str, source_arns: list[str]) -> tuple[str, str]:
    """Create a queue whose send policy is set IN CreateQueue, not by a later SetQueueAttributes.

    Measured: a policy set right before the subject act propagates eventually, and EventBridge
    deliveries refused meanwhile were retried with backoff — 10 of 15 events had not arrived 120 s
    later. The ARN is deterministic, so the policy can name it before the queue exists.
    """
    name = ctx.unique_name(prefix)
    arn = f"arn:{ident['Arn'].split(':')[1]}:sqs:{ctx.region}:{ident['Account']}:{name}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": principal},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": source_arns}},
        }],
    }
    url = sqs.create_queue(
        QueueName=name, Attributes={"Policy": json.dumps(policy)}, tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: sqs.delete_queue(QueueUrl=url)))
    real = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    assert real == arn, f"setup: queue ARN {real!r} differs from the ARN its policy names {arn!r}"
    return url, arn


def _put_rule(ctx, events, name: str, pattern: dict, targets: list[dict]) -> str:
    rule_arn = events.put_rule(
        Name=name, State="ENABLED", EventPattern=json.dumps(pattern),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: events.delete_rule(Name=name)))
    ctx.on_cleanup(lambda: _ignore_missing(
        lambda: events.remove_targets(Rule=name, Ids=[t["Id"] for t in targets])))
    resp = events.put_targets(Rule=name, Targets=targets)
    assert resp["FailedEntryCount"] == 0, f"PutTargets on {name!r} failed: {resp!r}"
    return rule_arn


def _eb_channels(ctx, events, sqs, ident, patterns: dict[str, dict]) -> dict[str, str]:
    """One default-bus rule -> queue per pattern, plus ONE canary rule targeting every queue.

    The canary is a bounded warm-up barrier on an observable condition: the subject act starts only
    once a canary PutEvents has actually landed in every queue, so a delivery path that is not yet
    live cannot masquerade as a dropped (or a correctly withheld) CloudFormation event.
    """
    partition = ident["Arn"].split(":")[1]
    rule_arn = lambda n: f"arn:{partition}:events:{ctx.region}:{ident['Account']}:rule/{n}"  # noqa: E731
    canary_rule = ctx.unique_name("sim2real-xsvc-cfn1-canary-")
    canary_id = ctx.unique_name("canary-")
    urls: dict[str, str] = {}
    arns: dict[str, str] = {}
    for key, pattern in patterns.items():
        rule = ctx.unique_name(f"sim2real-xsvc-cfn1-{key}-")
        urls[key], arns[key] = _queue_with_policy(
            ctx, sqs, ident, f"sim2real-xsvc-cfn1-{key}-", "events.amazonaws.com",
            [rule_arn(rule), rule_arn(canary_rule)],
        )
        made = _put_rule(ctx, events, rule, pattern, [{"Id": "q", "Arn": arns[key]}])
        assert made == rule_arn(rule), f"setup: rule ARN {made!r} != predicted {rule_arn(rule)!r}"
    _put_rule(
        ctx, events, canary_rule,
        {"source": [_CANARY_SOURCE], "detail": {"run": [canary_id]}},
        [{"Id": key, "Arn": arn} for key, arn in arns.items()],
    )
    pending = set(urls)
    deadline = time.monotonic() + WARMUP_TIMEOUT_S
    next_put = 0.0
    while pending and time.monotonic() < deadline:
        if time.monotonic() >= next_put:
            resp = events.put_events(Entries=[{
                "Source": _CANARY_SOURCE, "DetailType": "sim2real canary",
                "Detail": json.dumps({"run": canary_id}),
            }])
            assert resp["FailedEntryCount"] == 0, f"canary PutEvents failed: {resp!r}"
            next_put = time.monotonic() + 15.0
        for key in sorted(pending):
            got = sqs.receive_message(QueueUrl=urls[key], MaxNumberOfMessages=10, WaitTimeSeconds=1)
            for msg in got.get("Messages", []):
                sqs.delete_message(QueueUrl=urls[key], ReceiptHandle=msg["ReceiptHandle"])
                if _is_canary(msg["Body"]):
                    pending.discard(key)
    assert not pending, (
        f"warm-up: the EventBridge->SQS path never delivered a canary to {sorted(pending)!r} within "
        f"{WARMUP_TIMEOUT_S}s, so the wiring under test is not live"
    )
    return urls


def _is_canary(body: str) -> bool:
    if body.startswith(_CANARY_MARK):
        return True
    try:
        doc = json.loads(body)
    except ValueError:
        return False
    return isinstance(doc, dict) and doc.get("source") == _CANARY_SOURCE



def _failing_template(base: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "First": {"Type": "AWS::SSM::Parameter",
                      "Properties": {"Name": f"{base}/first", "Type": "String", "Value": "ok"}},
            "Middle": {"Type": "AWS::SSM::Parameter", "DependsOn": "First",
                       "Properties": {"Name": f"{base}/middle", "Type": "String",
                                      "AllowedPattern": "^[0-9]+$", "Value": "not-digits"}},
            "Last": {"Type": "AWS::SSM::Parameter", "DependsOn": "Middle",
                     "Properties": {"Name": f"{base}/last", "Type": "String", "Value": "ok"}},
        },
    })


def _good_template(base: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"P": {"Type": "AWS::SSM::Parameter",
                            "Properties": {"Name": f"{base}/p", "Type": "String", "Value": "ok"}}},
    })




def _poll_status(cfn, stack_id: str, *, why: str) -> str:
    """Bounded poll to a non-IN_PROGRESS status; RAISES on timeout."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not last.endswith("_IN_PROGRESS"):
            return last
        time.sleep(3.0)
    raise AssertionError(f"stack {stack_id!r} still {last!r} after {STACK_TIMEOUT_S}s [{why}]")


def _receive_into(sqs, url: str, seen: list, wait_s: int = 2) -> None:
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s, VisibilityTimeout=60)
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if not _is_canary(msg["Body"]):
            seen.append(json.loads(msg["Body"]))


def _drain_until(sqs, url: str, seen: list, *, want, why: str) -> None:
    """Accumulate into `seen` until want(seen); RAISES on timeout."""
    deadline = time.monotonic() + DELIVERY_TIMEOUT_S
    while time.monotonic() < deadline:
        _receive_into(sqs, url, seen)
        if want(seen):
            return
    raise AssertionError(f"queue never yielded [{why}] within {DELIVERY_TIMEOUT_S}s; got {[_brief(e) for e in seen][:12]!r}")


def _drain_for(sqs, q: dict, seen: dict, keys: list[str], *, seconds: float) -> None:
    """Drain the queues named by `keys` for a window the caller calibrated against MEASURED latency."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for key in keys:
            _receive_into(sqs, q[key], seen[key], wait_s=1)


def _status(e: dict) -> str | None:
    return e.get("detail", {}).get("status-details", {}).get("status")


def _has(evs: list[dict], detail_type: str, status: str, stack_id: str) -> bool:
    return any(e.get("detail-type") == detail_type and _status(e) == status
               and e["detail"].get("stack-id") == stack_id for e in evs)


def _brief(e: dict) -> tuple:
    d = e.get("detail", {})
    return (e.get("detail-type"), d.get("logical-resource-id"), _status(e) or d.get("status-details"))


def _ignore_missing(fn) -> None:
    """Teardown helper: tolerate a resource already gone, and nothing else."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in {"ResourceNotFoundException", "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"}:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
