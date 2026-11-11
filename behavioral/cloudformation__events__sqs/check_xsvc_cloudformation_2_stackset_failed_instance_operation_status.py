"""xsvc-cloudformation-2-stackset-failed-instance-operation-status."""
# Field names below are those AWS emits on real events. For a template whose resource fails to
# create, AWS emits Operation Status Change RUNNING then FAILED for the CreateStackInstances
# OperationId, and StackSet StackInstance Status Change status OUTDATED / detailed-status FAILED
# whose status-reason equals ListStackInstances' StatusReason and names the failing logical resource
# ("ResourceLogicalId:<id>, ..."). The failure is a WaitCondition nobody signals (Timeout 1): an SSM
# AllowedPattern mismatch can hang in its handler for minutes, so it is not a reliable trigger.
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudformation-2-stackset-failed-instance-operation-status"
GROUP = "eventing"
SERVICES = ["cloudformation", "events", "sqs"]

DT_SET = "CloudFormation StackSet Status Change"
DT_OP = "CloudFormation StackSet Operation Status Change"
DT_INST = "CloudFormation StackSet StackInstance Status Change"
OP_TIMEOUT_S = 240.0
DELIVERY_TIMEOUT_S = 90.0
IAM_PROPAGATION_S = 60.0
IAM_RETRY_S = 300.0


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:eventing", "concern:deploy",
      "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A StackSet instance that fails to create reports FAILED on EventBridge and never reaches a
    SUCCEEDED-only rule, while the later SUCCEEDED DELETE operation on the same set does reach it.
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    set_name = ctx.unique_name("sim2real-xsvc-ssbad-")
    arn_prefix = f"arn:aws:cloudformation:{region}:{account}:stackset/{set_name}:"

    # CONTROL matches every StackSet event for this set; CLAIM only SUCCEEDED operations. A later
    # SUCCEEDED DELETE on the claim queue is the contrast that makes its silence meaningful.
    control_q = _wired_queue(ctx, sqs, events, "ctl", {
        "source": ["aws.cloudformation"], "detail-type": [DT_SET, DT_OP, DT_INST],
        "detail": {"stack-set-arn": [{"prefix": arn_prefix}]}})
    claim_q = _wired_queue(ctx, sqs, events, "ok", {
        "source": ["aws.cloudformation"], "detail-type": [DT_OP],
        "detail": {"stack-set-arn": [{"prefix": arn_prefix}],
                   "status-details": {"status": ["SUCCEEDED"]}}})

    admin_arn, exec_name = _stackset_roles(ctx, iam)

    set_id = cfn.create_stack_set(
        StackSetName=set_name,
        TemplateBody=json.dumps({"Resources": {
            "H": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "W": {"Type": "AWS::CloudFormation::WaitCondition",
                  "Properties": {"Handle": {"Ref": "H"}, "Timeout": "1"}}}}),
        PermissionModel="SELF_MANAGED", AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_name, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackSetId"]
    ctx.on_cleanup(lambda: _teardown_set(cfn, set_name, account, region))
    set_arn = f"arn:aws:cloudformation:{region}:{account}:stackset/{set_id}"

    seen = _drain_until(ctx, sqs, control_q, lambda evs: _set_event(evs, "ACTIVE"),
                        why="StackSet Status Change ACTIVE after CreateStackSet (pipe control)")
    _assert_envelope(_set_event(seen, "ACTIVE"), set_arn, account, region)

    # --- The failing deployment ----------------------------------------------------------------
    op_id, op = _create_instances_with_iam_retry(ctx, cfn, set_name, account, region)
    retry_ops = op.get("RetryUndoOps", [])
    assert op["Status"] == "FAILED", (
        f"CreateStackInstances {op_id!r} with a template whose resource cannot be created: "
        f"expected operation FAILED, got {op['Status']!r} ({op!r})"
    )
    inst = cfn.list_stack_instances(StackSetName=set_name)["Summaries"]
    assert len(inst) == 1, f"expected exactly 1 stack instance, got {inst!r}"
    assert inst[0]["StackInstanceStatus"]["DetailedStatus"] == "FAILED", (
        f"instance DetailedStatus: expected FAILED, got {inst[0]!r}"
    )
    assert inst[0]["Status"] == "OUTDATED", f"instance Status: expected OUTDATED, got {inst[0]!r}"
    reason = inst[0]["StatusReason"]
    assert "ResourceLogicalId:W" in reason and "WaitCondition timed out" in reason, (
        f"the instance must fail on the template's WaitCondition W, not on wiring; reason={reason!r}"
    )
    instance_stack = inst[0]["StackId"]

    seen += _drain_until(
        ctx, sqs, control_q,
        lambda evs: _op_event(seen + evs, op_id, "RUNNING") and _op_event(seen + evs, op_id, "FAILED")
        and _inst_event(seen + evs, instance_stack, "FAILED"),
        why=f"operation {op_id!r} RUNNING + FAILED and its instance FAILED")
    running = _op_event(seen, op_id, "RUNNING")
    failed = _op_event(seen, op_id, "FAILED")
    for e in (running, failed):
        _assert_envelope(e, set_arn, account, region)
        assert e["detail"]["action"] == "CREATE", f"expected action CREATE, got {e['detail']!r}"
    assert running["time"] <= failed["time"], (
        f"RUNNING ({running['time']!r}) must not be later than FAILED ({failed['time']!r})"
    )
    inst_failed = _inst_event(seen, instance_stack, "FAILED")
    _assert_envelope(inst_failed, set_arn, account, region)
    assert inst_failed["detail"]["status-details"]["status"] == "OUTDATED", (
        f"a FAILED instance must be OUTDATED, got {inst_failed['detail']!r}"
    )
    assert inst_failed["detail"]["status-details"]["status-reason"] == reason, (
        f"event status-reason must equal ListStackInstances StatusReason {reason!r}; got "
        f"{inst_failed['detail']['status-details'].get('status-reason')!r}"
    )
    success_for_op = [e for e in seen if e.get("detail-type") == DT_OP
                      and e["detail"]["stack-set-operation-id"] == op_id
                      and e["detail"]["status-details"]["status"] == "SUCCEEDED"]
    assert not success_for_op, f"a FAILED operation also reported SUCCEEDED: {success_for_op!r}"

    # --- Contrast: a later SUCCEEDED operation on the same set DOES reach the claim queue; ------
    # nothing from the failed operation may arrive before it.
    del_id = cfn.delete_stack_instances(StackSetName=set_name, Accounts=[account],
                                        Regions=[region], RetainStacks=False)["OperationId"]
    del_op = _wait_op(ctx, cfn, set_name, del_id)
    assert del_op["Status"] == "SUCCEEDED", f"DeleteStackInstances {del_id!r}: got {del_op!r}"
    claimed = _drain_until(ctx, sqs, claim_q, lambda evs: _op_event(evs, del_id, "SUCCEEDED"),
                           why=f"DELETE operation {del_id!r} SUCCEEDED on the CLAIM queue")
    closed = _op_event(claimed, del_id, "SUCCEEDED")
    _assert_envelope(closed, set_arn, account, region)
    assert closed["detail"]["action"] == "DELETE", f"expected action DELETE, got {closed['detail']!r}"
    for_op = [e["detail"] for e in claimed if e["detail"].get("stack-set-operation-id") == op_id]
    assert not for_op, (
        f"the claim rule matches only SUCCEEDED, but failed operation {op_id!r} delivered {for_op!r}"
    )
    unexplained = [e["detail"] for e in claimed
                   if e["detail"].get("stack-set-operation-id") not in [*retry_ops, del_id]]
    assert not unexplained, f"the claim queue received unexpected events: {unexplained!r}"


def _deadline(ctx, seconds: float) -> float:
    """A monotonic deadline of `seconds`, capped by the run's remaining budget (no cap for None)."""
    left = None if ctx is None else ctx.time_left()
    return time.monotonic() + (seconds if left is None else min(seconds, left))


def _assert_envelope(event: dict, set_arn: str, account: str, region: str) -> None:
    assert event["source"] == "aws.cloudformation", f"source: got {event['source']!r}"
    assert event["account"] == account, f"account: expected {account!r}, got {event['account']!r}"
    assert event["region"] == region, f"region: expected {region!r}, got {event['region']!r}"
    assert event["resources"] == [set_arn], (
        f"resources: expected [{set_arn!r}], got {event['resources']!r}"
    )
    assert event["detail"]["stack-set-arn"] == set_arn, (
        f"detail.stack-set-arn: expected {set_arn!r}, got {event['detail'].get('stack-set-arn')!r}"
    )


def _set_event(evs: list[dict], status: str) -> dict | None:
    for e in evs:
        if e.get("detail-type") == DT_SET and e["detail"]["status-details"]["status"] == status:
            return e
    return None


def _op_event(evs: list[dict], op_id: str, status: str) -> dict | None:
    for e in evs:
        d = e.get("detail", {})
        if (e.get("detail-type") == DT_OP and d.get("stack-set-operation-id") == op_id
                and d["status-details"]["status"] == status):
            return e
    return None


def _inst_event(evs: list[dict], stack_id: str, detailed: str) -> dict | None:
    for e in evs:
        d = e.get("detail", {})
        if (e.get("detail-type") == DT_INST and d.get("stack-id") == stack_id
                and d["status-details"].get("detailed-status") == detailed):
            return e
    return None


def _stackset_roles(ctx, iam) -> tuple[str, str]:
    """SELF_MANAGED needs an administration role (trusted by CloudFormation) that may assume an
    execution role in the target account. Both are created here; the account's default-named
    AWSCloudFormationStackSet* roles are never relied on."""
    admin = ctx.unique_name("sim2real-xsvc-ssadm-")
    execr = ctx.unique_name("sim2real-xsvc-ssexe-")
    admin_arn = iam.create_role(RoleName=admin, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, admin))
    iam.put_role_policy(RoleName=admin, PolicyName="assume-exec", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                       "Resource": f"arn:aws:iam::*:role/{execr}"}]}))
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": admin_arn}, "Action": "sts:AssumeRole"}]})
    # First use of the new admin ARN is as a trust principal: retry, to a deadline, on the one
    # error a not-yet-propagated principal produces.
    deadline = _deadline(ctx, IAM_PROPAGATION_S)
    while True:
        try:
            iam.create_role(RoleName=execr, AssumeRolePolicyDocument=trust)
            break
        except ClientError as exc:
            if (exc.response["Error"]["Code"] != "MalformedPolicyDocument"
                    or time.monotonic() >= deadline):
                raise
            time.sleep(2.0)
    ctx.on_cleanup(lambda: _delete_role(iam, execr))
    iam.put_role_policy(RoleName=execr, PolicyName="deploy", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["cloudformation:*", "ssm:*", "sns:*", "s3:*"],
                       "Resource": "*"}]}))
    return admin_arn, execr


def _create_instances_with_iam_retry(ctx, cfn, set_name: str, account: str, region: str):
    """CreateStackInstances is the first use of the roles. An instance that failed for a reason
    that names no template resource is IAM propagation: undo it and retry, to a deadline."""
    undone: list[str] = []
    deadline = _deadline(ctx, IAM_RETRY_S)
    while True:
        op_id = cfn.create_stack_instances(
            StackSetName=set_name, Accounts=[account], Regions=[region],
            OperationPreferences={"FailureToleranceCount": 0, "MaxConcurrentCount": 1},
        )["OperationId"]
        op = _wait_op(ctx, cfn, set_name, op_id)
        if op["Status"] == "SUCCEEDED":
            return op_id, dict(op, RetryUndoOps=undone)
        reasons = [s.get("StatusReason", "") for s in
                   cfn.list_stack_instances(StackSetName=set_name)["Summaries"]]
        if time.monotonic() >= deadline or any("ResourceLogicalId" in r for r in reasons):
            return op_id, dict(op, InstanceReasons=reasons, RetryUndoOps=undone)
        undo = cfn.delete_stack_instances(StackSetName=set_name, Accounts=[account],
                                          Regions=[region], RetainStacks=False)["OperationId"]
        undone.append(undo)
        _wait_op(ctx, cfn, set_name, undo)
        time.sleep(2.0)


def _wait_op(ctx, cfn, set_name: str, op_id: str) -> dict:
    deadline = _deadline(ctx, OP_TIMEOUT_S)
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stack_set_operation(StackSetName=set_name, OperationId=op_id)[
            "StackSetOperation"]
        if last["Status"] not in {"RUNNING", "QUEUED", "STOPPING"}:
            return last
        time.sleep(2.0)
    raise AssertionError(f"operation {op_id!r} not finished after {OP_TIMEOUT_S}s: {last!r}")


def _teardown_set(cfn, set_name: str, account: str, region: str) -> None:
    """Remove any remaining instance, then the set. Idempotent; a failure raises."""
    try:
        insts = cfn.list_stack_instances(StackSetName=set_name)["Summaries"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "StackSetNotFoundException":
            return
        raise
    if insts:
        op_id = cfn.delete_stack_instances(StackSetName=set_name, Accounts=[account],
                                           Regions=[region], RetainStacks=False)["OperationId"]
        try:
            _wait_op(None, cfn, set_name, op_id)
        except AssertionError as exc:
            raise RuntimeError(
                f"stack set {set_name} instance delete did not finish: {exc}"
            ) from exc
    try:
        cfn.delete_stack_set(StackSetName=set_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise RuntimeError(f"stack set {set_name}: {exc}") from exc


def _delete_role(iam, name: str) -> None:
    try:
        for pol in iam.list_role_policies(RoleName=name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=name, PolicyName=pol)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wired_queue(ctx, sqs, events, label: str, pattern: dict) -> str:
    """One SQS queue fed by one EventBridge rule on the default bus; both torn down LIFO."""
    queue_url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-xsvc-ssf-{label}-"),
                                 tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: sqs.delete_queue(QueueUrl=queue_url)))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    rule = ctx.unique_name(f"sim2real-xsvc-ssf-{label}-")
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


def _drain_until(ctx, sqs, queue_url: str, want, *, why: str) -> list[dict]:
    """Accumulate NEW events until want(new_events); RAISES on timeout."""
    deadline = _deadline(ctx, DELIVERY_TIMEOUT_S)
    got: list[dict] = []
    while time.monotonic() < deadline:
        got.extend(_receive(sqs, queue_url))
        if want(got):
            return got
    raise AssertionError(
        f"queue never yielded [{why}] within {DELIVERY_TIMEOUT_S}s; got {len(got)} events: "
        f"{[(e.get('detail-type'), e.get('detail')) for e in got]!r}"
    )


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
