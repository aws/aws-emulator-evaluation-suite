"""eventbridge-execution-started-event-delivered."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-execution-started-event-delivered"
GROUP = "event-propagation"
SERVICES = ["arc-region-switch"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Starting a plan execution emits an 'ARC Region Switch Plan Execution' EventBridge event
    that an EventBridge rule can route to SQS, and the delivered event correlates back to the
    execution that triggered it via detail.executionId and the plan's arn in `resources`."""
    region_a, region_b = _pick_regions(ctx)
    events = ctx.client("events", region=region_b)
    sqs = ctx.client("sqs", region=region_b)
    arc = ctx.client("arc-region-switch")
    arc_b = ctx.client("arc-region-switch", region=region_b)
    ctx.client("sts").get_caller_identity()["Account"]

    queue_url = _create_queue_or_skip(sqs, ctx.unique_name("sim2real-arc-evt-"))
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-arc-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": ["aws.arc-region-switch"],
                "detail-type": ["ARC Region Switch Plan Execution"],
            }
        ),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    events.put_targets(
        Rule=rule_name, Targets=[{"Id": "sim2real-arc-target", "Arn": queue_arn}]
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["sim2real-arc-target"]))

    role_arn = _create_execution_role(ctx)
    plan_arn = _create_plan_with_approval_workflow(ctx, role_arn, region_a, region_b)
    ctx.on_cleanup(lambda: _safe_delete(arc, plan_arn))

    started = _start_execution_with_retry(
        arc_b, planArn=plan_arn, targetRegion=region_b, action="activate"
    )
    execution_id = started["executionId"]
    ctx.on_cleanup(lambda: _safe_cleanup_execution(arc_b, plan_arn, execution_id))

    matches = _poll_for_matching_events(sqs, queue_url, plan_arn, execution_id, timeout_s=120)
    assert len(matches) > 0, "no EventBridge event correlating to this execution was delivered"
    sample = matches[0]
    assert sample["source"] == "aws.arc-region-switch"
    assert sample["detail-type"] == "ARC Region Switch Plan Execution"
    assert any(plan_arn in r for r in sample.get("resources", []))
    assert sample["detail"]["executionId"] == execution_id


def _create_queue_or_skip(sqs, queue_name):
    from botocore.exceptions import ClientError

    try:
        return sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
    except ClientError as e:
        if e.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"):

            raise AssertionError(
                "sqs:CreateQueue was denied in this verification account ('no identity-based "
                "policy allows the sqs:createqueue action') -- this suite's ambient role has no "
                "SQS permissions here, an environment limitation unrelated to arc-region-switch's "
                "EventBridge event-emission behavior under test"
            )
        raise


def _pick_regions(ctx):
    # region_b is the region we actually call StartPlanExecution against (must equal ctx.region
    # since the verification account's IAM is scoped to a single region); region_a is the
    # plan's other participating (primary) region, used only as metadata -- never dialed directly.
    region_b = ctx.region
    region_a = "us-west-2" if region_b != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _safe_delete(arc, arn):
    try:
        arc.delete_plan(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_cleanup_execution(arc, plan_arn, execution_id):
    try:
        state = arc.get_plan_execution(planArn=plan_arn, executionId=execution_id)["executionState"]
        if state in ("pendingManualApproval",):
            arc.approve_plan_execution_step(
                planArn=plan_arn, executionId=execution_id, stepName="Approve", approval="decline"
            )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_for_matching_events(sqs, queue_url, plan_arn, execution_id, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    matches = []
    while time.monotonic() < deadline and not matches:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (ValueError, KeyError):
                body = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if not isinstance(body, dict):
                continue
            detail = body.get("detail", {})
            if detail.get("executionId") == execution_id:
                matches.append(body)
    return matches


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-arcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "arc-region-switch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    arn = role["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-all",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ),
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="allow-all")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for _ in range(20):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(1)
    # IAM role/trust-policy propagation to the arc-region-switch service is bounded
    # by _start_execution_with_retry's own AccessDeniedException backoff below, not
    # by a flat sleep here.
    return arn


def _create_plan_with_approval_workflow(ctx, role_arn, region_a, region_b, step_name="Approve"):
    arc = ctx.client("arc-region-switch")
    block = {
        "name": step_name,
        "executionBlockType": "ManualApproval",
        "executionBlockConfiguration": {
            "executionApprovalConfig": {"approvalRole": role_arn, "timeoutMinutes": 60}
        },
    }
    resp = arc.create_plan(
        name=_plan_name(ctx),
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=role_arn,
        workflows=[
            {"workflowTargetAction": "activate", "steps": [block]},
        ],
        tags={"sim2real": CHECK},
    )
    return resp["plan"]["arn"]


def _start_execution_with_retry(arc, **kwargs):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(8):
        try:
            return arc.start_plan_execution(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "IllegalArgumentException", "ResourceNotFoundException"):
                # A just-created plan can be briefly invisible to StartPlanExecution --
                # observed on real AWS as ResourceNotFoundException seconds after CreatePlan
                # returned successfully -- so this absorbs that replication lag too.
                last_exc = e
                time.sleep(5)
                continue
            raise
    if isinstance(last_exc, ClientError) and last_exc.response["Error"]["Code"] == "AccessDeniedException":

        raise AssertionError(
            "StartPlanExecution was persistently denied (AccessDeniedException with no detail) "
            "even for a freshly created, correctly-trust-policied execution role after 40s of "
            "retries; this sandbox account appears to withhold arc-region-switch execution "
            "privileges (likely an iam:PassRole/service-principal allow-list gap for "
            "arc-region-switch.amazonaws.com) independent of the plan/role setup under test"
        )
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
