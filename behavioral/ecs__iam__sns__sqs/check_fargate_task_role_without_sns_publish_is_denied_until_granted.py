"""fargate-task-role-without-sns-publish-is-denied-until-granted."""

from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "fargate-task-role-without-sns-publish-is-denied-until-granted"
GROUP = "iam-sns-permission-chain"
SERVICES = ["ecs", "iam", "sns", "sqs"]

_IMAGE = "public.ecr.aws/aws-cli/aws-cli:latest"
_CONTAINER = "Publisher"
#: ENI provisioning, image pull and cold start before the first publish attempt; a ceiling to
#: FAIL at, never an asserted latency.
_STOPPED_DEADLINE_S = 420
_LOG_DEADLINE_S = 90
_RECEIVE_DEADLINE_S = 60
_RESOURCE_TAGS = {"sim2real:managed": "true"}

# Retries the publish for roughly 30s so IAM propagation on a freshly-granted role is never
# mistaken for a fidelity gap, then reports exactly one of two stable outcome lines.
_PUBLISH_SCRIPT = r'''set -u
attempt=0
outcome=DENIED
detail=""
while [ "$attempt" -lt 6 ]; do
  if raw=$(aws sns publish --topic-arn "$TOPIC_ARN" --message "$BODY" 2>&1); then
    outcome=OK
    break
  fi
  detail=$(printf '%s' "$raw" | tail -n 1)
  attempt=$((attempt + 1))
  sleep 5
done
if [ "$outcome" = OK ]; then
  echo "OUTCOME=OK BODY=$BODY"
else
  echo "OUTCOME=DENIED BODY=$BODY DETAIL=$detail"
fi
exit 0
'''


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A Fargate task whose role lacks sns:Publish never delivers to the topic's subscriber;
    granting the one missing statement to the same role lets the next task's message arrive.
    """
    sns, iam, ecs = ctx.client("sns"), ctx.client("iam"), ctx.client("ecs")
    token = ctx.unique_name("sim2real-ecssns-")
    queue_url, queue_arn = _create_subscriber_queue(ctx)
    topic_arn = _create_topic(ctx, queue_arn)

    trust = _ecs_tasks_trust()
    publish_statement = {"Effect": "Allow", "Action": ["sns:Publish"], "Resource": [topic_arn]}
    exec_role = _make_role(
        ctx, f"{token}-exec", trust,
        managed_policy="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy")
    granted_role = _make_role(ctx, f"{token}-granted", trust, inline_statements=[publish_statement])
    denied_role = _make_role(ctx, f"{token}-denied", trust)

    logs = ctx.client("logs")
    log_group = f"{token}-logs"
    logs.create_log_group(logGroupName=log_group, tags=dict(_RESOURCE_TAGS))
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    cluster = ecs.create_cluster(clusterName=token, tags=_ecs_tags())["cluster"]["clusterName"]
    ctx.on_cleanup(_cluster_cleanup(ctx, cluster))

    net = ctx.network()
    subnet, security_group = net.subnet_ids[0], net.security_group_id

    bodies = {"granted": f"{token}-granted-payload", "denied": f"{token}-denied-payload"}
    task_def_arns = {}
    for which, role in (("granted", granted_role), ("denied", denied_role)):
        family = f"{token}-{which}"
        ctx.on_cleanup(_deregister_family(ctx, family))
        task_def_arns[which] = _register_publisher(
            ctx, family, exec_role["arn"], role["arn"], topic_arn, bodies[which], log_group, which)

    granted_task = _launch(ctx, cluster, task_def_arns["granted"], subnet, security_group)
    denied_task = _launch(ctx, cluster, task_def_arns["denied"], subnet, security_group)
    _await_stopped(ctx, cluster, granted_task)
    _await_stopped(ctx, cluster, denied_task)

    granted_line = _await_log_line(ctx, log_group, f"granted/{_CONTAINER}/{_task_id(granted_task)}")
    denied_line = _await_log_line(ctx, log_group, f"denied/{_CONTAINER}/{_task_id(denied_task)}")

    assert granted_line.startswith("OUTCOME=OK"), (
        f"the granted role should have published its message, got {granted_line!r}"
    )
    delivered = _drain_for_body(ctx, queue_url, bodies["granted"], deadline_s=_RECEIVE_DEADLINE_S)
    assert delivered is not None, (
        f"subscriber queue never carried the body {bodies['granted']!r} the granted task published"
    )

    assert denied_line.startswith("OUTCOME=DENIED"), (
        f"the denied role should never have published, got {denied_line!r}"
    )
    code, message = _parse_cli_error(denied_line)
    assert code == "AuthorizationError", (
        f"expected error code 'AuthorizationError', got {code!r} ({denied_line!r})"
    )
    expected_message = (
        f'User: arn:aws:sts::{ctx.account}:assumed-role/{denied_role["name"]}/'
        f'{_task_id(denied_task)} is not authorized to perform: SNS:Publish on resource: '
        f'{topic_arn} because no identity-based policy allows the SNS:Publish action'
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    never_arrived = _drain_for_body(ctx, queue_url, bodies["denied"], deadline_s=15)
    assert never_arrived is None, (
        f"the denied task's body {bodies['denied']!r} reached the subscriber queue despite no grant"
    )

    # Repair exactly the one missing statement on the SAME role; the family's next revision must
    # now deliver, closing the loop against a typo "passing" the denial alone.
    iam.put_role_policy(RoleName=denied_role["name"], PolicyName="grant", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [publish_statement]}))
    repaired_body = f"{token}-denied-repaired-payload"
    repaired_arn = _register_publisher(
        ctx, f"{token}-denied", exec_role["arn"], denied_role["arn"], topic_arn, repaired_body,
        log_group, "denied")
    repaired_task = _launch(ctx, cluster, repaired_arn, subnet, security_group)
    _await_stopped(ctx, cluster, repaired_task)
    repaired_line = _await_log_line(ctx, log_group, f"denied/{_CONTAINER}/{_task_id(repaired_task)}")
    assert repaired_line.startswith("OUTCOME=OK"), (
        f"after granting sns:Publish the same role should deliver, got {repaired_line!r}"
    )
    repaired_delivered = _drain_for_body(ctx, queue_url, repaired_body, deadline_s=_RECEIVE_DEADLINE_S)
    assert repaired_delivered is not None, (
        f"subscriber queue never carried the repaired body {repaired_body!r} after the grant"
    )


# ===== helpers =====

def _ecs_tasks_trust() -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
        "Action": "sts:AssumeRole"}]})


def _ecs_tags() -> list:
    return [{"key": k, "value": v} for k, v in _RESOURCE_TAGS.items()]


def _create_subscriber_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-ecssns-")
    queue_url = sqs.create_queue(QueueName=name)["QueueUrl"]

    def _delete():
        try:
            sqs.delete_queue(QueueUrl=queue_url)
        except sqs.exceptions.QueueDoesNotExist:
            pass

    ctx.on_cleanup(_delete)
    sqs.tag_queue(QueueUrl=queue_url, Tags=dict(_RESOURCE_TAGS))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return queue_url, queue_arn


def _create_topic(ctx, queue_arn: str) -> str:
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-ecssns-")
    topic_arn = sns.create_topic(
        Name=name, Tags=[{"Key": k, "Value": v} for k, v in _RESOURCE_TAGS.items()])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.get_queue_url(QueueName=queue_arn.rsplit(":", 1)[-1])["QueueUrl"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]}
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    subscription_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=subscription_arn))
    return topic_arn


def _make_role(ctx, name: str, trust: str, *, managed_policy: str | None = None,
               inline_statements: list | None = None) -> dict:
    iam = ctx.client("iam")
    role_name = name[:64]
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Description="sim2real ecs task role for a cross-service permission check",
        Tags=[{"Key": k, "Value": v} for k, v in _RESOURCE_TAGS.items()])["Role"]["Arn"]

    def _delete():
        for policy_name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        for attached in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=attached["PolicyArn"])
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete)
    if managed_policy:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy)
    if inline_statements:
        iam.put_role_policy(RoleName=role_name, PolicyName="grant", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": inline_statements}))
    return {"name": role_name, "arn": arn}


def _register_publisher(ctx, family: str, exec_role_arn: str, task_role_arn: str, topic_arn: str,
                         body: str, log_group: str, stream_prefix: str) -> str:
    ecs = ctx.client("ecs")
    return ecs.register_task_definition(
        family=family, requiresCompatibilities=["FARGATE"], networkMode="awsvpc", cpu="256",
        memory="512", executionRoleArn=exec_role_arn, taskRoleArn=task_role_arn,
        tags=_ecs_tags(), containerDefinitions=[{
            "name": _CONTAINER, "image": _IMAGE, "essential": True,
            "entryPoint": ["bash", "-c"], "command": [_PUBLISH_SCRIPT],
            "environment": [{"name": "TOPIC_ARN", "value": topic_arn},
                            {"name": "BODY", "value": body},
                            {"name": "AWS_DEFAULT_REGION", "value": ctx.region}],
            "logConfiguration": {"logDriver": "awslogs", "options": {
                "awslogs-group": log_group, "awslogs-region": ctx.region,
                "awslogs-stream-prefix": stream_prefix}}}])["taskDefinition"]["taskDefinitionArn"]


def _task_id(task_arn: str) -> str:
    return task_arn.rsplit("/", 1)[-1]


def _parse_cli_error(line: str) -> tuple[str, str]:
    """``code, message`` out of the CLI's own ``An error occurred (CODE) ...: MESSAGE`` text."""
    m = re.search(
        r"An error occurred \(([^)]+)\) when calling the \S+ operation: (.*)$", line)
    assert m, f"could not parse an AWS CLI error out of {line!r}"
    return m.group(1), m.group(2)


def _drain_for_body(ctx, queue_url: str, body: str, *, deadline_s: float) -> dict | None:
    """Poll receives until an SNS envelope carrying ``body`` is seen (and deleted), or
    ``deadline_s`` runs out."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + deadline_s
    while True:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for message in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
            envelope = json.loads(message["Body"])
            if envelope.get("Message") == body:
                return envelope
        if time.monotonic() >= deadline:
            return None


def _launch(ctx, cluster: str, task_definition: str, subnet: str, security_group: str) -> str:
    """RunTask with a BOUNDED retry for the one documented propagation refusal: a fresh task role
    is not yet assumable by ECS (ClientException 'unable to assume the role')."""
    from botocore.exceptions import ClientError

    ecs = ctx.client("ecs")
    deadline = time.monotonic() + 180
    while True:
        try:
            resp = ecs.run_task(
                cluster=cluster, taskDefinition=task_definition, launchType="FARGATE", count=1,
                networkConfiguration={"awsvpcConfiguration": {
                    "subnets": [subnet], "securityGroups": [security_group],
                    "assignPublicIp": "ENABLED"}})
        except ClientError as exc:
            if "unable to assume" not in str(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(5)
            continue
        assert resp["failures"] == [] and len(resp["tasks"]) == 1, f"RunTask answered {resp!r}"
        return resp["tasks"][0]["taskArn"]


def _await_stopped(ctx, cluster: str, task_arn: str) -> dict:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + _STOPPED_DEADLINE_S
    while True:
        task = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0]
        if task["lastStatus"] == "STOPPED":
            containers = {c["name"]: c for c in task.get("containers", [])}
            publisher = containers.get(_CONTAINER, {})
            assert publisher.get("exitCode") == 0, (
                f"task {_task_id(task_arn)!r} container exited {publisher.get('exitCode')!r}: "
                f"{task.get('stoppedReason')!r}"
            )
            return task
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"task {_task_id(task_arn)!r} did not reach STOPPED within {_STOPPED_DEADLINE_S}s; "
                f"last status {task['lastStatus']!r}"
            )
        time.sleep(5)


def _await_log_line(ctx, log_group: str, stream: str) -> str:
    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    deadline = time.monotonic() + _LOG_DEADLINE_S
    while True:
        try:
            events = logs.get_log_events(
                logGroupName=log_group, logStreamName=stream, startFromHead=True)["events"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            events = []
        for event in events:
            if event["message"].startswith("OUTCOME="):
                return event["message"].rstrip("\n")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no OUTCOME= line in {log_group!r}/{stream!r} within {_LOG_DEADLINE_S}s; "
                f"events were {[e['message'] for e in events]!r}"
            )
        time.sleep(3)


def _cluster_cleanup(ctx, cluster: str):
    """Stop every task, wait for STOPPED (bounded, raising past it), then delete the cluster."""
    def _go():
        ecs = ctx.client("ecs")
        arns = []
        for page in ecs.get_paginator("list_tasks").paginate(cluster=cluster):
            arns.extend(page.get("taskArns", []))
        for arn in arns:
            ecs.stop_task(cluster=cluster, task=arn, reason="sim2real cleanup")
        deadline = time.monotonic() + 240
        while arns:
            live = [t["taskArn"] for t in ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"]
                    if t["lastStatus"] != "STOPPED"]
            if not live:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f"tasks {live!r} in cluster {cluster} never reached STOPPED")
            time.sleep(5)
        ecs.delete_cluster(cluster=cluster)
    return _go


def _deregister_family(ctx, family: str):
    def _go():
        ecs = ctx.client("ecs")
        arns = ecs.list_task_definitions(familyPrefix=family)["taskDefinitionArns"]
        for arn in arns:
            ecs.deregister_task_definition(taskDefinition=arn)
        if arns:
            resp = ecs.delete_task_definitions(taskDefinitions=arns)
            if resp.get("failures"):
                raise RuntimeError(f"delete_task_definitions {family}: {resp['failures']!r}")
    return _go


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
