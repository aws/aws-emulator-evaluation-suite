"""fargate-task-role-missing-s3-putobject-grant-is-denied-then-repaired."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "fargate-task-role-missing-s3-putobject-grant-is-denied-then-repaired"
GROUP = "permission-chain"
SERVICES = ["ecs", "iam", "s3"]

#: A Fargate task needs up to a few minutes for ENI provisioning, image pull and cold start before
#: its container even starts the retry loop; a ceiling to FAIL at, never an asserted latency.
_TASK_DEADLINE_S = 420
_LOG_DEADLINE_S = 90
_IMAGE = "public.ecr.aws/aws-cli/aws-cli:2.36.44"
_CONTAINER = "Writer"

# Retries the put for up to ~30s so IAM propagation on the ALLOWED role's freshly-attached policy
# cannot be mistaken for a fidelity gap, then reports exactly one of two stable result lines.
_SCRIPT = r'''set -u
echo sim2real-payload > /tmp/payload.txt
i=0
RESULT=DENIED
ERR=""
while [ "$i" -lt 6 ]; do
  if aws s3api put-object --bucket "$BUCKET" --key "$KEY" --body /tmp/payload.txt 2>/tmp/err; then
    RESULT=OK
    break
  fi
  ERR=$(tail -n 1 /tmp/err)
  i=$((i + 1))
  sleep 5
done
if [ "$RESULT" = OK ]; then
  echo "RESULT:OK key=$KEY"
else
  echo "RESULT:DENIED key=$KEY error=$ERR"
fi
exit 0
'''


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A Fargate task whose role lacks an S3 grant gets AccessDenied and writes nothing; once the
    one statement is added to the same role, a task of the next revision writes its object.
    """
    s3, iam, ecs = ctx.client("s3"), ctx.client("iam"), ctx.client("ecs")
    tok = ctx.unique_name("sim2real-ecsiam-")
    bucket = _create_bucket(ctx)

    trust = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
        "Action": "sts:AssumeRole"}]})
    put_stmt = {"Effect": "Allow", "Action": ["s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/*"]}
    exec_role = _role(ctx, f"{tok}-exec", trust,
                      managed="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy")
    allowed_role = _role(ctx, f"{tok}-allowed", trust, inline=[put_stmt])
    denied_role = _role(ctx, f"{tok}-denied", trust)

    logs = ctx.client("logs")
    group = f"{tok}-logs"
    logs.create_log_group(logGroupName=group, tags=dict(_TAGS))
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    cluster = ecs.create_cluster(
        clusterName=tok, tags=_ECS_TAGS)["cluster"]["clusterName"]
    ctx.on_cleanup(_cluster_teardown(ctx, cluster))

    net = ctx.network()
    subnet, sg = net.subnet_ids[0], net.security_group_id

    keys = {"allowed": f"{tok}/allowed.txt", "denied": f"{tok}/denied.txt"}
    task_def_arns = {}
    for which, role in (("allowed", allowed_role), ("denied", denied_role)):
        family = f"{tok}-{which}"
        ctx.on_cleanup(_deregister_family(ctx, family))
        task_def_arns[which] = ecs.register_task_definition(
            family=family, requiresCompatibilities=["FARGATE"], networkMode="awsvpc", cpu="256",
            memory="512", executionRoleArn=exec_role["arn"], taskRoleArn=role["arn"], tags=_ECS_TAGS,
            containerDefinitions=[{
                "name": _CONTAINER, "image": _IMAGE, "essential": True,
                "entryPoint": ["bash", "-c"], "command": [_SCRIPT],
                "environment": [{"name": "BUCKET", "value": bucket},
                                {"name": "KEY", "value": keys[which]},
                                {"name": "AWS_DEFAULT_REGION", "value": ctx.region}],
                "logConfiguration": {"logDriver": "awslogs", "options": {
                    "awslogs-group": group, "awslogs-region": ctx.region,
                    "awslogs-stream-prefix": which}}}])["taskDefinition"]["taskDefinitionArn"]

    allowed_task = _run_task(ctx, cluster, task_def_arns["allowed"], subnet, sg)
    denied_task = _run_task(ctx, cluster, task_def_arns["denied"], subnet, sg)

    _wait_stopped(ctx, cluster, allowed_task)
    _wait_stopped(ctx, cluster, denied_task)

    allowed_line = _wait_log_line(ctx, group, f"allowed/{_CONTAINER}/{_task_id(allowed_task)}")
    denied_line = _wait_log_line(ctx, group, f"denied/{_CONTAINER}/{_task_id(denied_task)}")

    assert allowed_line.startswith("RESULT:OK"), (
        f"the allowed task should have written its object, got {allowed_line!r}"
    )
    assert _head_object(s3, bucket, keys["allowed"]), (
        f"no object at the allowed task's key {keys['allowed']!r} in bucket {bucket!r}"
    )

    assert denied_line.startswith("RESULT:DENIED"), (
        f"the denied task should never have succeeded, got {denied_line!r}"
    )
    code, message = _parse_denied(denied_line)
    assert code == "AccessDenied", (
        f"expected error code 'AccessDenied', got {code!r} (line={denied_line!r})"
    )
    expected_message = (
        f'User: arn:aws:sts::{ctx.account}:assumed-role/{denied_role["name"]}/'
        f'{_task_id(denied_task)} is not authorized to perform: s3:PutObject on resource: '
        f'"arn:aws:s3:::{bucket}/{keys["denied"]}" because no identity-based policy allows '
        f'the s3:PutObject action'
    )
    assert message == expected_message, (
        f"expected error message {expected_message!r}, got {message!r} (line={denied_line!r})"
    )
    assert not _head_object(s3, bucket, keys["denied"]), (
        f"the denied task's key {keys['denied']!r} exists in bucket {bucket!r} despite no grant"
    )

    # Repair exactly the one missing statement on the SAME role; a task of the family's next
    # revision must now succeed -- closing the loop against a typo "passing" the first half.
    iam.put_role_policy(RoleName=denied_role["name"], PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [put_stmt]}))
    repaired_key = f"{tok}/denied-repaired.txt"
    keys["denied"] = repaired_key
    # Same family, same role; only the KEY env var differs, so register the family's next
    # revision with the new key rather than branching the container's own behaviour.
    repaired_arn = ecs.register_task_definition(
        family=f"{tok}-denied", requiresCompatibilities=["FARGATE"], networkMode="awsvpc",
        cpu="256", memory="512", executionRoleArn=exec_role["arn"], taskRoleArn=denied_role["arn"],
        tags=_ECS_TAGS, containerDefinitions=[{
            "name": _CONTAINER, "image": _IMAGE, "essential": True,
            "entryPoint": ["bash", "-c"], "command": [_SCRIPT],
            "environment": [{"name": "BUCKET", "value": bucket},
                            {"name": "KEY", "value": repaired_key},
                            {"name": "AWS_DEFAULT_REGION", "value": ctx.region}],
            "logConfiguration": {"logDriver": "awslogs", "options": {
                "awslogs-group": group, "awslogs-region": ctx.region,
                "awslogs-stream-prefix": "denied"}}}])["taskDefinition"]["taskDefinitionArn"]
    repaired_task = _run_task(ctx, cluster, repaired_arn, subnet, sg)
    _wait_stopped(ctx, cluster, repaired_task)
    repaired_line = _wait_log_line(ctx, group, f"denied/{_CONTAINER}/{_task_id(repaired_task)}")
    assert repaired_line.startswith("RESULT:OK"), (
        f"after granting s3:PutObject the same role should succeed, got {repaired_line!r}"
    )
    assert _head_object(s3, bucket, repaired_key), (
        f"no object at the repaired key {repaired_key!r} in bucket {bucket!r} after the grant"
    )


_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-ecsiam"}
_ECS_TAGS = [{"key": k, "value": v} for k, v in _TAGS.items()]


def _task_id(task_arn: str) -> str:
    return task_arn.rsplit("/", 1)[-1]


def _parse_denied(line: str) -> tuple[str, str]:
    """``code, message`` out of the CLI's own ``An error occurred (CODE) ...: MESSAGE`` text."""
    import re
    m = re.search(
        r"error=(?:aws: \[ERROR\]: )?An error occurred \(([^)]+)\) when calling the \S+ "
        r"operation: (.*)$",
        line,
    )
    assert m, f"could not parse an AWS CLI error out of {line!r}"
    return m.group(1), m.group(2)


def _head_object(s3, bucket: str, key: str) -> bool:
    from botocore.exceptions import ClientError
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "404":
            return False
        raise


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ecsiam-")
    # us-east-1 is the one region S3 rejects a CreateBucket LocationConstraint for.
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={
        "TagSet": [{"Key": k, "Value": v} for k, v in _TAGS.items()]})
    return bucket


def _role(ctx, name: str, trust: str, *, managed: str | None = None, inline=None) -> dict:
    iam = ctx.client("iam")
    arn = iam.create_role(RoleName=name[:64], AssumeRolePolicyDocument=trust,
                          Description="sim2real ecs task role",
                          Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]

    def _delete():
        for p in iam.list_role_policies(RoleName=name[:64])["PolicyNames"]:
            iam.delete_role_policy(RoleName=name[:64], PolicyName=p)
        for p in iam.list_attached_role_policies(RoleName=name[:64])["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name[:64], PolicyArn=p["PolicyArn"])
        iam.delete_role(RoleName=name[:64])

    ctx.on_cleanup(_delete)
    if managed:
        iam.attach_role_policy(RoleName=name[:64], PolicyArn=managed)
    if inline:
        iam.put_role_policy(RoleName=name[:64], PolicyName="inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": inline}))
    return {"name": name[:64], "arn": arn}


def _run_task(ctx, cluster: str, task_definition: str, subnet: str, sg: str) -> str:
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
                    "subnets": [subnet], "securityGroups": [sg], "assignPublicIp": "ENABLED"}})
        except ClientError as exc:
            if "unable to assume" not in str(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(5)
            continue
        assert resp["failures"] == [] and len(resp["tasks"]) == 1, f"RunTask answered {resp!r}"
        return resp["tasks"][0]["taskArn"]


def _wait_stopped(ctx, cluster: str, task_arn: str) -> dict:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + _TASK_DEADLINE_S
    while True:
        task = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0]
        if task["lastStatus"] == "STOPPED":
            containers = {c["name"]: c for c in task.get("containers", [])}
            writer = containers.get(_CONTAINER, {})
            assert writer.get("exitCode") == 0, (
                f"task {_task_id(task_arn)!r} container exited {writer.get('exitCode')!r}: "
                f"{task.get('stoppedReason')!r}"
            )
            return task
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"task {_task_id(task_arn)!r} did not reach STOPPED within {_TASK_DEADLINE_S}s; "
                f"last status {task['lastStatus']!r}"
            )
        time.sleep(5)


def _wait_log_line(ctx, group: str, stream: str) -> str:
    logs = ctx.client("logs")
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _LOG_DEADLINE_S
    while True:
        try:
            events = logs.get_log_events(
                logGroupName=group, logStreamName=stream, startFromHead=True)["events"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            events = []
        for e in events:
            if e["message"].startswith("RESULT:"):
                return e["message"].rstrip("\n")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no RESULT: line in {group!r}/{stream!r} within {_LOG_DEADLINE_S}s; "
                f"events were {[e['message'] for e in events]!r}"
            )
        time.sleep(3)


def _cluster_teardown(ctx, cluster: str):
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
