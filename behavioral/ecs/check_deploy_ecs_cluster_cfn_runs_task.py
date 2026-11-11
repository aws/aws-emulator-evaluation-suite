"""deploy-ecs-cluster-cfn-runs-task."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-ecs-cluster-cfn-runs-task"
GROUP = "deploy"
SERVICES = ["ecs"]

_SIM2REAL_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-ecs"},
]

_CFN_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterName:
    Type: String
Resources:
  Cluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: !Ref ClusterName
Outputs:
  ClusterArn:
    Value: !GetAtt Cluster.Arn
  ClusterNameOut:
    Value: !Ref Cluster
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask against a cluster created purely via CloudFormation reaches RUNNING on that exact cluster."""
    cluster_name = ctx.unique_name("sim2real-ecs-cfncluster-")
    _stack_name, outputs = _deploy_cfn(
        ctx,
        _CFN_TEMPLATE,
        parameters=[{"ParameterKey": "ClusterName", "ParameterValue": cluster_name}],
    )
    cluster_arn = outputs["ClusterArn"]
    assert outputs["ClusterNameOut"] == cluster_name, (
        f"stack output ClusterNameOut={outputs['ClusterNameOut']!r}, expected {cluster_name!r}"
    )

    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_subnet_and_sg(ctx)
    task_def_arn = _register_nginx_task_def(ctx)

    run_resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [subnet_id],
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": t["Key"], "value": t["Value"]} for t in _SIM2REAL_TAGS],
    )
    assert not run_resp.get("failures"), f"RunTask failures: {run_resp.get('failures')}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_and_wait(ctx, cluster_arn, task_arn))

    task = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0],
        lambda t: t["lastStatus"] in ("RUNNING", "STOPPED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert task["lastStatus"] == "RUNNING", f"task did not reach RUNNING: {task.get('stoppedReason')}"
    assert task["clusterArn"] == cluster_arn, (
        f"task placed on clusterArn={task['clusterArn']!r}, expected the CFN-created {cluster_arn!r}"
    )

    clusters = ecs.describe_clusters(clusters=[cluster_arn])["clusters"]
    assert len(clusters) == 1, f"describe_clusters({cluster_arn!r}) returned {len(clusters)} clusters, expected 1"
    assert clusters[0]["clusterArn"] == cluster_arn, (
        f"describe_clusters returned clusterArn={clusters[0]['clusterArn']!r}, expected {cluster_arn!r}"
    )
    assert clusters[0]["clusterName"] == cluster_name, (
        f"describe_clusters returned clusterName={clusters[0]['clusterName']!r}, expected {cluster_name!r}"
    )


# ===== helpers =====

def _deploy_cfn(ctx, template_body, parameters=None, capabilities=None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ecs-stack-")
    kwargs = {"StackName": stack_name, "TemplateBody": template_body, "Tags": _SIM2REAL_TAGS}
    if parameters:
        kwargs["Parameters"] = parameters
    if capabilities:
        kwargs["Capabilities"] = capabilities

    def _cleanup():
        try:
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackNotFoundException":
                raise

    cfn.create_stack(**kwargs)
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
    return stack_name, outputs


def _default_subnet_and_sg(ctx):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to place a Fargate task ENI")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


def _register_nginx_task_def(ctx):
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-task-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/nginx:1.27",
                "essential": True,
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
            }
        ],
        tags=[{"key": t["Key"], "value": t["Value"]} for t in _SIM2REAL_TAGS],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _stop_and_wait(ctx, cluster_arn, task_arn, timeout_s=120.0):
    ecs = ctx.client("ecs")
    try:
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
            return
        if not resp or resp[0]["lastStatus"] == "STOPPED":
            return
        time.sleep(5.0)


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
