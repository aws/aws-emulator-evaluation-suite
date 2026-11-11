"""deploy-ecs-capacityprovider-cfn-association-enforced."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-ecs-capacityprovider-cfn-association-enforced"
GROUP = "deploy"
SERVICES = ["ecs"]

_SIM2REAL_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
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
  ClusterCapacityProviders:
    Type: AWS::ECS::ClusterCapacityProviderAssociations
    Properties:
      Cluster: !Ref Cluster
      CapacityProviders:
        - FARGATE_SPOT
      DefaultCapacityProviderStrategy:
        - CapacityProvider: FARGATE_SPOT
          Weight: 1
Outputs:
  ClusterArn:
    Value: !GetAtt Cluster.Arn
  ClusterNameOut:
    Value: !Ref Cluster
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN cluster/capacity-provider association actually constrains where RunTask places tasks."""
    cluster_name = ctx.unique_name("sim2real-ecs-cfncpcluster-")
    _stack_name, outputs = _deploy_cfn(
        ctx,
        _CFN_TEMPLATE,
        parameters=[{"ParameterKey": "ClusterName", "ParameterValue": cluster_name}],
    )
    cluster_arn = outputs["ClusterArn"]

    ecs = ctx.client("ecs")
    clusters = ecs.describe_clusters(clusters=[cluster_arn])["clusters"]
    assert clusters[0]["capacityProviders"] == ["FARGATE_SPOT"], (
        f"expected the CFN-associated capacityProviders to be ['FARGATE_SPOT'], "
        f"got {clusters[0]['capacityProviders']!r}"
    )
    assert clusters[0]["defaultCapacityProviderStrategy"][0]["capacityProvider"] == "FARGATE_SPOT", (
        f"expected the CFN-set defaultCapacityProviderStrategy to name FARGATE_SPOT, "
        f"got {clusters[0]['defaultCapacityProviderStrategy']!r}"
    )

    subnet_id, sg_id = _default_subnet_and_sg(ctx)
    task_def_arn = _register_nginx_task_def(ctx)

    # No launchType/capacityProviderStrategy: RunTask must fall back to the
    # cluster's default strategy, which only names FARGATE_SPOT.
    run_resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
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

    # DescribeTasks can transiently report an empty list in the instant right after RunTask
    # returns (observed on real AWS); None (not a hard subscript) is what "not visible yet"
    # feeds the predicate, so a real absence times out via _poll_until rather than crashing
    # the check on the very first probe.
    task = _poll_until(
        lambda: (ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"] or [None])[0],
        lambda t: t is not None and t["lastStatus"] in ("RUNNING", "STOPPED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert task["lastStatus"] == "RUNNING", f"task did not reach RUNNING: {task.get('stoppedReason')}"
    assert task["capacityProviderName"] == "FARGATE_SPOT", (
        f"RunTask relied on the cluster's CFN-set default strategy (no launchType/"
        f"capacityProviderStrategy given); expected capacityProviderName=FARGATE_SPOT, "
        f"got {task.get('capacityProviderName')!r}"
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
