"""deploy-cfn-cluster-hosts-runtask-behavior."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-cluster-hosts-runtask-behavior"
GROUP = "server-side"
SERVICES = ["ecs"]


_TEMPLATE = """
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
  ClusterArnOut:
    Value: !GetAtt Cluster.Arn
  ClusterNameOut:
    Value: !Ref Cluster
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A cluster created via a CloudFormation stack actually accepts and runs tasks through
    the standard RunTask data-plane API, not merely reaching CREATE_COMPLETE."""
    ecs = ctx.client("ecs")
    net = _default_network(ctx)


    stack_name = ctx.unique_name("sim2real-ecs-cfn-cluster-")
    cluster_name = ctx.unique_name("sim2real-ecs-cfn-cluster-name-")
    outputs = _deploy_cfn(ctx, stack_name, _TEMPLATE, {"ClusterName": cluster_name})
    ctx.on_cleanup(lambda: _destroy_cfn(ctx, stack_name))

    assert outputs["ClusterNameOut"] == cluster_name, (
        f"expected stack output ClusterNameOut={cluster_name!r}, got {outputs['ClusterNameOut']!r}"
    )
    clusters = ecs.describe_clusters(clusters=[cluster_name])["clusters"]
    assert len(clusters) == 1, f"expected exactly 1 cluster named {cluster_name!r}, got {clusters!r}"
    assert clusters[0]["status"] == "ACTIVE", f"expected cluster status ACTIVE, got {clusters[0]['status']!r}"
    assert clusters[0]["clusterArn"] == outputs["ClusterArnOut"], (
        f"describe_clusters clusterArn {clusters[0]['clusterArn']!r} != "
        f"stack output ClusterArnOut {outputs['ClusterArnOut']!r}"
    )

    family = ctx.unique_name("sim2real-ecs-cfn-cluster-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "command": ["sleep", "3600"],
                "essential": True,
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_def(ecs, td_arn))

    run_resp = ecs.run_task(
        cluster=cluster_name,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": net["subnet_ids"][:1],
                "securityGroups": [net["sg_id"]],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    assert not run_resp.get("failures"), f"RunTask failures: {run_resp.get('failures')}"
    task_arn = run_resp["tasks"][0]["taskArn"]

    def _stop_and_wait() -> None:
        try:
            ecs.stop_task(cluster=cluster_name, task=task_arn, reason="check cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
        _poll_until(
            lambda: ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"][0]["lastStatus"],
            lambda s: s == "STOPPED",
            timeout_s=180,
            interval_s=5,
        )

    ctx.on_cleanup(_stop_and_wait)

    last_status = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"][0]["lastStatus"],
        lambda s: s in ("RUNNING", "STOPPED"),
        timeout_s=300,
        interval_s=10,
    )
    assert last_status == "RUNNING", f"expected task lastStatus RUNNING, got {last_status!r}"


def _retire_task_def(ecs, arn: str) -> None:
    """Deregister, then delete, one task definition revision, so no INACTIVE revision lingers."""
    ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures") or []
    if failures:
        raise RuntimeError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError(f"vpc {vpc_id!r} has no subnets available")
    public = [s["SubnetId"] for s in subnets if s.get("MapPublicIpOnLaunch")]
    subnet_ids = public or [s["SubnetId"] for s in subnets]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError(f"vpc {vpc_id!r} has no default security group")
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sgs[0]["GroupId"]}


def _deploy_cfn(ctx, stack_name, template_body, parameters):
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _destroy_cfn(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
