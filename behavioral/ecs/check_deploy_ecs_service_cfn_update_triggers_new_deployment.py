"""deploy-ecs-service-cfn-update-triggers-new-deployment."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "deploy-ecs-service-cfn-update-triggers-new-deployment"
GROUP = "deploy"
SERVICES = ["ecs"]

_CFN_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterName:
    Type: String
  ServiceName:
    Type: String
  TaskDefinitionArn:
    Type: String
  SubnetId:
    Type: String
  SecurityGroupId:
    Type: String
Resources:
  Cluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: !Ref ClusterName
  Service:
    Type: AWS::ECS::Service
    Properties:
      Cluster: !Ref Cluster
      ServiceName: !Ref ServiceName
      TaskDefinition: !Ref TaskDefinitionArn
      DesiredCount: 1
      LaunchType: FARGATE
      NetworkConfiguration:
        AwsvpcConfiguration:
          Subnets:
            - !Ref SubnetId
          SecurityGroups:
            - !Ref SecurityGroupId
          AssignPublicIp: ENABLED
Outputs:
  ClusterArn:
    Value: !GetAtt Cluster.Arn
  ServiceArn:
    Value: !Ref Service
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """Updating a CFN-deployed service's task definition revision fires a real new deployment."""
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_subnet_and_sg(ctx)
    family = ctx.unique_name("sim2real-ecs-task-")
    task_def_arn_v1 = _register_nginx_task_def(ctx, family, revision_tag="v1")
    cluster_name = ctx.unique_name("sim2real-ecs-cfncluster-")
    service_name = ctx.unique_name("sim2real-ecs-cfnsvc-")

    stack_name, outputs = _deploy_cfn(
        ctx,
        _CFN_TEMPLATE,
        parameters=[
            {"ParameterKey": "ClusterName", "ParameterValue": cluster_name},
            {"ParameterKey": "ServiceName", "ParameterValue": service_name},
            {"ParameterKey": "TaskDefinitionArn", "ParameterValue": task_def_arn_v1},
            {"ParameterKey": "SubnetId", "ParameterValue": subnet_id},
            {"ParameterKey": "SecurityGroupId", "ParameterValue": sg_id},
        ],
    )
    cluster_arn = outputs["ClusterArn"]
    service_arn = outputs["ServiceArn"]

    def _describe():
        return ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"][0]

    def _steady(svc):
        primary = next((d for d in svc["deployments"] if d["status"] == "PRIMARY"), None)
        return (
            svc["runningCount"] == svc["desiredCount"] == 1
            and primary is not None
            and primary["rolloutState"] == "COMPLETED"
        )

    service = _poll_until(_describe, _steady, timeout_s=240.0, interval_s=8.0)
    assert service["taskDefinition"] == task_def_arn_v1, (
        f"expected steady-state service on {task_def_arn_v1!r}, got {service['taskDefinition']!r}"
    )

    baseline_deployment_arns = {
        d["serviceDeploymentArn"]
        for d in ecs.list_service_deployments(cluster=cluster_arn, service=service_arn)[
            "serviceDeployments"
        ]
    }

    task_def_arn_v2 = _register_nginx_task_def(ctx, family, revision_tag="v2")
    assert task_def_arn_v2 != task_def_arn_v1, (
        f"expected a new task def revision distinct from {task_def_arn_v1!r}, got the same arn"
    )

    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_CFN_TEMPLATE,
        Parameters=[
            {"ParameterKey": "ClusterName", "ParameterValue": cluster_name},
            {"ParameterKey": "ServiceName", "ParameterValue": service_name},
            {"ParameterKey": "TaskDefinitionArn", "ParameterValue": task_def_arn_v2},
            {"ParameterKey": "SubnetId", "ParameterValue": subnet_id},
            {"ParameterKey": "SecurityGroupId", "ParameterValue": sg_id},
        ],
    )
    cfn.get_waiter("stack_update_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    def _list_new_deployments():
        arns = {
            d["serviceDeploymentArn"]
            for d in ecs.list_service_deployments(cluster=cluster_arn, service=service_arn)[
                "serviceDeployments"
            ]
        }
        return arns - baseline_deployment_arns

    new_arns = _poll_until(
        _list_new_deployments, lambda arns: len(arns) > 0, timeout_s=60.0, interval_s=5.0
    )
    new_deployment_arn = sorted(new_arns)[0]

    def _describe_new_deployment():
        return ecs.describe_service_deployments(serviceDeploymentArns=[new_deployment_arn])[
            "serviceDeployments"
        ][0]

    deployment = _poll_until(
        _describe_new_deployment,
        lambda d: d["status"] in ("SUCCESSFUL", "STOPPED", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert deployment["status"] == "SUCCESSFUL", f"deployment ended in {deployment['status']!r}"
    assert deployment["serviceArn"] == service_arn, (
        f"expected the new deployment to belong to {service_arn!r}, got {deployment['serviceArn']!r}"
    )

    final_service = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"][0]
    assert final_service["taskDefinition"] == task_def_arn_v2, (
        f"expected the service to converge on {task_def_arn_v2!r}, got {final_service['taskDefinition']!r}"
    )


# ===== helpers =====

def _deploy_cfn(ctx, template_body, parameters=None, capabilities=None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ecs-stack-")
    kwargs = {"StackName": stack_name, "TemplateBody": template_body}
    if parameters:
        kwargs["Parameters"] = parameters
    if capabilities:
        kwargs["Capabilities"] = capabilities

    def _cleanup():
        try:
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 420}
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


def _register_nginx_task_def(ctx, family, revision_tag):
    ecs = ctx.client("ecs")
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
                "environment": [{"name": "SIM2REAL_REVISION", "value": revision_tag}],
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
            }
        ],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


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
