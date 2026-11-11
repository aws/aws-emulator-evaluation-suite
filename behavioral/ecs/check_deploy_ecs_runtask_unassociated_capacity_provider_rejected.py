"""deploy-ecs-runtask-unassociated-capacity-provider-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-ecs-runtask-unassociated-capacity-provider-rejected"
GROUP = "deploy"
SERVICES = ["ecs"]

_CLUSTER_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
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
"""


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask with a capacityProviderStrategy naming a provider never associated with the cluster is rejected."""
    cluster_name = ctx.unique_name("sim2real-ecs-neg-cl-")
    _stack_name, outputs = _deploy_stack(
        ctx, _CLUSTER_TEMPLATE, params={"ClusterName": cluster_name}
    )
    cluster_arn = outputs["ClusterArn"]

    ecs = ctx.client("ecs")
    task_def_arn = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-ecs-neg-td-"))
    subnets, sg_id = _default_network_config(ctx)
    network_config = {
        "awsvpcConfiguration": {
            "subnets": subnets,
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }

    # FARGATE_SPOT exists account-wide but is never associated with a brand-new cluster
    # unless explicitly attached via PutClusterCapacityProviders / the CFN CapacityProviders
    # property -- this cluster was created with neither.
    strategy = [{"capacityProvider": "FARGATE_SPOT", "weight": 1}]

    def _attempt_with_strategy():
        return ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=task_def_arn,
            count=1,
            capacityProviderStrategy=strategy,
            networkConfiguration=network_config,
        )

    code, message = _error(_attempt_with_strategy)
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a strategy naming a capacity provider never "
        f"associated with the cluster, got {code!r}"
    )
    assert message == "The specified capacity provider strategy cannot contain a capacity provider that is not associated with the cluster. Associate the capacity provider with the cluster or specify a valid capacity provider and try again.", f"unexpected message: {message!r}"

    # the rejected call must not have placed any task on the cluster
    task_arns = ecs.list_tasks(cluster=cluster_arn)["taskArns"]
    assert task_arns == [], f"expected no tasks placed by the rejected RunTask, got {task_arns!r}"

    # positive control: the same cluster/task definition DOES accept a plain FARGATE launch,
    # so the negative above is attributable to the missing association, not a broken cluster
    run_resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration=network_config,
    )
    assert run_resp["failures"] == [], f"RunTask failures: {run_resp['failures']}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_and_drain(ctx, cluster_arn, task_arn))
    task = _wait_task_status(ctx, cluster_arn, task_arn, "RUNNING", timeout_s=300.0)
    assert task["lastStatus"] == "RUNNING", f"expected RUNNING, got {task['lastStatus']!r}"

    # restore: associate FARGATE_SPOT with the cluster, then the IDENTICAL strategy call that
    # was just rejected must now succeed -- proving the rejection tracked the association, not
    # a blanket refusal of capacityProviderStrategy on this cluster
    ecs.put_cluster_capacity_providers(
        cluster=cluster_arn,
        capacityProviders=["FARGATE_SPOT"],
        defaultCapacityProviderStrategy=[],
    )
    spot_resp = _run_until_capacity_provider_ready(_attempt_with_strategy, timeout_s=120.0)
    assert spot_resp["failures"] == [], f"RunTask failures after association: {spot_resp['failures']}"
    spot_task_arn = spot_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_and_drain(ctx, cluster_arn, spot_task_arn))
    spot_task = _wait_task_status(ctx, cluster_arn, spot_task_arn, "RUNNING", timeout_s=300.0)
    assert spot_task["lastStatus"] == "RUNNING", (
        f"expected RUNNING after associating FARGATE_SPOT, got {spot_task['lastStatus']!r}"
    )


# ===== helpers =====

def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not be reported as an
    error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _deploy_stack(ctx, template_body: str, params: dict[str, str] | None = None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ecs-stack-")
    kwargs: dict[str, Any] = {"StackName": stack_name, "TemplateBody": template_body}
    if params:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in params.items()
        ]

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(**kwargs)
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
    return stack_name, outputs


def _register_fargate_task_def(ctx, family: str) -> str:
    ecs = ctx.client("ecs")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["sleep", "900"],
            }
        ],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_def(ecs, arn))
    return arn


def _retire_task_def(ecs, arn: str) -> None:
    """Deregister, then delete, one task definition revision, so no INACTIVE revision lingers."""
    ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures") or []
    if failures:
        raise RuntimeError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _default_network_config(ctx) -> tuple[list[str], str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region to attach Fargate ENIs to"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_ids, sgs[0]["GroupId"]


def _run_until_capacity_provider_ready(attempt, timeout_s=120.0, interval_s=5.0):
    """PutClusterCapacityProviders is not instantaneous: RunTask can still see the pre-association
    state for a few seconds after the API call returns. Retry only the transient rejection --
    any other ClientError is a real defect and must propagate."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return attempt()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code != "InvalidParameterException":
                raise
            last_code = code
            time.sleep(interval_s)
    raise AssertionError(
        f"RunTask with the newly-associated FARGATE_SPOT strategy still rejected as "
        f"{last_code!r} after {timeout_s}s"
    )


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _wait_task_status(ctx, cluster: str, task_arn: str, target_status: str, timeout_s=300.0):
    ecs = ctx.client("ecs")

    def probe():
        resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        return resp["tasks"][0] if resp["tasks"] else None

    def done(task):
        return task is not None and task["lastStatus"] == target_status

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=5.0)


def _stop_and_drain(ctx, cluster: str, task_arn: str) -> None:
    ecs = ctx.client("ecs")
    try:
        ecs.stop_task(cluster=cluster, task=task_arn, reason="sim2real-behav-cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise
    try:
        _wait_task_status(ctx, cluster, task_arn, "STOPPED", timeout_s=180.0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
