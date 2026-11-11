"""create-deployment-group-ecs-without-load-balancer-info-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "create-deployment-group-ecs-without-load-balancer-info-rejected"
GROUP = "validation"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeploymentGroup for computePlatform=ECS without loadBalancerInfo is rejected and
    creates no group, while a Server-platform IN_PLACE group with the same omission succeeds."""
    cd = ctx.client("codedeploy")
    role_arn = _create_service_role(ctx)

    ecs_app = _create_application(ctx, compute_platform="ECS")
    ecs_dg_name = ctx.unique_name("sim2real-behav-dg-")
    code, message = _error(lambda: _create_deployment_group_with_role_retry(
        ctx, cd,
        applicationName=ecs_app,
        deploymentGroupName=ecs_dg_name,
        serviceRoleArn=role_arn,
        deploymentStyle={"deploymentType": "BLUE_GREEN", "deploymentOption": "WITH_TRAFFIC_CONTROL"},
        ecsServices=[{"serviceName": ctx.unique_name("sim2real-behav-svc-"), "clusterName": ctx.unique_name("sim2real-behav-cluster-")}],
    ))
    assert code == "InvalidLoadBalancerInfoException", (
        f"expected an ECS deployment group with no loadBalancerInfo to be rejected "
        f"InvalidLoadBalancerInfoException, got {code!r}"
    )
    expected = "For ECS deployment group, loadBalancerInfo must be specified"
    assert message == expected, f"the refusal says {message!r}, expected {expected!r}"

    listed = cd.list_deployment_groups(applicationName=ecs_app)["deploymentGroups"]
    assert ecs_dg_name not in listed, (
        f"rejected deployment group {ecs_dg_name!r} must not exist, but ListDeploymentGroups "
        f"returned {listed!r}"
    )

    # Positive control: the same omission (no load balancer) is legitimate for a Server
    # platform deployment group under IN_PLACE, proving the rejection above is about the
    # ECS/load-balancer combination rather than a blanket rejection of a missing
    # loadBalancerInfo.
    server_app = _create_application(ctx, compute_platform="Server")
    server_dg_name = ctx.unique_name("sim2real-behav-dg-")
    _create_deployment_group_with_role_retry(
        ctx, cd,
        applicationName=server_app,
        deploymentGroupName=server_dg_name,
        serviceRoleArn=role_arn,
        deploymentStyle={"deploymentType": "IN_PLACE", "deploymentOption": "WITHOUT_TRAFFIC_CONTROL"},
        ec2TagFilters=[{"Key": "sim2real-nonexistent", "Value": "none", "Type": "KEY_AND_VALUE"}],
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_group(applicationName=server_app, deploymentGroupName=server_dg_name))
    info = cd.get_deployment_group(applicationName=server_app, deploymentGroupName=server_dg_name)["deploymentGroupInfo"]
    assert info["deploymentGroupName"] == server_dg_name, info


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)



def _error(fn):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_deployment_group_with_role_retry(ctx, cd, **kwargs):
    """CreateDeploymentGroup, retrying only InvalidRoleException while a just-created service
    role's trust propagates, so a genuine validation error still surfaces immediately."""
    deadline = time.monotonic() + 75  # the minted role's trust propagates within ~a minute
    while True:
        try:
            return cd.create_deployment_group(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            msg = (err.get("Message") or "").lower()
            transient_role = code == "InvalidRoleException" or ("assume" in msg or "not authorized" in msg)
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-app-")
    cd.create_application(applicationName=name, computePlatform=compute_platform)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _create_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-codedeploy-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codedeploy.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )

    def _del_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codedeploy-inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )
    # CreateDeploymentGroup retries the assume-role transient on its own (bounded), so a target
    # that is consistent at once pays nothing; no other call here touches the role.
    return resp["Role"]["Arn"]
