"""deployment-group-duplicate-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-group-duplicate-name-rejected"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeploymentGroup with an existing name raises DeploymentGroupAlreadyExistsException and leaves
    the group unchanged, while another name creates."""
    cd = ctx.client("codedeploy")

    app_name = ctx.unique_name("sim2real-cdapp-")
    cd.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    role_arn = _create_codedeploy_service_role(ctx)

    dg_name = ctx.unique_name("sim2real-cdgroup-")
    original_filter = [{"Key": "sim2real-tag", "Value": "orig", "Type": "KEY_AND_VALUE"}]
    _create_deployment_group_with_retry(
        cd,
        applicationName=app_name,
        deploymentGroupName=dg_name,
        serviceRoleArn=role_arn,
        onPremisesInstanceTagFilters=original_filter,
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_group(applicationName=app_name, deploymentGroupName=dg_name))

    code, message = _error(
        lambda: cd.create_deployment_group(
            applicationName=app_name,
            deploymentGroupName=dg_name,
            serviceRoleArn=role_arn,
            onPremisesInstanceTagFilters=[
                {"Key": "sim2real-tag", "Value": "different", "Type": "KEY_AND_VALUE"}
            ],
        )
    )
    assert code == "DeploymentGroupAlreadyExistsException", code
    assert message == (
        f"An Deployment Group with the name {dg_name} already exists for this application."
    ), message

    # Effect absent: the existing deployment group's tag filter is unchanged.
    info = cd.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)["deploymentGroupInfo"]
    assert info["onPremisesInstanceTagFilters"] == original_filter, info["onPremisesInstanceTagFilters"]

    # Positive control: creating a deployment group under a different name succeeds,
    # and an independent read at the destination confirms it actually exists.
    dg_name2 = ctx.unique_name("sim2real-cdgroup2-")
    _create_deployment_group_with_retry(
        cd,
        applicationName=app_name,
        deploymentGroupName=dg_name2,
        serviceRoleArn=role_arn,
        onPremisesInstanceTagFilters=original_filter,
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_group(applicationName=app_name, deploymentGroupName=dg_name2))

    info2 = cd.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name2)["deploymentGroupInfo"]
    assert info2["deploymentGroupName"] == dg_name2, info2["deploymentGroupName"]
    assert info2["onPremisesInstanceTagFilters"] == original_filter, info2["onPremisesInstanceTagFilters"]


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_codedeploy_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cdrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codedeploy.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_deployment_group_with_retry(cd, **kwargs):
    deadline = time.monotonic() + 60.0
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return cd.create_deployment_group(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRoleException":
                last_err = e
                time.sleep(3)
                continue
            raise
    assert last_err is not None
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
