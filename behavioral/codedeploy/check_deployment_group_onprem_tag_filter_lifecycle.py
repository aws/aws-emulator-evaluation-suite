"""deployment-group-onprem-tag-filter-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-group-onprem-tag-filter-lifecycle"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """onPremisesInstanceTagFilters from create and from a later update read back verbatim; after delete
    GetDeploymentGroup and UpdateDeploymentGroup raise DeploymentGroupDoesNotExistException."""
    cd = ctx.client("codedeploy")
    check_tag = [{"Key": "sim2real-check", "Value": CHECK}]

    app_name = ctx.unique_name("sim2real-cdapp-")
    cd.create_application(applicationName=app_name, computePlatform="Server", tags=check_tag)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    role_arn = _create_codedeploy_service_role(ctx)

    dg_name = ctx.unique_name("sim2real-cdgroup-")
    filter_a = [{"Key": "sim2real-tag", "Value": "filter-a", "Type": "KEY_AND_VALUE"}]
    _create_deployment_group_with_retry(
        cd,
        applicationName=app_name,
        deploymentGroupName=dg_name,
        serviceRoleArn=role_arn,
        onPremisesInstanceTagFilters=filter_a,
        tags=check_tag,
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_group(applicationName=app_name, deploymentGroupName=dg_name))

    info = cd.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)["deploymentGroupInfo"]
    assert info["onPremisesInstanceTagFilters"] == filter_a, info["onPremisesInstanceTagFilters"]

    filter_b = [{"Key": "sim2real-tag", "Value": "filter-b", "Type": "KEY_AND_VALUE"}]
    cd.update_deployment_group(
        applicationName=app_name,
        currentDeploymentGroupName=dg_name,
        onPremisesInstanceTagFilters=filter_b,
    )

    info2 = cd.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)["deploymentGroupInfo"]
    assert info2["onPremisesInstanceTagFilters"] == filter_b, info2["onPremisesInstanceTagFilters"]

    cd.delete_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)

    not_found, not_found_message = _error(
        lambda: cd.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)
    )
    assert not_found == "DeploymentGroupDoesNotExistException", not_found
    assert not_found_message == f"No Deployment Group found for name: {dg_name}", not_found_message

    mutate_not_found, mutate_message = _error(
        lambda: cd.update_deployment_group(
            applicationName=app_name,
            currentDeploymentGroupName=dg_name,
            onPremisesInstanceTagFilters=filter_a,
        )
    )
    assert mutate_not_found == "DeploymentGroupDoesNotExistException", mutate_not_found
    assert mutate_message == f"No Deployment Group found for name: {dg_name}", mutate_message


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a not-found rejection, but the call SUCCEEDED: {result!r}")


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
