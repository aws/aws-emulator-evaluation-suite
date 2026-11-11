"""deployment-group-tag-filter-empty-vs-absent-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-group-tag-filter-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deployment group created with an empty onPremisesInstanceTagFilters list and one created
    without it both read back with the key present and the value []."""
    cd = ctx.client("codedeploy")
    role_arn = _create_service_role(ctx)
    app = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(applicationName=app, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app))

    group_empty = ctx.unique_name("sim2real-cd-dg-empty-")
    _create_deployment_group(ctx, cd, app, group_empty, role_arn, onPremisesInstanceTagFilters=[])

    group_absent = ctx.unique_name("sim2real-cd-dg-absent-")
    _create_deployment_group(ctx, cd, app, group_absent, role_arn)

    info_empty = cd.get_deployment_group(applicationName=app, deploymentGroupName=group_empty)["deploymentGroupInfo"]
    info_absent = cd.get_deployment_group(applicationName=app, deploymentGroupName=group_absent)["deploymentGroupInfo"]

    assert "onPremisesInstanceTagFilters" in info_empty, info_empty
    assert info_empty["onPremisesInstanceTagFilters"] == [], info_empty["onPremisesInstanceTagFilters"]

    # Empirical finding: the omitted-field group is normalized to the identical [],
    # not left absent -- both representations converge.
    assert "onPremisesInstanceTagFilters" in info_absent, info_absent
    assert info_absent["onPremisesInstanceTagFilters"] == [], info_absent["onPremisesInstanceTagFilters"]
    assert info_empty["onPremisesInstanceTagFilters"] == info_absent["onPremisesInstanceTagFilters"], (
        info_empty["onPremisesInstanceTagFilters"],
        info_absent["onPremisesInstanceTagFilters"],
    )


def _create_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cd-role"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_deployment_group(ctx, cd, application_name, deployment_group_name, service_role_arn, **kwargs):
    deadline = time.monotonic() + 30
    while True:
        try:
            resp = cd.create_deployment_group(
                applicationName=application_name,
                deploymentGroupName=deployment_group_name,
                serviceRoleArn=service_role_arn,
                **kwargs,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: cd.delete_deployment_group(
        applicationName=application_name, deploymentGroupName=deployment_group_name
    ))
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
