"""deployment-group-lambda-default-config-get-batchget-agree."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-group-lambda-default-config-get-batchget-agree"
GROUP = "lifecycle"
SERVICES = ["codedeploy", "iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Lambda deployment group created BLUE_GREEN/WITH_TRAFFIC_CONTROL with no
    deploymentConfigName defaults to CodeDeployDefault.LambdaCanary10Percent5Minutes, and
    GetDeploymentGroup and BatchGetDeploymentGroups return the identical record."""
    cd = ctx.client("codedeploy")

    app = ctx.unique_name("sim2real-behav-cdapp-")
    cd.create_application(applicationName=app, computePlatform="Lambda")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app))

    role = _create_service_role(ctx)

    dg = ctx.unique_name("sim2real-behav-cddg-")
    style = {"deploymentType": "BLUE_GREEN", "deploymentOption": "WITH_TRAFFIC_CONTROL"}
    _create_deployment_group_with_retry(
        cd,
        applicationName=app,
        deploymentGroupName=dg,
        serviceRoleArn=role,
        deploymentStyle=style,
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=dg))

    get_info = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=dg
    )["deploymentGroupInfo"]
    assert get_info["applicationName"] == app, get_info
    assert get_info["deploymentGroupName"] == dg, get_info
    assert get_info["computePlatform"] == "Lambda", get_info
    assert get_info["serviceRoleArn"] == role, get_info
    assert get_info["deploymentConfigName"] == "CodeDeployDefault.LambdaCanary10Percent5Minutes", (
        f"a Lambda BLUE_GREEN deployment group created with no deploymentConfigName must "
        f"default to CodeDeployDefault.LambdaCanary10Percent5Minutes, got "
        f"{get_info['deploymentConfigName']!r}"
    )
    assert get_info["deploymentStyle"] == style, get_info["deploymentStyle"]

    batch_infos = cd.batch_get_deployment_groups(
        applicationName=app, deploymentGroupNames=[dg]
    )["deploymentGroupsInfo"]
    assert len(batch_infos) == 1, batch_infos
    assert batch_infos[0] == get_info, (
        f"BatchGetDeploymentGroups must return the identical record GetDeploymentGroup does: "
        f"{batch_infos[0]!r} != {get_info!r}"
    )

    listed = cd.list_deployment_groups(applicationName=app)
    assert listed["applicationName"] == app, listed
    assert listed["deploymentGroups"] == [dg], (
        f"a freshly-minted application can only have the one group it was just given: "
        f"{listed['deploymentGroups']!r}"
    )


def _create_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cdrole-")
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
    return resp["Role"]["Arn"]


def _create_deployment_group_with_retry(cd, **kwargs):
    # A freshly-minted service role is not immediately assumable by CodeDeploy until the
    # trust relationship propagates; retry the create through that window, but only for the
    # assume-role transient so a genuinely bad config still fails fast.
    deadline = time.monotonic() + 75
    while True:
        try:
            cd.create_deployment_group(**kwargs)
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient = err.get("Code") == "InvalidRoleException" and (
                "assume" in msg or "not authorized" in msg or "permissions required" in msg
            )
            if transient and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
