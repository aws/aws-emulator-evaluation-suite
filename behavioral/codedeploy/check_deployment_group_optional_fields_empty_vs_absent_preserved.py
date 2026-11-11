"""deployment-group-optional-fields-empty-vs-absent-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-group-optional-fields-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDeploymentGroup distinguishes omitting ec2TagFilters (keep the existing
    set unchanged) from explicitly passing an empty list (clear it), as documented for
    the operation's replacement-list semantics."""
    codedeploy = ctx.client("codedeploy")

    app_name = ctx.unique_name("sim2real-cdapp-")
    codedeploy.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cdapp"}],
    )
    ctx.on_cleanup(lambda: codedeploy.delete_application(applicationName=app_name))

    role_arn = _create_codedeploy_service_role(ctx)

    dg_name = ctx.unique_name("sim2real-cddg-")
    original_filters = [{"Key": "sim2real-key", "Value": ctx.unique_name("sim2real-val-"), "Type": "KEY_AND_VALUE"}]
    _create_deployment_group_with_retry(
        codedeploy,
        applicationName=app_name,
        deploymentGroupName=dg_name,
        serviceRoleArn=role_arn,
        ec2TagFilters=original_filters,
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cddg"}],
    )
    ctx.on_cleanup(lambda: codedeploy.delete_deployment_group(applicationName=app_name, deploymentGroupName=dg_name))

    before = codedeploy.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)
    assert before["deploymentGroupInfo"].get("ec2TagFilters") == original_filters, (
        f"expected freshly-created ec2TagFilters={original_filters!r}, "
        f"got {before['deploymentGroupInfo'].get('ec2TagFilters')!r}"
    )

    # 1) Omit ec2TagFilters entirely while changing an unrelated field -> preserved.
    codedeploy.update_deployment_group(
        applicationName=app_name,
        currentDeploymentGroupName=dg_name,
        deploymentConfigName="CodeDeployDefault.AllAtOnce",
    )
    after_omit = codedeploy.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)
    assert after_omit["deploymentGroupInfo"].get("ec2TagFilters") == original_filters, (
        "omitting ec2TagFilters on update must preserve the existing set"
    )

    # 2) Explicitly pass an empty list -> cleared.
    codedeploy.update_deployment_group(
        applicationName=app_name,
        currentDeploymentGroupName=dg_name,
        ec2TagFilters=[],
    )
    after_clear = codedeploy.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)
    cleared_info = after_clear["deploymentGroupInfo"]
    assert "ec2TagFilters" in cleared_info, (
        f"expected the cleared ec2TagFilters key to still be present (as []), got keys {sorted(cleared_info)}"
    )
    assert cleared_info["ec2TagFilters"] == [], (
        f"an explicit empty ec2TagFilters list on update must clear the filter set, "
        f"got {cleared_info['ec2TagFilters']!r}"
    )


def _create_codedeploy_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cdrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-cdrole"}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_deployment_group_with_retry(codedeploy, *, timeout_s=45.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return codedeploy.create_deployment_group(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRoleException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
