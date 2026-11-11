"""deployment-group-nonexistent-deployment-config-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deployment-group-nonexistent-deployment-config-rejected"
GROUP = 'overly-permissive'
SERVICES = ['codedeploy']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeploymentGroup naming an absent deploymentConfigName raises
    DeploymentConfigDoesNotExistException naming it and creates no group, while the same request with
    a real config creates one and the existing group keeps its config."""
    cd = ctx.client("codedeploy")
    app = _create_application(ctx, compute_platform="Server")
    absent_cfg = ctx.unique_name("sim2real-behav-cd-cfg-absent-")

    # Establish that a real config is accepted, which also proves the service role is
    # assumable so an InvalidRoleException below would be a real mismatch.
    real_cfg = _create_deployment_config(
        ctx, compute_platform="Server",
        minimum_healthy_hosts={"type": "HOST_COUNT", "value": 1},
    )
    control = _create_dg_control(ctx, app, deployment_config=real_cfg)
    echoed = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=control
    )["deploymentGroupInfo"]
    assert echoed.get("deploymentConfigName") == real_cfg, (
        f"deploymentConfigName must round-trip, got "
        f"{echoed.get('deploymentConfigName')!r}"
    )

    before = _dg_names(cd, app)
    assert before == {control}, before

    # Confirm the negative's config really is absent, so the rejection is about
    # reference integrity and not about a name collision.
    absent_code, absent_message = _error(
        lambda: cd.get_deployment_config(deploymentConfigName=absent_cfg)
    )
    assert absent_code == "DeploymentConfigDoesNotExistException", (
        f"precondition: {absent_cfg} must not exist; GetDeploymentConfig answered "
        f"{absent_code!r}"
    )
    assert absent_message == f"No deployment configuration found for name: {absent_cfg}", (
        absent_message
    )

    # Break exactly one thing: point at the absent config.
    bad = ctx.unique_name("sim2real-behav-cd-dg-badcfg-")
    code, message = _error(
        lambda: cd.create_deployment_group(
            applicationName=app,
            deploymentGroupName=bad,
            deploymentConfigName=absent_cfg,
            serviceRoleArn=_create_service_role(ctx),
        )
    )
    assert code == "DeploymentConfigDoesNotExistException", (
        f"a deployment group naming an absent deployment config must raise "
        f"DeploymentConfigDoesNotExistException, got {code!r}"
    )
    assert message == f"No deployment configuration found for name: {absent_cfg}", message

    # The effect is absent.
    after = _dg_names(cd, app)
    assert after == before, (
        f"a refused CreateDeploymentGroup must not change ListDeploymentGroups: "
        f"{before!r} -> {after!r}"
    )
    missing, missing_message = _error(
        lambda: cd.get_deployment_group(applicationName=app, deploymentGroupName=bad)
    )
    assert missing == "DeploymentGroupDoesNotExistException", (
        f"the refused group {bad} must not exist; GetDeploymentGroup answered {missing!r}"
    )
    assert missing_message == f"No Deployment Group found for name: {bad}", missing_message

    # The control still works: the same shape with a real config is accepted, and the
    # existing group is undisturbed.
    second = _create_dg_control(ctx, app, deployment_config=real_cfg)
    assert _dg_names(cd, app) == before | {second}, (
        "the control CreateDeploymentGroup with a real config must be accepted"
    )
    still = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=control
    )["deploymentGroupInfo"]
    assert still.get("deploymentConfigName") == real_cfg, still


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


# _error raises on an unexpected success.

def _error(fn):
    """(code, message) of the raised ClientError. An unexpected SUCCESS raises, because a
    target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _dg_names(cd, app):
    names = set()
    token = None
    while True:
        kwargs = {"applicationName": app}
        if token:
            kwargs["nextToken"] = token
        page = cd.list_deployment_groups(**kwargs)
        names.update(page.get("deploymentGroups") or [])
        token = page.get("nextToken")
        if not token:
            return names


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cd-app-")
    cd.create_application(applicationName=name, computePlatform=compute_platform)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _create_deployment_config(ctx, *, compute_platform, traffic_routing_config=None,
                              minimum_healthy_hosts=None):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cd-cfg-")
    kwargs = {"deploymentConfigName": name, "computePlatform": compute_platform}
    if traffic_routing_config is not None:
        kwargs["trafficRoutingConfig"] = traffic_routing_config
    if minimum_healthy_hosts is not None:
        kwargs["minimumHealthyHosts"] = minimum_healthy_hosts
    cd.create_deployment_config(**kwargs)
    ctx.on_cleanup(lambda: cd.delete_deployment_config(deploymentConfigName=name))
    return name


def _create_service_role(ctx):
    cached = getattr(ctx, "_cd_service_role_arn", None)
    if cached:
        return cached
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
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
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
    # IAM propagation delay is absorbed by _create_dg_control's bounded
    # InvalidRoleException retry (deadline below), not an unconditional sleep here.
    arn = resp["Role"]["Arn"]
    ctx._cd_service_role_arn = arn
    return arn


def _create_dg_control(ctx, app, *, deployment_config="CodeDeployDefault.OneAtATime",
                       name=None, **extra):
    cd = ctx.client("codedeploy")
    name = name or ctx.unique_name("sim2real-behav-cd-dg-")
    kwargs = {
        "applicationName": app,
        "deploymentGroupName": name,
        "deploymentConfigName": deployment_config,
        "serviceRoleArn": _create_service_role(ctx),
    }
    kwargs.update(extra)
    deadline = time.monotonic() + 75
    while True:
        try:
            cd.create_deployment_group(**kwargs)
            break
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
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=name)
    )
    return name
