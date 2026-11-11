"""tag-resource-unsupported-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-unsupported-arn-rejected"
GROUP = 'error-semantics'
SERVICES = ['codedeploy']

def _account_id(ctx):
    cached = getattr(ctx, "_cd_account_id", None)
    if cached is None:
        cached = ctx.account
        ctx._cd_account_id = cached
    return cached


def _deployment_config_arn(ctx, name):
    return f"arn:aws:codedeploy:{ctx.region}:{_account_id(ctx)}:deploymentconfig:{name}"


def _application_arn(ctx, name):
    return f"arn:aws:codedeploy:{ctx.region}:{_account_id(ctx)}:application:{name}"


def _create_deployment_config(ctx, *, min_healthy_type="HOST_COUNT", min_healthy_value=1):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-dpcfg-")
    cd.create_deployment_config(
        deploymentConfigName=name,
        computePlatform="Server",
        minimumHealthyHosts={"type": min_healthy_type, "value": min_healthy_value},
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_config(deploymentConfigName=name))
    return name


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-app-")
    cd.create_application(applicationName=name, computePlatform=compute_platform)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on a deploymentconfig ARN fails with ArnNotSupportedException (not a taggable
    type), while tagging an application ARN in the same account succeeds."""
    cd = ctx.client("codedeploy")

    app_name = _create_application(ctx)
    app_arn = _application_arn(ctx, app_name)
    cd.tag_resource(ResourceArn=app_arn, Tags=[{"Key": "Team", "Value": "probe-control"}])
    app_tags = {
        t["Key"]: t["Value"] for t in cd.list_tags_for_resource(ResourceArn=app_arn)["Tags"]
    }
    assert app_tags.get("Team") == "probe-control", (
        f"positive control failed: expected Team=probe-control on {app_arn}, got {app_tags}"
    )

    cfg = _create_deployment_config(ctx)
    cfg_arn = _deployment_config_arn(ctx, cfg)
    error = _client_error(
        lambda: cd.tag_resource(
            ResourceArn=cfg_arn,
            Tags=[{"Key": "Team", "Value": "probe-config"}],
        )
    )
    assert error == (
        "ArnNotSupportedException",
        f"The ARN: {cfg_arn} is not supported by CodeDeploy",
    ), f"expected ArnNotSupportedException tagging a deploymentconfig ARN, got {error!r}"

    read_error = _client_error(lambda: cd.list_tags_for_resource(ResourceArn=cfg_arn))
    assert read_error == (
        "ArnNotSupportedException",
        f"Not a CodeDeploy ARN: {cfg_arn}",
    ), (
        f"expected ArnNotSupportedException reading tags on a deploymentconfig ARN, got "
        f"{read_error!r}"
    )

    cfg_still = cd.get_deployment_config(deploymentConfigName=cfg)["deploymentConfigInfo"]
    assert cfg_still["deploymentConfigName"] == cfg, (
        f"the refused tag call left the deployment config unreadable: {cfg_still}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
