"""deployment-group-blue-green-config-without-blue-green-style-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deployment-group-blue-green-config-without-blue-green-style-rejected"
GROUP = 'overly-permissive'
SERVICES = ['codedeploy']

# greenFleetProvisioningOption DISCOVER_EXISTING provisions nothing; COPY_AUTO_SCALING_GROUP
# would duplicate an Auto Scaling group and bill EC2 if the call were accepted.
BLUE_GREEN_CONFIG = {
    "terminateBlueInstancesOnDeploymentSuccess": {
        "action": "KEEP_ALIVE",
    },
    "deploymentReadyOption": {
        "actionOnTimeout": "CONTINUE_DEPLOYMENT",
    },
    "greenFleetProvisioningOption": {
        "action": "DISCOVER_EXISTING",
    },
}

# The messages attribute each rejection to its cause (the platform, or the style pairing), so
# they are asserted alongside the codes.
_LAMBDA_BG_MESSAGE = (
    "For Lambda deployment group, blueGreenDeploymentConfiguration can not be specified"
)
_NO_TRAFFIC_CONTROL_MESSAGE = (
    "BLUE_GREEN deployment type not supported with WITHOUT_TRAFFIC_CONTROL option"
)

# CreateDeploymentGroup validates the target group NAME (length) but not its EXISTENCE.
_TARGET_GROUP_NAME_MAX = 32
_TARGET_GROUP_TOO_LONG_MESSAGE = (
    "The target group name {name} specified in targetGroupInfoList exceeds the maximum "
    "allowed length of 32 characters."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """blueGreenDeploymentConfiguration is gated by compute platform, not deploymentStyle: a Lambda
    group rejects it under either style while a Server group accepts it even under IN_PLACE, and
    BLUE_GREEN requires WITH_TRAFFIC_CONTROL.

    Reference: https://docs.aws.amazon.com/codedeploy/latest/APIReference/API_CreateDeploymentGroup.html
    """
    cd = ctx.client("codedeploy")
    app = _create_application(ctx, compute_platform="Server")

    # Control: the blue/green struct under the style it belongs to. loadBalancerInfo names
    # a target group that does not exist -- accepted, because CreateDeploymentGroup does
    # not resolve it -- which is what keeps this check free of an ELB.
    # Kept under 32 characters on purpose -- see the length assertion below.
    absent_target_group = ctx.unique_name("sim2real-notg-")
    assert len(absent_target_group) <= _TARGET_GROUP_NAME_MAX, absent_target_group
    ok_bg = _create_dg_control(
        ctx, app,
        deploymentStyle={
            "deploymentType": "BLUE_GREEN",
            "deploymentOption": "WITH_TRAFFIC_CONTROL",
        },
        blueGreenDeploymentConfiguration=BLUE_GREEN_CONFIG,
        loadBalancerInfo={"targetGroupInfoList": [{"name": absent_target_group}]},
    )
    echoed = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=ok_bg
    )["deploymentGroupInfo"]
    assert echoed.get("deploymentStyle") == {
        "deploymentType": "BLUE_GREEN",
        "deploymentOption": "WITH_TRAFFIC_CONTROL",
    }, f"deploymentStyle must round-trip verbatim, got {echoed.get('deploymentStyle')!r}"
    assert echoed.get("loadBalancerInfo") == {
        "targetGroupInfoList": [{"name": absent_target_group}]
    }, (
        f"loadBalancerInfo must round-trip verbatim -- CreateDeploymentGroup records the "
        f"target group name without resolving it -- got "
        f"{echoed.get('loadBalancerInfo')!r}"
    )
    got_bg = echoed.get("blueGreenDeploymentConfiguration") or {}
    assert got_bg.get("greenFleetProvisioningOption", {}).get("action") == (
        "DISCOVER_EXISTING"
    ), (
        f"greenFleetProvisioningOption must round-trip as DISCOVER_EXISTING (a value "
        f"that provisions nothing), got {got_bg!r}"
    )
    assert got_bg.get("terminateBlueInstancesOnDeploymentSuccess", {}).get("action") == (
        "KEEP_ALIVE"
    ), got_bg
    # Not a verbatim echo: the service supplies these two defaults. An emulator that
    # returns the request unchanged omits them.
    assert got_bg["terminateBlueInstancesOnDeploymentSuccess"].get(
        "terminationWaitTimeInMinutes"
    ) == 0, (
        f"the service must default terminationWaitTimeInMinutes to 0, got {got_bg!r}"
    )
    assert got_bg.get("deploymentReadyOption", {}).get("waitTimeInMinutes") == 0, (
        f"the service must default deploymentReadyOption.waitTimeInMinutes to 0, got "
        f"{got_bg!r}"
    )

    # The other half of that measurement: the name is not resolved, but it IS validated.
    # A 33-character target group name is refused, which proves the acceptance above is a
    # deliberate deferral of the existence check rather than no validation at all.
    too_long = "s" * (_TARGET_GROUP_NAME_MAX + 1)
    tg_code, tg_message = _error(
        lambda: cd.create_deployment_group(
            applicationName=app,
            deploymentGroupName=ctx.unique_name("sim2real-behav-cd-dg-longtg-"),
            deploymentConfigName="CodeDeployDefault.OneAtATime",
            serviceRoleArn=_create_service_role(ctx),
            deploymentStyle={
                "deploymentType": "BLUE_GREEN",
                "deploymentOption": "WITH_TRAFFIC_CONTROL",
            },
            blueGreenDeploymentConfiguration=BLUE_GREEN_CONFIG,
            loadBalancerInfo={"targetGroupInfoList": [{"name": too_long}]},
        )
    )
    assert tg_code == "InvalidLoadBalancerInfoException", (
        f"a target group name over {_TARGET_GROUP_NAME_MAX} characters must raise "
        f"InvalidLoadBalancerInfoException, got {tg_code!r} -- the name is syntax-checked "
        f"at create time even though its existence is not"
    )
    assert tg_message == _TARGET_GROUP_TOO_LONG_MESSAGE.format(name=too_long), tg_message

    # Control 2: an IN_PLACE group with no blue/green struct at all.
    ok_inplace = _create_dg_control(
        ctx, app,
        deploymentStyle={
            "deploymentType": "IN_PLACE",
            "deploymentOption": "WITHOUT_TRAFFIC_CONTROL",
        },
    )

    # Control 3: Server + IN_PLACE + blue/green struct is ACCEPTED and stored. This makes the
    # Lambda rejection below specifically about the PLATFORM rather than deploymentStyle.
    ok_inplace_bg = _create_dg_control(
        ctx, app,
        deploymentStyle={
            "deploymentType": "IN_PLACE",
            "deploymentOption": "WITHOUT_TRAFFIC_CONTROL",
        },
        blueGreenDeploymentConfiguration=BLUE_GREEN_CONFIG,
    )
    inplace_echo = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=ok_inplace_bg
    )["deploymentGroupInfo"]
    assert inplace_echo.get("deploymentStyle", {}).get("deploymentType") == "IN_PLACE", (
        f"the style must be stored as sent, got {inplace_echo.get('deploymentStyle')!r}"
    )
    assert (inplace_echo.get("blueGreenDeploymentConfiguration") or {}).get(
        "greenFleetProvisioningOption", {}
    ).get("action") == "DISCOVER_EXISTING", (
        f"a Server deployment group keeps its blueGreenDeploymentConfiguration even under "
        f"IN_PLACE, got {inplace_echo.get('blueGreenDeploymentConfiguration')!r}"
    )

    before = _dg_names(cd, app)
    assert before == {ok_bg, ok_inplace, ok_inplace_bg}, before

    # Break exactly one thing: BLUE_GREEN without traffic control. This IS the enforced
    # style pairing.
    bad_style = ctx.unique_name("sim2real-behav-cd-dg-bgnotc-")
    _register_dg_teardown(ctx, cd, app, bad_style)
    style_code, style_message = _error(
        lambda: cd.create_deployment_group(
            applicationName=app,
            deploymentGroupName=bad_style,
            deploymentConfigName="CodeDeployDefault.OneAtATime",
            serviceRoleArn=_create_service_role(ctx),
            deploymentStyle={
                "deploymentType": "BLUE_GREEN",
                "deploymentOption": "WITHOUT_TRAFFIC_CONTROL",
            },
            blueGreenDeploymentConfiguration=BLUE_GREEN_CONFIG,
        )
    )
    assert style_code == "InvalidDeploymentStyleException", (
        f"BLUE_GREEN requires WITH_TRAFFIC_CONTROL, so the pairing must raise "
        f"InvalidDeploymentStyleException, got {style_code!r}"
    )
    assert style_message == _NO_TRAFFIC_CONTROL_MESSAGE, (
        f"the rejection must name the unsupported combination; expected "
        f"{_NO_TRAFFIC_CONTROL_MESSAGE!r}, got {style_message!r}"
    )

    # --- The rejection this check's error code belongs to: it is platform-scoped. ---
    lambda_app = _create_application(ctx, compute_platform="Lambda")
    lambda_before = _dg_names(cd, lambda_app)
    assert lambda_before == set(), lambda_before

    # Proven under BOTH styles, so an emulator cannot pass by keying on deploymentStyle.
    for style in (
        {"deploymentType": "BLUE_GREEN", "deploymentOption": "WITH_TRAFFIC_CONTROL"},
        {"deploymentType": "IN_PLACE", "deploymentOption": "WITHOUT_TRAFFIC_CONTROL"},
    ):
        bad = ctx.unique_name("sim2real-behav-cd-dg-bgmismatch-")
        _register_dg_teardown(ctx, cd, lambda_app, bad)
        code, message = _error(
            lambda: cd.create_deployment_group(
                applicationName=lambda_app,
                deploymentGroupName=bad,
                deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
                serviceRoleArn=_create_service_role(ctx),
                deploymentStyle=style,
                blueGreenDeploymentConfiguration=BLUE_GREEN_CONFIG,
            )
        )
        assert code == "InvalidBlueGreenDeploymentConfigurationException", (
            f"a Lambda deployment group may not carry a blueGreenDeploymentConfiguration "
            f"under any style, so {style['deploymentType']} must raise "
            f"InvalidBlueGreenDeploymentConfigurationException, got {code!r}"
        )
        assert message == _LAMBDA_BG_MESSAGE, (
            f"the rejection must attribute itself to the compute platform, not the style; "
            f"expected {_LAMBDA_BG_MESSAGE!r}, got {message!r}"
        )

        # The effect is absent.
        assert _dg_names(cd, lambda_app) == lambda_before, (
            f"a refused CreateDeploymentGroup must not change ListDeploymentGroups: "
            f"{lambda_before!r} -> {_dg_names(cd, lambda_app)!r}"
        )
        missing, missing_message = _error(
            lambda: cd.get_deployment_group(
                applicationName=lambda_app, deploymentGroupName=bad
            )
        )
        assert missing == "DeploymentGroupDoesNotExistException", (
            f"the refused group {bad} must not exist; GetDeploymentGroup answered "
            f"{missing!r}"
        )
        assert missing_message == f"No Deployment Group found for name: {bad}", missing_message

    # The Lambda control: the same group WITHOUT the struct is accepted, so the platform
    # is not what was refused -- the struct on that platform is.
    ok_lambda = _create_dg_control(
        ctx, lambda_app,
        deployment_config="CodeDeployDefault.LambdaAllAtOnce",
        deploymentStyle={
            "deploymentType": "BLUE_GREEN",
            "deploymentOption": "WITH_TRAFFIC_CONTROL",
        },
    )
    lambda_echo = cd.get_deployment_group(
        applicationName=lambda_app, deploymentGroupName=ok_lambda
    )["deploymentGroupInfo"]
    assert lambda_echo.get("deploymentStyle") == {
        "deploymentType": "BLUE_GREEN",
        "deploymentOption": "WITH_TRAFFIC_CONTROL",
    }, lambda_echo
    assert "blueGreenDeploymentConfiguration" not in lambda_echo, (
        f"a Lambda deployment group cannot hold one even implicitly, got "
        f"{lambda_echo.get('blueGreenDeploymentConfiguration')!r}"
    )

    # The Server controls are undisturbed.
    assert _dg_names(cd, app) == before, (
        f"the Server application's groups changed: {before!r} -> {_dg_names(cd, app)!r}"
    )
    still = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=ok_bg
    )["deploymentGroupInfo"]
    assert still.get("deploymentStyle", {}).get("deploymentType") == "BLUE_GREEN", (
        f"the control group was disturbed by the refused calls: {still!r}"
    )
    assert (still.get("blueGreenDeploymentConfiguration") or {}).get(
        "greenFleetProvisioningOption", {}
    ).get("action") == "DISCOVER_EXISTING", still


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


def _register_dg_teardown(ctx, cd, app, name):
    """Teardown for a group we EXPECT not to exist. DeleteApplication already cascades
    to its deployment groups, but if a permissive target accepts the refused call this
    removes it explicitly rather than relying on the cascade."""
    def _teardown():
        try:
            cd.delete_deployment_group(applicationName=app, deploymentGroupName=name)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("DeploymentGroupDoesNotExistException",
                            "ApplicationDoesNotExistException"):
                raise

    ctx.on_cleanup(_teardown)


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cd-app-")
    cd.create_application(applicationName=name, computePlatform=compute_platform)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
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
    # IAM propagation is bounded by _create_dg_control's InvalidRoleException retry loop.
    arn = resp["Role"]["Arn"]
    ctx._cd_service_role_arn = arn
    return arn


def _create_dg_control(ctx, app, *, deployment_config="CodeDeployDefault.OneAtATime",
                       name=None, **extra):
    """Create a control deployment group. Provisions no compute: without
    autoScalingGroups / ecsServices there is no fleet to launch, and no deployment is
    ever created against it."""
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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
