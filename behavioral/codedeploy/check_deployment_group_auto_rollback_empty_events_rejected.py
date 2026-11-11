"""deployment-group-auto-rollback-empty-events-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deployment-group-auto-rollback-empty-events-rejected"
GROUP = 'overly-permissive'
SERVICES = ['codedeploy']

# InvalidAutoRollbackConfigException also
# covers unrecognised event names, so the message is the discriminator for this cause.
_EMPTY_EVENTS_MESSAGE = (
    "Deployment Groups need to have at least one event specified when auto rollback is "
    "enabled"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """autoRollbackConfiguration {enabled: true, events: []} is refused on create and update,
    while the accepted forms round-trip as AWS normalises them: an empty disabled config is
    dropped, exactly like an omitted one, and a config naming an event echoes verbatim."""
    cd = ctx.client("codedeploy")
    app = _create_application(ctx, compute_platform="Server")

    # Control A: enabled with a real event. Also proves the role is assumable, so an
    # InvalidRoleException on the negative would be a genuine mismatch.
    enabled_cfg = {"enabled": True, "events": ["DEPLOYMENT_FAILURE"]}
    ok_enabled = _create_dg_control(ctx, app, autoRollbackConfiguration=enabled_cfg)
    echoed = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=ok_enabled
    )["deploymentGroupInfo"]
    assert echoed.get("autoRollbackConfiguration") == enabled_cfg, (
        f"autoRollbackConfiguration must round-trip verbatim, got "
        f"{echoed.get('autoRollbackConfiguration')!r}"
    )

    # Control B: explicitly disabled, no events. Accepted -- an empty events list is
    # representable -- but normalised away rather than stored, so the member is ABSENT.
    ok_disabled = _create_dg_control(
        ctx, app, autoRollbackConfiguration={"enabled": False, "events": []}
    )
    info_off = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=ok_disabled
    )["deploymentGroupInfo"]
    assert "autoRollbackConfiguration" not in info_off, (
        f"an all-empty disabled auto-rollback config carries no information, so real AWS "
        f"normalises it away and GetDeploymentGroup omits the member entirely; got "
        f"{info_off.get('autoRollbackConfiguration')!r}"
    )

    # Control B': omitting the parameter is indistinguishable from Control B. This is the
    # half of the normalisation an emulator that merely 'drops falsy structs' still gets
    # wrong if it invents a default instead.
    ok_absent = _create_dg_control(ctx, app)
    info_absent = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=ok_absent
    )["deploymentGroupInfo"]
    assert "autoRollbackConfiguration" not in info_absent, (
        f"a deployment group created with no autoRollbackConfiguration must not acquire "
        f"one, got {info_absent.get('autoRollbackConfiguration')!r}"
    )

    # Control C: disabled WITH an event round-trips verbatim. This proves the drop above
    # is about the empty events list, not about enabled=False being unrepresentable --
    # without it, "omits the member" would be satisfied by an emulator that discards
    # every disabled config.
    disabled_cfg = {"enabled": False, "events": ["DEPLOYMENT_FAILURE"]}
    ok_disabled_evt = _create_dg_control(
        ctx, app, autoRollbackConfiguration=disabled_cfg
    )
    echoed_disabled_evt = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=ok_disabled_evt
    )["deploymentGroupInfo"].get("autoRollbackConfiguration")
    assert echoed_disabled_evt == disabled_cfg, (
        f"enabled=False WITH an event is informative and must round-trip verbatim, got "
        f"{echoed_disabled_evt!r}"
    )

    before = _dg_names(cd, app)
    assert before == {ok_enabled, ok_disabled, ok_absent, ok_disabled_evt}, before

    # Break exactly one thing: keep enabled true, empty the events list.
    bad = ctx.unique_name("sim2real-behav-cd-dg-badrollback-")
    code, message = _error(
        lambda: cd.create_deployment_group(
            applicationName=app,
            deploymentGroupName=bad,
            deploymentConfigName="CodeDeployDefault.OneAtATime",
            serviceRoleArn=_create_service_role(ctx),
            autoRollbackConfiguration={"enabled": True, "events": []},
        )
    )
    assert code == "InvalidAutoRollbackConfigException", (
        f"autoRollbackConfiguration with enabled=true and no events must raise "
        f"InvalidAutoRollbackConfigException, got {code!r}"
    )
    assert message == _EMPTY_EVENTS_MESSAGE, (
        f"the rejection must name the missing event as the reason, so a caller can tell "
        f"it apart from the other InvalidAutoRollbackConfigException causes; expected "
        f"{_EMPTY_EVENTS_MESSAGE!r}, got {message!r}"
    )

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
        f"the refused group {bad} must not exist; GetDeploymentGroup answered "
        f"{missing!r}"
    )
    assert missing_message == f"No Deployment Group found for name: {bad}", missing_message

    # The control still works, and the same contradiction is refused on the update
    # path too -- an emulator that validates only on create leaves a live group
    # reachable to an invalid state.
    update_code, update_message = _error(
        lambda: cd.update_deployment_group(
            applicationName=app,
            currentDeploymentGroupName=ok_enabled,
            autoRollbackConfiguration={"enabled": True, "events": []},
        )
    )
    assert update_code == "InvalidAutoRollbackConfigException", (
        f"UpdateDeploymentGroup must apply the same auto-rollback validation as "
        f"create, got {update_code!r}"
    )
    assert update_message == _EMPTY_EVENTS_MESSAGE, update_message
    still = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=ok_enabled
    )["deploymentGroupInfo"]
    assert still.get("autoRollbackConfiguration") == enabled_cfg, (
        f"the refused update must leave the group's auto-rollback config intact, got "
        f"{still.get('autoRollbackConfiguration')!r}"
    )

    # An UPDATE to the all-empty disabled form is accepted, and applies the same
    # normalisation as create: the config the group demonstrably had is CLEARED, not
    # rewritten to enabled=False. This is how a customer actually turns auto-rollback
    # off, so an emulator that stores {enabled: False, events: []} here diverges on a
    # live group rather than only at creation time.
    cd.update_deployment_group(
        applicationName=app,
        currentDeploymentGroupName=ok_enabled,
        autoRollbackConfiguration={"enabled": False, "events": []},
    )
    cleared = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=ok_enabled
    )["deploymentGroupInfo"]
    assert "autoRollbackConfiguration" not in cleared, (
        f"updating to an all-empty disabled config must clear the member, leaving the "
        f"group indistinguishable from one that never had auto-rollback; got "
        f"{cleared.get('autoRollbackConfiguration')!r}"
    )




# ===== helpers =====
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
    arn = resp["Role"]["Arn"]
    ctx._cd_service_role_arn = arn
    return arn


def _create_dg_control(ctx, app, *, deployment_config="CodeDeployDefault.OneAtATime",
                       name=None, **extra):
    """Create a control deployment group. Provisions no compute: without
    autoScalingGroups / ecsServices there is no fleet to launch."""
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
