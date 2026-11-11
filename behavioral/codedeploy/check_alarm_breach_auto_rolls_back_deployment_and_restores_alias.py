"""alarm-breach-auto-rolls-back-deployment-and-restores-alias."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "alarm-breach-auto-rolls-back-deployment-and-restores-alias"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")
CANARY_PERCENTAGE = 10
CANARY_INTERVAL_MINUTES = 1
# An alarm breach mid-shift ends the deployment 'Stopped' (not 'Failed') with ALARM_ACTIVE; the
# stopped deployment's rollbackInfo names rollbackDeploymentId, and the rollback deployment points
# back via rollbackTriggeringDeploymentId.
_ROLLED_BACK_STATUS = "Stopped"
_ROLLED_BACK_CODE = "ALARM_ACTIVE"
_ROLLBACK_CREATOR = "codeDeployRollback"


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-configurations.html
@tags("axis:happy-path", "concern:metrics", "plane:control", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """Breaching the deployment group's alarm mid-canary stops the deployment (ALARM_ACTIVE), spawns
    a codeDeployRollback deployment linked both ways, and restores the alias; an identical leg with
    the alarm at OK succeeds first.

    Reference: https://docs.aws.amazon.com/codedeploy/latest/userguide/deployments-rollback-and-redeploy.html
    """
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    v3 = _publish_version(lam, fn, 3)
    assert len({v1, v2, v3}) == 3, f"setup: versions collided: {(v1, v2, v3)!r}"

    alarm = ctx.unique_name("sim2real-behav-cd-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm,
        # A namespace that never receives a datapoint: nothing to leave behind, and the
        # alarm's state is therefore entirely under SetAlarmState's control.
        Namespace="sim2real/codedeploy/no-datapoints",
        MetricName="never-published",
        Statistic="Sum",
        Period=300,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        AlarmDescription="sim2real codedeploy auto-rollback trigger",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_alarm(cw, alarm))

    app = _create_application(ctx, compute_platform="Lambda")
    cfg = _create_deployment_config(
        ctx,
        compute_platform="Lambda",
        traffic_routing_config={
            "type": "TimeBasedCanary",
            "timeBasedCanary": {"canaryPercentage": CANARY_PERCENTAGE,
                                "canaryInterval": CANARY_INTERVAL_MINUTES},
        },
    )
    dg = _create_deployment_group(
        ctx, app, deployment_config=cfg,
        alarmConfiguration={"enabled": True, "alarms": [{"name": alarm}]},
        autoRollbackConfiguration={"enabled": True,
                                   "events": ["DEPLOYMENT_STOP_ON_ALARM"]})
    group_info = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=dg)["deploymentGroupInfo"]
    assert [a["name"] for a in group_info.get("alarmConfiguration", {}).get("alarms", [])] \
        == [alarm], (
        f"the deployment group echoed alarmConfiguration "
        f"{group_info.get('alarmConfiguration')!r}, expected exactly the alarm {alarm!r}"
    )
    assert group_info.get("autoRollbackConfiguration", {}).get("events") == \
        ["DEPLOYMENT_STOP_ON_ALARM"], (
        f"the deployment group echoed autoRollbackConfiguration "
        f"{group_info.get('autoRollbackConfiguration')!r}, expected events "
        f"['DEPLOYMENT_STOP_ON_ALARM']"
    )

    # Control first: an unpollable alarm or a canary that never opens would otherwise fail the
    # breach leg for an unrelated reason.
    _force_alarm_state(cw, alarm, "OK")
    control_id, control = _deploy_and_wait(
        ctx, cd, app, dg, _lambda_revision(fn, alias, v1, v2), timeout_s=420)
    assert control.get("status") == "Succeeded", (
        f"positive control: with the alarm at OK the canary deployment {control_id!r} ended "
        f"{control.get('status')!r} with errorInformation "
        f"{control.get('errorInformation')!r}; the alarm state cannot be isolated until "
        f"this leg passes"
    )
    at_v2 = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                  lambda a: a.get("FunctionVersion") == v2
                  and not (a.get("RoutingConfig") or {}).get("AdditionalVersionWeights"),
                  timeout_s=180, interval_s=2)
    assert at_v2["FunctionVersion"] == v2, (
        f"positive control: the un-breached deployment left the alias at "
        f"{at_v2['FunctionVersion']!r}, expected {v2!r}"
    )

    # Only the alarm's state differs, driven to ALARM mid-shift.
    breach_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg, deploymentConfigName=cfg,
        revision=_lambda_revision(fn, alias, v2, v3))["deploymentId"]
    _register_deployment_teardown(ctx, cd, breach_id)
    running = _poll(lambda: cd.get_deployment(deploymentId=breach_id)["deploymentInfo"],
                    lambda i: i.get("status") == "InProgress" or i.get("status") in TERMINAL,
                    timeout_s=180, interval_s=2)
    assert running.get("status") == "InProgress", (
        f"the deployment reached {running.get('status')!r} before the canary window opened, "
        f"so there was nothing for the alarm to interrupt; a "
        f"{CANARY_INTERVAL_MINUTES}-minute canary must not complete immediately"
    )
    _force_alarm_state(cw, alarm, "ALARM")

    stopped = _poll(lambda: cd.get_deployment(deploymentId=breach_id)["deploymentInfo"],
                    lambda i: i.get("status") in TERMINAL,
                    timeout_s=300, interval_s=3)
    assert stopped.get("status") == _ROLLED_BACK_STATUS, (
        f"a deployment stopped by an alarm breach must end {_ROLLED_BACK_STATUS!r}, got "
        f"{stopped.get('status')!r} with errorInformation "
        f"{stopped.get('errorInformation')!r}"
    )
    err = stopped.get("errorInformation") or {}
    assert err.get("code") == _ROLLED_BACK_CODE, (
        f"expected errorInformation code {_ROLLED_BACK_CODE!r} after an alarm breach, got "
        f"{err!r}"
    )
    assert err.get("message") == (
        "One or more alarms have been activated according to the Amazon CloudWatch metrics "
        "you selected, and the affected deployments have been stopped. Activated alarms: "
        f"<{alarm}>"
    ), (
        f"the failure must name the alarm that activated; got {err.get('message')!r}"
    )

    # rollbackInfo is populated a beat AFTER the deployment first reads terminal,
    # so this polls an observable condition rather than reading the terminal snapshot.
    attributed = _poll(
        lambda: cd.get_deployment(deploymentId=breach_id)["deploymentInfo"],
        lambda i: bool((i.get("rollbackInfo") or {}).get("rollbackDeploymentId")),
        timeout_s=180, interval_s=3)
    rollback_id = (attributed.get("rollbackInfo") or {}).get("rollbackDeploymentId")
    assert rollback_id, (
        f"the stopped deployment must name the rollback it spawned in "
        f"rollbackInfo.rollbackDeploymentId; it reads {attributed.get('rollbackInfo')!r}"
    )
    rollback_message = (attributed.get("rollbackInfo") or {}).get("rollbackMessage")
    assert rollback_message == (
        f"Deployment {breach_id} terminated. Automatic rollback is triggered with a "
        f"DeploymentId {rollback_id}."
    ), (
        f"the rollbackMessage must name the deployment that was terminated ({breach_id!r}); "
        f"it reads {rollback_message!r}"
    )
    _register_deployment_teardown(ctx, cd, rollback_id)
    rollback = cd.get_deployment(deploymentId=rollback_id)["deploymentInfo"]
    assert rollback.get("creator") == _ROLLBACK_CREATOR, (
        f"the rollback deployment {rollback_id!r} must be attributed to "
        f"{_ROLLBACK_CREATOR!r}, not {rollback.get('creator')!r}; a rollback the service "
        f"performed on its own is not a user deployment"
    )
    assert (rollback.get("rollbackInfo") or {}).get("rollbackTriggeringDeploymentId") == \
        breach_id, (
        f"the rollback deployment must point back at the deployment that triggered it "
        f"({breach_id!r}); its rollbackInfo reads {rollback.get('rollbackInfo')!r}"
    )
    assert rollback_id != breach_id, (
        f"the rollback must be a separate deployment record, not the same id {breach_id!r}"
    )

    restored = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                     lambda a: a.get("FunctionVersion") == v2
                     and not (a.get("RoutingConfig") or {}).get("AdditionalVersionWeights"),
                     timeout_s=240, interval_s=3)
    assert restored["FunctionVersion"] == v2, (
        f"the auto-rollback must restore the alias to the version the interrupted "
        f"deployment started from ({v2!r}), it reads {restored['FunctionVersion']!r}"
    )
    assert not (restored.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"the auto-rollback must clear the canary weight it had already applied: "
        f"{restored!r}"
    )
    ids = _list_group_deployments(cd, app, dg)
    assert {control_id, breach_id, rollback_id} <= set(ids), (
        f"the paginated deployment listing {ids!r} does not contain the control "
        f"{control_id!r}, the interrupted deployment {breach_id!r} and the rollback "
        f"{rollback_id!r}"
    )



def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _error_code(fn):
    """The raised ClientError's code. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(
        "the call was expected to be refused but it SUCCEEDED; an accepted call is a "
        "stronger signal than a wrong error code and must not read as one"
    )


def _deploy_and_wait(ctx, cd, app, dg, revision, *, timeout_s=420, **extra):
    """create_deployment, register its teardown immediately, then poll to a terminal state."""
    dep_id = cd.create_deployment(applicationName=app, deploymentGroupName=dg,
                                  revision=revision, **extra)["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)
    info = _poll(lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
                 lambda i: i.get("status") in TERMINAL,
                 timeout_s=timeout_s, interval_s=3)
    assert info.get("status") in TERMINAL, (
        f"deployment {dep_id!r} never reached a terminal state; last status "
        f"{info.get('status')!r} with errorInformation {info.get('errorInformation')!r}"
    )
    return dep_id, info


def _list_group_deployments(cd, app, dg):
    """Every deployment id for the group, paginated."""
    ids, token = [], None
    while True:
        kwargs = {"applicationName": app, "deploymentGroupName": dg}
        if token:
            kwargs["nextToken"] = token
        resp = cd.list_deployments(**kwargs)
        ids.extend(resp.get("deployments") or [])
        token = resp.get("nextToken")
        if not token:
            break
    return ids


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _lambda_exec_role_arn(ctx):
    """An execution role this check creates; the function is never invoked, so it needs only
    the Lambda trust policy."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cd-fnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_function_with_retry(lam, **kwargs):
    """CreateFunction, retried while a just-created execution role is not yet assumable."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            unpropagated = err.get("Code") == "InvalidParameterValueException" and (
                "cannot be assumed" in (err.get("Message") or "")
            )
            if unpropagated and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _wait_lambda_active(lam, fn, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last.get("State") == "Failed":
            raise AssertionError(f"{fn} entered Failed: {last.get('StateReason')}")
        if last.get("State") == "Active" and last.get("LastUpdateStatus", "Successful") == "Successful":
            return
        time.sleep(2)
    raise AssertionError(f"{fn} never became Active within {timeout_s}s. Last: {last!r}")


def _cleanup_function(ctx, lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _publish_version(lam, fn, n):
    lam.update_function_code(
        FunctionName=fn, ZipFile=_make_zip(f"def handler(e, c): return {{'v': {n}}}"))
    _wait_lambda_active(lam, fn)
    return lam.publish_version(FunctionName=fn, Description=f"v{n}")["Version"]


def _versioned_function_with_alias(ctx, lam, alias_name="live"):
    name = ctx.unique_name("sim2real-behav-cd-fn-")
    _create_function_with_retry(
        lam,
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_lambda_exec_role_arn(ctx),
        Code={"ZipFile": _make_zip("def handler(e, c): return {'v': 1}")},
        MemorySize=128,
        Timeout=10,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _cleanup_function(ctx, lam, name))
    _wait_lambda_active(lam, name)
    v1 = lam.publish_version(FunctionName=name, Description="v1")["Version"]
    v2 = _publish_version(lam, name, 2)
    assert v1 != v2, f"publish_version returned the same version twice: {v1!r}"
    lam.create_alias(FunctionName=name, Name=alias_name, FunctionVersion=v1)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=name, Name=alias_name))
    return name, v1, v2, alias_name


def _appspec_body(fn, alias, current_version, target_version):
    """The AppSpec CodeDeploy parses to decide which alias to move, and from/to where."""
    return {
        "version": 0.0,
        "Resources": [
            {
                fn: {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Name": fn,
                        "Alias": alias,
                        "CurrentVersion": current_version,
                        "TargetVersion": target_version,
                    },
                }
            }
        ],
    }


def _lambda_revision(fn, alias, current_version, target_version):
    return {
        "revisionType": "AppSpecContent",
        "appSpecContent": {
            "content": json.dumps(_appspec_body(fn, alias, current_version, target_version))
        },
    }


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cd-app-")
    cd.create_application(
        applicationName=name,
        computePlatform=compute_platform,
        tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": CHECK}],
    )
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


def _make_codedeploy_role(ctx, prefix, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
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
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM exposes no signal that a policy is effective; the bounded InvalidRoleException retry in
    # _create_deployment_group absorbs propagation delay.
    return resp["Role"]["Arn"]


def _create_service_role(ctx):
    cached = getattr(ctx, "_cd_service_role_arn", None)
    if cached:
        return cached
    arn = _make_codedeploy_role(ctx, "sim2real-behav-role-codedeploy-",
                                [{"Effect": "Allow", "Action": "*", "Resource": "*"}])
    ctx._cd_service_role_arn = arn
    return arn


def _create_deployment_group(ctx, app, *, deployment_config, name=None, **extra):
    cd = ctx.client("codedeploy")
    name = name or ctx.unique_name("sim2real-behav-cd-dg-")
    kwargs = {
        "applicationName": app,
        "deploymentGroupName": name,
        "deploymentConfigName": deployment_config,
        "serviceRoleArn": extra.pop("serviceRoleArn", None) or _create_service_role(ctx),
        "deploymentStyle": {
            "deploymentType": "BLUE_GREEN",
            "deploymentOption": "WITH_TRAFFIC_CONTROL",
        },
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


def _register_deployment_teardown(ctx, cd, dep_id):
    """Drive the deployment to a terminal state at teardown: a non-terminal deployment blocks its
    group's deletion, so this must run before the group's cleanup (LIFO gives that ordering).
    """
    def _teardown():
        try:
            cd.stop_deployment(deploymentId=dep_id, autoRollbackEnabled=False)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("DeploymentAlreadyCompletedException",
                            "InvalidDeploymentStatusException"):
                raise
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            status = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"].get("status")
            if status in TERMINAL:
                return
            time.sleep(5)
        raise AssertionError(
            f"deployment {dep_id} did not reach a terminal state within the teardown "
            "deadline; the deployment group may block deletion"
        )

    ctx.on_cleanup(_teardown)


def _force_alarm_state(cw, alarm, want, timeout_s=60):
    """SetAlarmState, then poll DescribeAlarms until the alarm reads that state: SetAlarmState is
    asynchronous, and CodeDeploy must observe the new state inside the window.
    """
    cw.set_alarm_state(AlarmName=alarm, StateValue=want,
                       StateReason="sim2real: driving the CodeDeploy rollback trigger")
    got = _poll(lambda: cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0],
                lambda a: a.get("StateValue") == want, timeout_s=timeout_s, interval_s=2)
    assert got.get("StateValue") == want, (
        f"the alarm {alarm!r} did not reach {want!r} within {timeout_s}s; it reads "
        f"{got.get('StateValue')!r}, so the deployment would not see the state this check "
        f"intends to test"
    )


def _delete_alarm(cw, alarm, timeout_s=90):
    """Delete the alarm and confirm it is gone, retrying: ctx.on_cleanup swallows errors, so a delete
    refused while CodeDeploy still has the alarm associated would otherwise leak silently.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cw.delete_alarms(AlarmNames=[alarm])
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)
            continue
        if not cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"]:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"alarm {alarm!r} still present after {timeout_s}s of delete attempts"
            )
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
