"""lambda-deployment-stopped-and-rolled-back-by-alarm."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "lambda-deployment-stopped-and-rolled-back-by-alarm"
GROUP = "lifecycle"
SERVICES = ["cloudwatch", "codedeploy", "lambda"]

TERMINAL = ("Succeeded", "Failed", "Stopped")
# An alarm already in ALARM at CreateDeployment stops the deployment before AllAtOnce moves the
# alias; CodeDeploy still spawns a rollback deployment attributed to codeDeployRollback.
_STOPPED_STATUS = "Stopped"
_STOPPED_CODE = "ALARM_ACTIVE"
_ROLLBACK_CREATOR = "codeDeployRollback"


@tags("axis:negative-delivery", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudWatch alarm already in ALARM when a Lambda deployment is created stops it
    (Stopped/ALARM_ACTIVE) before the alias moves, and CodeDeploy still records a rollback
    deployment; an OK-alarm control deployment first succeeds and moves the alias.
    """
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    fn, v1, alias = _versioned_function_with_alias(ctx, lam)
    v2 = _publish_version(lam, fn, 2)
    v3 = _publish_version(lam, fn, 3)
    assert len({v1, v2, v3}) == 3, f"setup: versions collided: {(v1, v2, v3)!r}"

    # No datapoints are ever published; the state is driven with SetAlarmState instead.
    alarm = ctx.unique_name("sim2real-behav-cdalarm-")
    cw.put_metric_alarm(
        AlarmName=alarm,
        Namespace="sim2real/codedeploy/no-datapoints",
        MetricName="never-published",
        Statistic="Sum",
        Period=300,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        AlarmDescription="sim2real codedeploy alarm-already-active trigger",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_alarm(cw, alarm))

    app = _create_application(ctx, compute_platform="Lambda")
    dg = _create_deployment_group(
        ctx, app,
        deployment_config="CodeDeployDefault.LambdaAllAtOnce",
        alarmConfiguration={"enabled": True, "alarms": [{"name": alarm}]},
        autoRollbackConfiguration={"enabled": True,
                                    "events": ["DEPLOYMENT_STOP_ON_ALARM"]},
    )

    # --- positive control, FIRST: alarm at OK, everything else identical ---
    _force_alarm_state(cw, alarm, "OK")
    control_id, control = _deploy_and_wait(
        ctx, cd, app, dg, _lambda_revision(fn, alias, v1, v2), timeout_s=180)
    assert control.get("status") == "Succeeded", (
        f"positive control: with the alarm at OK the AllAtOnce deployment {control_id!r} "
        f"ended {control.get('status')!r} with errorInformation "
        f"{control.get('errorInformation')!r}; the alarm state cannot be isolated until "
        f"this leg passes"
    )
    at_v2 = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                  lambda a: a.get("FunctionVersion") == v2,
                  timeout_s=120, interval_s=2)
    assert at_v2["FunctionVersion"] == v2, (
        f"positive control: the un-breached deployment left the alias at "
        f"{at_v2['FunctionVersion']!r}, expected {v2!r}"
    )

    # --- break exactly one thing: force the alarm to ALARM BEFORE CreateDeployment ---
    _force_alarm_state(cw, alarm, "ALARM")
    breach_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg,
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
        revision=_lambda_revision(fn, alias, v2, v3))["deploymentId"]
    _register_deployment_teardown(ctx, cd, breach_id)

    stopped = _poll(lambda: cd.get_deployment(deploymentId=breach_id)["deploymentInfo"],
                     lambda i: i.get("status") in TERMINAL,
                     timeout_s=120, interval_s=2)
    assert stopped.get("status") == _STOPPED_STATUS, (
        f"a deployment created while its group's alarm is already ALARM must end "
        f"{_STOPPED_STATUS!r}, got {stopped.get('status')!r} with errorInformation "
        f"{stopped.get('errorInformation')!r}"
    )
    err = stopped.get("errorInformation") or {}
    assert err.get("code") == _STOPPED_CODE, (
        f"expected errorInformation code {_STOPPED_CODE!r}, got {err!r}"
    )
    assert alarm in (err.get("message") or ""), (
        f"the failure must name the alarm that was active; expected {alarm!r} in "
        f"{err.get('message')!r}"
    )

    # --- CodeDeploy still spawns a rollback deployment, unasked, even with nothing to undo ---
    attributed = _poll(
        lambda: cd.get_deployment(deploymentId=breach_id)["deploymentInfo"],
        lambda i: bool((i.get("rollbackInfo") or {}).get("rollbackDeploymentId")),
        timeout_s=60, interval_s=2)
    rollback_id = (attributed.get("rollbackInfo") or {}).get("rollbackDeploymentId")
    assert rollback_id, (
        f"the stopped deployment must name the rollback it spawned in "
        f"rollbackInfo.rollbackDeploymentId; it reads {attributed.get('rollbackInfo')!r}"
    )
    _register_deployment_teardown(ctx, cd, rollback_id)
    rollback = _poll(lambda: cd.get_deployment(deploymentId=rollback_id)["deploymentInfo"],
                      lambda i: i.get("status") in TERMINAL,
                      timeout_s=60, interval_s=2)
    assert rollback.get("creator") == _ROLLBACK_CREATOR, (
        f"the rollback deployment {rollback_id!r} must be attributed to "
        f"{_ROLLBACK_CREATOR!r}, not {rollback.get('creator')!r}"
    )
    assert (rollback.get("rollbackInfo") or {}).get("rollbackTriggeringDeploymentId") == \
        breach_id, (
        f"the rollback deployment must point back at the deployment that triggered it "
        f"({breach_id!r}); its rollbackInfo reads {rollback.get('rollbackInfo')!r}"
    )
    assert rollback_id != breach_id, (
        f"the rollback must be a separate deployment record, not {breach_id!r} itself"
    )

    # --- the observable absence: the alias never moved to v3 at any point ---
    held = lam.get_alias(FunctionName=fn, Name=alias)
    assert held["FunctionVersion"] == v2, (
        f"the alias must keep the version the blocked deployment started from ({v2!r}); "
        f"it reads {held['FunctionVersion']!r}"
    )
    assert not (held.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"a deployment stopped before it could begin must leave no partial routing "
        f"weight behind: {held!r}"
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


def _deploy_and_wait(ctx, cd, app, dg, revision, *, timeout_s=180, **extra):
    dep_id = cd.create_deployment(applicationName=app, deploymentGroupName=dg,
                                   deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
                                   revision=revision, **extra)["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)
    info = _poll(lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
                 lambda i: i.get("status") in TERMINAL,
                 timeout_s=timeout_s, interval_s=2)
    assert info.get("status") in TERMINAL, (
        f"deployment {dep_id!r} never reached a terminal state; last status "
        f"{info.get('status')!r} with errorInformation {info.get('errorInformation')!r}"
    )
    return dep_id, info


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _lambda_exec_role_arn(ctx):
    """An execution role this check creates. The function is never invoked, so the role needs
    only the Lambda trust policy, no permissions."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cdalarm-exec-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_function_when_role_assumable(lam, timeout_s=90.0, **kwargs):
    """CreateFunction, retrying only Lambda's not-yet-assumable refusal of a fresh role."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            fresh = (err.get("Code") == "InvalidParameterValueException"
                     and "cannot be assumed" in (err.get("Message") or ""))
            if not fresh or time.monotonic() >= deadline:
                raise
            time.sleep(3)


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
    name = ctx.unique_name("sim2real-behav-cdalarm-fn-")
    _create_function_when_role_assumable(
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
    lam.create_alias(FunctionName=name, Name=alias_name, FunctionVersion=v1)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=name, Name=alias_name))
    return name, v1, alias_name


def _lambda_revision(fn, alias, current_version, target_version):
    appspec = {
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
    return {
        "revisionType": "AppSpecContent",
        "appSpecContent": {"content": json.dumps(appspec)},
    }


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cdalarm-app-")
    cd.create_application(
        applicationName=name,
        computePlatform=compute_platform,
        tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
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
    # IAM exposes no signal that a policy is effective; the bounded InvalidRoleException
    # retry in _create_deployment_group absorbs propagation delay.
    return resp["Role"]["Arn"]


def _create_service_role(ctx):
    cached = getattr(ctx, "_cdalarm_service_role_arn", None)
    if cached:
        return cached
    arn = _make_codedeploy_role(ctx, "sim2real-behav-role-cdalarm-",
                                 [{"Effect": "Allow", "Action": "*", "Resource": "*"}])
    ctx._cdalarm_service_role_arn = arn
    return arn


def _create_deployment_group(ctx, app, *, deployment_config, name=None, **extra):
    cd = ctx.client("codedeploy")
    name = name or ctx.unique_name("sim2real-behav-cdalarm-dg-")
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
    """Drive the deployment to a terminal state at teardown: a non-terminal deployment
    blocks its deployment group's deletion, so this must run before the group's own
    cleanup (LIFO gives that ordering for free)."""
    def _teardown():
        try:
            cd.stop_deployment(deploymentId=dep_id, autoRollbackEnabled=False)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("DeploymentAlreadyCompletedException",
                            "InvalidDeploymentStatusException"):
                raise
        deadline = time.monotonic() + 180
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
    """SetAlarmState, then poll DescribeAlarms until the alarm really reads that state.
    SetAlarmState is asynchronous: returning is not the same as CodeDeploy being able to
    observe the new state."""
    cw.set_alarm_state(AlarmName=alarm, StateValue=want,
                        StateReason="sim2real: driving the CodeDeploy alarm-already-active check")
    got = _poll(lambda: cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0],
                lambda a: a.get("StateValue") == want, timeout_s=timeout_s, interval_s=2)
    assert got.get("StateValue") == want, (
        f"the alarm {alarm!r} did not reach {want!r} within {timeout_s}s; it reads "
        f"{got.get('StateValue')!r}"
    )


def _delete_alarm(cw, alarm, timeout_s=90):
    """Delete the alarm and CONFIRM it is gone, retrying. ctx.on_cleanup swallows whatever
    this raises, so a delete that is transiently refused while CodeDeploy still has the
    alarm associated would otherwise leak in silence."""
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
