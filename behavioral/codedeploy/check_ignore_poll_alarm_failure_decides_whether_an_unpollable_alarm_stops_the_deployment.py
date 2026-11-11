"""ignore-poll-alarm-failure-decides-whether-an-unpollable-alarm-stops-the-deployment."""
from __future__ import annotations

import io
import json
import time

import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

# CodeDeploy checks that its service role can call DescribeAlarms as a pre-flight step whenever
# alarmConfiguration is enabled, so an IAM deny fails the deployment (IAM_ROLE_PERMISSIONS)
# before any bake-window polling, whatever ignorePollAlarmFailure says.

CHECK = "ignore-poll-alarm-failure-decides-whether-an-unpollable-alarm-stops-the-deployment"
GROUP = "lifecycle"
SERVICES = ["codedeploy"]

TERMINAL = ("Succeeded", "Failed", "Stopped")
_INLINE_POLICY = "codedeploy-inline"
_SRC = "def handler(event, context):\n    return {{'marker': 'v{n}'}}\n"
#: The groups' own config is a canary, so the refused legs run under weighted traffic routing;
#: the legs that must succeed override it with AllAtOnce, which has no bake to wait out.
CANARY_PERCENTAGE = 10
CANARY_INTERVAL_MINUTES = 1
_ALL_AT_ONCE = "CodeDeployDefault.LambdaAllAtOnce"
#: Deadline for a rewritten role policy to take effect for CodeDeploy's assume-role.
IAM_PROPAGATION_S = 300
#: Everything the service role needs. The ONE statement the negative leg removes is the
#: cloudwatch:DescribeAlarms grant, and it is separated out so the two policy documents differ
#: in exactly that.
_BASE_STATEMENTS = [
    {
        "Effect": "Allow",
        "Action": [
            "lambda:*",
            "codedeploy:*",
            "cloudwatch:PutMetricData",
            "cloudwatch:GetMetricData",
            "cloudwatch:GetMetricStatistics",
            "sns:Publish",
            "s3:Get*",
            "s3:List*",
            "iam:PassRole",
        ],
        "Resource": "*",
    }
]
_ALARM_READ = {
    "Effect": "Allow",
    "Action": ["cloudwatch:DescribeAlarms", "cloudwatch:DescribeAlarmHistory"],
    "Resource": "*",
}
_ALARM_DENY = {
    "Effect": "Deny",
    "Action": ["cloudwatch:DescribeAlarms", "cloudwatch:DescribeAlarmHistory"],
    "Resource": "*",
}


@tags("axis:rejection", "cap:c4", "concern:metrics", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ignorePollAlarmFailure does not excuse a DescribeAlarms denial: twin groups differing only
    in that flag both fail with IAM_ROLE_PERMISSIONS, leave the alias unmoved, and both succeed
    once the grant is restored.
    """
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    exec_role = _exec_role_arn(ctx)
    role_name, role_arn = _make_codedeploy_role(
        ctx, "sim2real-behav-role-codedeploy-", _BASE_STATEMENTS + [_ALARM_READ]
    )

    alarm = _create_alarm(ctx, cw)
    cfg = _create_canary_config(ctx, cd)

    strict_fn, strict_vs, alias = _versioned_function_with_alias(ctx, lam, exec_role)
    lenient_fn, lenient_vs, _ = _versioned_function_with_alias(ctx, lam, exec_role)
    probe_fn, probe_vs, _ = _versioned_function_with_alias(ctx, lam, exec_role, n_versions=2)

    app = _create_application(ctx, compute_platform="Lambda")
    strict_dg = _create_group_with_alarm(
        ctx, cd, app, cfg, role_arn, alarm, ignore_poll=False
    )
    lenient_dg = _create_group_with_alarm(
        ctx, cd, app, cfg, role_arn, alarm, ignore_poll=True
    )
    # A third group on the same role shows when a policy change has taken effect for CodeDeploy.
    probe_dg = _create_group_with_alarm(
        ctx, cd, app, cfg, role_arn, alarm, ignore_poll=False
    )

    # --- positive controls, FIRST: with the grant in place BOTH groups deploy cleanly ---
    ok_id, ok_info = _deploy_until_permitted(
        ctx,
        cd,
        app,
        strict_dg,
        _lambda_revision(strict_fn, alias, strict_vs[0], strict_vs[1]),
    )
    assert ok_info.get("status") == "Succeeded", (
        f"positive control (strict): with cloudwatch:DescribeAlarms GRANTED, the strict group's "
        f"deployment {ok_id!r} ended {ok_info.get('status')!r} with errorInformation "
        f"{ok_info.get('errorInformation')!r}. The alarm is on a namespace that receives no "
        f"datapoints and reads OK, so nothing should stop this. Until it passes, a failed "
        f"deployment below proves nothing about the DescribeAlarms grant"
    )
    at_v2 = lam.get_alias(FunctionName=strict_fn, Name=alias)
    assert at_v2["FunctionVersion"] == strict_vs[1], (
        f"positive control (strict): the alias is at {at_v2['FunctionVersion']!r} after a "
        f"Succeeded deployment, expected {strict_vs[1]!r}"
    )

    lok_id, lok_info = _deploy_until_permitted(
        ctx,
        cd,
        app,
        lenient_dg,
        _lambda_revision(lenient_fn, alias, lenient_vs[0], lenient_vs[1]),
    )
    assert lok_info.get("status") == "Succeeded", (
        f"positive control (lenient): with cloudwatch:DescribeAlarms GRANTED, the lenient "
        f"group's deployment {lok_id!r} ended {lok_info.get('status')!r} with errorInformation "
        f"{lok_info.get('errorInformation')!r}. Without this, a later refusal on the lenient "
        f"group proves nothing -- it could just be a group that never deploys"
    )
    lat_v2 = lam.get_alias(FunctionName=lenient_fn, Name=alias)
    assert lat_v2["FunctionVersion"] == lenient_vs[1], (
        f"positive control (lenient): the alias is at {lat_v2['FunctionVersion']!r} after a "
        f"Succeeded deployment, expected {lenient_vs[1]!r}"
    )

    # --- break exactly one thing: the service role's ability to READ the alarm ---
    _put_service_role_policy(ctx, role_name, _BASE_STATEMENTS + [_ALARM_DENY])
    _await_probe_refused(ctx, cd, lam, app, probe_dg, probe_fn, alias, probe_vs)

    strict_id, strict_info = _deploy_and_wait(
        ctx,
        cd,
        app,
        strict_dg,
        _lambda_revision(strict_fn, alias, strict_vs[1], strict_vs[2]),
    )
    assert strict_info.get("status") == "Failed", (
        f"with the service role DENIED cloudwatch:DescribeAlarms, CodeDeploy refuses the "
        f"deployment as a pre-flight authorization failure -- MEASURED on real AWS, independent "
        f"of ignorePollAlarmFailure. Deployment {strict_id!r} ended "
        f"{strict_info.get('status')!r} with errorInformation "
        f"{strict_info.get('errorInformation')!r}, expected status 'Failed'"
    )
    assert (strict_info.get("errorInformation") or {}).get("code") == "IAM_ROLE_PERMISSIONS", (
        f"deployment {strict_id!r} failed with errorInformation "
        f"{strict_info.get('errorInformation')!r}; expected code 'IAM_ROLE_PERMISSIONS' -- the "
        f"specific code real CodeDeploy returns when its service role cannot call "
        f"cloudwatch:DescribeAlarms. A different code means this run's failure has a different "
        f"cause than the grant we removed"
    )

    # effect absent, read at the destination through a different operation than the mutation
    unmoved = lam.get_alias(FunctionName=strict_fn, Name=alias)
    assert unmoved["FunctionVersion"] == strict_vs[1], (
        f"effect not absent: the alias reads {unmoved['FunctionVersion']!r} after a deployment "
        f"CodeDeploy refused for a missing permission; it must still be at {strict_vs[1]!r}. A "
        f"deployment CodeDeploy declined to run must not have moved traffic"
    )
    assert not (unmoved.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"effect not absent: the refused strict deployment left weighted routing on the alias: "
        f"{unmoved!r}"
    )

    # --- the twin: the SAME denial, ignorePollAlarmFailure=true -- refused THE SAME WAY ---
    lenient_id, lenient_info = _deploy_and_wait(
        ctx,
        cd,
        app,
        lenient_dg,
        _lambda_revision(lenient_fn, alias, lenient_vs[1], lenient_vs[2]),
    )
    assert lenient_info.get("status") == "Failed", (
        f"ignorePollAlarmFailure=TRUE does not excuse a real cloudwatch:DescribeAlarms denial: "
        f"CodeDeploy refuses this deployment exactly as it refused the strict one above. "
        f"{lenient_id!r} ended {lenient_info.get('status')!r} with errorInformation "
        f"{lenient_info.get('errorInformation')!r}, expected status 'Failed'. A 'Succeeded' here "
        f"would mean the boolean lets an authorization failure through, which real CodeDeploy "
        f"does not do"
    )
    assert (lenient_info.get("errorInformation") or {}).get("code") == "IAM_ROLE_PERMISSIONS", (
        f"deployment {lenient_id!r} failed with errorInformation "
        f"{lenient_info.get('errorInformation')!r}; expected the SAME code as the strict leg, "
        f"'IAM_ROLE_PERMISSIONS' -- proving both groups were refused by the identical cause"
    )
    lenient_unmoved = lam.get_alias(FunctionName=lenient_fn, Name=alias)
    assert lenient_unmoved["FunctionVersion"] == lenient_vs[1], (
        f"effect not absent: the lenient group's alias reads "
        f"{lenient_unmoved['FunctionVersion']!r} after a refused deployment; it must still be "
        f"at {lenient_vs[1]!r}"
    )
    assert not (lenient_unmoved.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"effect not absent: the refused lenient deployment left weighted routing on the alias: "
        f"{lenient_unmoved!r}"
    )

    # --- restore: re-grant the read, re-run the IDENTICAL deployments on BOTH groups ---
    _put_service_role_policy(ctx, role_name, _BASE_STATEMENTS + [_ALARM_READ])

    redo_id, redo_info = _deploy_until_permitted(
        ctx,
        cd,
        app,
        strict_dg,
        _lambda_revision(strict_fn, alias, strict_vs[1], strict_vs[2]),
    )
    assert redo_info.get("status") == "Succeeded", (
        f"restore (strict): with the grant back, the IDENTICAL strict deployment ended "
        f"{redo_info.get('status')!r} on {redo_id!r} (errorInformation="
        f"{redo_info.get('errorInformation')!r}). The request never changed, so the refusal was "
        f"either not caused by the missing grant or the fixture has died"
    )
    # Poll only for any traffic weights to clear; the version is asserted next so a wrong
    # version fails as itself rather than as a poll timeout.
    _poll(
        lambda: lam.get_alias(FunctionName=strict_fn, Name=alias),
        lambda a: not (a.get("RoutingConfig") or {}).get("AdditionalVersionWeights"),
        timeout_s=300,
        interval_s=2,
        what=(
            f"the canary weights on {strict_fn!r}'s alias to clear after the restored "
            f"deployment {redo_id!r} reported Succeeded"
        ),
    )
    restored = lam.get_alias(FunctionName=strict_fn, Name=alias)
    assert restored["FunctionVersion"] == strict_vs[2], (
        f"restore (strict): the alias reads {restored['FunctionVersion']!r}, expected "
        f"{strict_vs[2]!r} -- the exact shift the earlier refusal blocked must now go through"
    )

    lredo_id, lredo_info = _deploy_until_permitted(
        ctx,
        cd,
        app,
        lenient_dg,
        _lambda_revision(lenient_fn, alias, lenient_vs[1], lenient_vs[2]),
    )
    assert lredo_info.get("status") == "Succeeded", (
        f"restore (lenient): with the grant back, the IDENTICAL lenient deployment ended "
        f"{lredo_info.get('status')!r} on {lredo_id!r} (errorInformation="
        f"{lredo_info.get('errorInformation')!r}). The request never changed, so the refusal was "
        f"either not caused by the missing grant or the fixture has died"
    )
    _poll(
        lambda: lam.get_alias(FunctionName=lenient_fn, Name=alias),
        lambda a: not (a.get("RoutingConfig") or {}).get("AdditionalVersionWeights"),
        timeout_s=300,
        interval_s=2,
        what=(
            f"the canary weights on {lenient_fn!r}'s alias to clear after the restored "
            f"deployment {lredo_id!r} reported Succeeded"
        ),
    )
    lrestored = lam.get_alias(FunctionName=lenient_fn, Name=alias)
    assert lrestored["FunctionVersion"] == lenient_vs[2], (
        f"restore (lenient): the alias reads {lrestored['FunctionVersion']!r}, expected "
        f"{lenient_vs[2]!r} -- the exact shift the earlier refusal blocked must now go through"
    )


def _create_alarm(ctx, cw):
    """An alarm on a namespace that receives no datapoints, with TreatMissingData=notBreaching.

    Its state is kept uninteresting so only CodeDeploy's ability to read the alarm differs.
    """
    name = ctx.unique_name("sim2real-behav-cd-alarm-")
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace="sim2real/codedeploy/no-datapoints",
        MetricName="never-published",
        Statistic="Sum",
        Period=300,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))
    # Poll only for the alarm to have SOME state; the OK/INSUFFICIENT_DATA assertion follows
    # so a breaching alarm fails as a setup problem rather than as a poll timeout.
    state = _poll(
        lambda: cw.describe_alarms(AlarmNames=[name])["MetricAlarms"],
        lambda alarms: bool(alarms) and bool(alarms[0].get("StateValue")),
        timeout_s=120,
        interval_s=2,
        what=f"alarm {name!r} to become readable with a state before any deployment runs",
    )
    assert state[0]["StateValue"] in ("OK", "INSUFFICIENT_DATA"), (
        f"setup: alarm {name!r} reads {state[0]['StateValue']!r}. It is built on a namespace "
        f"that receives no datapoints with TreatMissingData=notBreaching, so it must not be "
        f"breaching -- otherwise a stopped deployment could be explained by the alarm's STATE "
        f"rather than by its unreadability, which is the only thing this check varies"
    )
    return name


def _create_canary_config(ctx, cd):
    name = ctx.unique_name("sim2real-behav-cd-cfg-")
    cd.create_deployment_config(
        deploymentConfigName=name,
        computePlatform="Lambda",
        trafficRoutingConfig={
            "type": "TimeBasedCanary",
            "timeBasedCanary": {
                "canaryPercentage": CANARY_PERCENTAGE,
                "canaryInterval": CANARY_INTERVAL_MINUTES,
            },
        },
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_config(deploymentConfigName=name))
    return name


def _create_group_with_alarm(ctx, cd, app, cfg, role_arn, alarm, *, ignore_poll):
    dg = _create_deployment_group(
        ctx,
        app,
        deployment_config=cfg,
        role_arn=role_arn,
        alarmConfiguration={
            "enabled": True,
            "ignorePollAlarmFailure": ignore_poll,
            "alarms": [{"name": alarm}],
        },
    )
    info = cd.get_deployment_group(applicationName=app, deploymentGroupName=dg)[
        "deploymentGroupInfo"
    ]
    ac = info.get("alarmConfiguration") or {}
    assert ac.get("enabled") is True, (
        f"group {dg!r} reports alarmConfiguration {ac!r}; it must be ENABLED or the boolean "
        f"under test has no effect: with alarms disabled, ignorePollAlarmFailure is never "
        f"consulted"
    )
    assert ac.get("ignorePollAlarmFailure") is ignore_poll, (
        f"group {dg!r} reports ignorePollAlarmFailure "
        f"{ac.get('ignorePollAlarmFailure')!r}, expected {ignore_poll!r}; the two legs differ "
        f"in exactly this value, so a group that did not store it makes them the same leg"
    )
    assert [a["name"] for a in ac.get("alarms") or []] == [alarm], (
        f"group {dg!r} reports alarms {ac.get('alarms')!r}, expected exactly [{alarm!r}]"
    )
    return dg


def _refused(info):
    return (info.get("status") == "Failed"
            and (info.get("errorInformation") or {}).get("code") == "IAM_ROLE_PERMISSIONS")


def _await_probe_refused(ctx, cd, lam, app, dg, fn, alias, versions):
    """Deploy the probe group until CodeDeploy refuses it with IAM_ROLE_PERMISSIONS: IAM has no
    readiness signal, so the refusal itself shows the Deny is in effect for the shared role."""
    deadline = _deadline(ctx, IAM_PROPAGATION_S)
    while True:
        current = lam.get_alias(FunctionName=fn, Name=alias)["FunctionVersion"]
        target = versions[1] if current == versions[0] else versions[0]
        dep_id, info = _deploy_and_wait(
            ctx, cd, app, dg, _lambda_revision(fn, alias, current, target),
            deploymentConfigName=_ALL_AT_ONCE,
        )
        if _refused(info):
            return
        assert time.monotonic() < deadline, (
            f"with the service role DENIED cloudwatch:DescribeAlarms, CodeDeploy never refused a "
            f"deployment of the probe group {dg!r} within {IAM_PROPAGATION_S}s; the last, "
            f"{dep_id!r}, ended {info.get('status')!r} with errorInformation "
            f"{info.get('errorInformation')!r}"
        )
        time.sleep(2)


def _deploy_until_permitted(ctx, cd, app, dg, revision):
    """An AllAtOnce deployment, re-created while IAM_ROLE_PERMISSIONS shows a grant that has not
    yet taken effect; a refused deployment moves no traffic, so the retry is idempotent."""
    deadline = _deadline(ctx, IAM_PROPAGATION_S)
    while True:
        dep_id, info = _deploy_and_wait(
            ctx, cd, app, dg, revision, deploymentConfigName=_ALL_AT_ONCE
        )
        if not _refused(info) or time.monotonic() >= deadline:
            return dep_id, info
        time.sleep(2)


def _deadline(ctx, seconds):
    """A monotonic deadline of `seconds`, capped by the run's remaining budget."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else min(seconds, left))


def _poll(fn, pred, *, timeout_s, interval_s, what, ctx=None):
    """Bounded retry with a deadline and a stated reason; raises on timeout."""
    deadline = time.monotonic() + timeout_s if ctx is None else _deadline(ctx, timeout_s)
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; the last value observed was "
                f"{val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _deploy_and_wait(ctx, cd, app, dg, revision, *, timeout_s=600, **extra):
    dep_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg, revision=revision, **extra
    )["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)
    info = _poll(
        lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
        lambda i: i.get("status") in TERMINAL,
        timeout_s=timeout_s,
        interval_s=2,
        what=f"deployment {dep_id!r} to reach one of {TERMINAL!r}",
        ctx=ctx,
    )
    return dep_id, info


def _register_deployment_teardown(ctx, cd, dep_id):
    def _teardown():
        try:
            cd.stop_deployment(deploymentId=dep_id, autoRollbackEnabled=False)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in (
                "DeploymentAlreadyCompletedException",
                "InvalidDeploymentStatusException",
            ):
                raise
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            status = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"].get("status")
            if status in TERMINAL:
                return
            time.sleep(2)
        raise AssertionError(
            f"deployment {dep_id} did not reach a terminal state within the teardown deadline"
        )

    ctx.on_cleanup(_teardown)


def _create_application(ctx, compute_platform="Lambda"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cd-app-")
    cd.create_application(
        applicationName=name,
        computePlatform=compute_platform,
        tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _make_codedeploy_role(ctx, prefix, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codedeploy.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
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
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    # IAM has no signal that a new policy is effective: _create_deployment_group retries
    # InvalidRoleException and _deploy_until_permitted retries IAM_ROLE_PERMISSIONS.
    _put_service_role_policy(ctx, role_name, statements)
    return role_name, resp["Role"]["Arn"]


def _put_service_role_policy(ctx, role_name, statements):
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName=_INLINE_POLICY,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )


def _create_deployment_group(ctx, app, *, deployment_config, role_arn, name=None, **extra):
    cd = ctx.client("codedeploy")
    name = name or ctx.unique_name("sim2real-behav-cd-dg-")
    kwargs = {
        "applicationName": app,
        "deploymentGroupName": name,
        "deploymentConfigName": deployment_config,
        "serviceRoleArn": role_arn,
        "deploymentStyle": {
            "deploymentType": "BLUE_GREEN",
            "deploymentOption": "WITH_TRAFFIC_CONTROL",
        },
    }
    kwargs.update(extra)
    deadline = time.monotonic() + 90
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
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=name)
    )
    return name


def _lambda_zip(src):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("lambda_function.py")
        info.external_attr = 0o644 << 16
        zf.writestr(info, src)
    return buf.getvalue()


def _exec_role_arn(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cd-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["Role"]["Arn"]
    # CreateFunction retries the role-propagation error, so no wait is needed here.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _versioned_function_with_alias(ctx, lam, exec_role, n_versions=3, alias="live"):
    """A function with `n_versions` distinct published versions and an alias on the first.

    Each version returns a marker naming itself, so an invoke shows which code actually ran.
    """
    fn = ctx.unique_name("sim2real-behav-cd-fn-")
    deadline = time.monotonic() + 180
    while True:
        try:
            lam.create_function(
                FunctionName=fn,
                Runtime="python3.12",
                Role=exec_role,
                Handler="lambda_function.handler",
                Code={"ZipFile": _lambda_zip(_SRC.format(n=1))},
                Timeout=15,
                Publish=False,
                Tags={"sim2real:managed": "true", "sim2real": CHECK},
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            retryable = err["Code"] == "InvalidParameterValueException" and (
                "role" in (err.get("Message") or "").lower()
            )
            if retryable and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))
    _wait_active(lam, fn)
    versions = [lam.publish_version(FunctionName=fn)["Version"]]
    for n in range(2, n_versions + 1):
        lam.update_function_code(FunctionName=fn, ZipFile=_lambda_zip(_SRC.format(n=n)))
        _wait_updated(lam, fn)
        versions.append(lam.publish_version(FunctionName=fn)["Version"])
    assert len(set(versions)) == n_versions, (
        f"setup: publishing {n_versions} versions produced {versions!r}, which are not all "
        f"distinct; every assertion below distinguishes versions by identity"
    )
    lam.create_alias(FunctionName=fn, Name=alias, FunctionVersion=versions[0])
    return fn, versions, alias


def _wait_active(lam, fn, timeout_s=180):
    _poll(
        lambda: lam.get_function(FunctionName=fn)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=timeout_s,
        interval_s=2,
        what=f"function {fn!r} to become Active",
    )


def _wait_updated(lam, fn, timeout_s=180):
    _poll(
        lambda: lam.get_function(FunctionName=fn)["Configuration"]["LastUpdateStatus"],
        lambda s: s == "Successful",
        timeout_s=timeout_s,
        interval_s=2,
        what=f"the code update on {fn!r} to finish",
    )


def _lambda_revision(fn, alias, current, target):
    return {
        "revisionType": "AppSpecContent",
        "appSpecContent": {
            "content": json.dumps(
                {
                    "version": "0.0",
                    "Resources": [
                        {
                            "sim2realFunction": {
                                "Type": "AWS::Lambda::Function",
                                "Properties": {
                                    "Name": fn,
                                    "Alias": alias,
                                    "CurrentVersion": current,
                                    "TargetVersion": target,
                                },
                            }
                        }
                    ],
                }
            )
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
