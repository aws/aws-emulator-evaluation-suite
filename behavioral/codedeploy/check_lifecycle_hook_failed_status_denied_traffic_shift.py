"""lifecycle-hook-failed-status-denied-traffic-shift."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "lifecycle-hook-failed-status-denied-traffic-shift"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")
HOOK_EVENT = "BeforeAllowTraffic"
# CodeDeploy invokes this hook itself; HOOK_STATUS is the only difference between the two legs.
_HOOK_SRC = """
import os
import boto3


def handler(event, context):
    boto3.client("codedeploy").put_lifecycle_event_hook_execution_status(
        deploymentId=event["DeploymentId"],
        lifecycleEventHookExecutionId=event["LifecycleEventHookExecutionId"],
        status=os.environ["HOOK_STATUS"],
    )
    return {"reported": os.environ["HOOK_STATUS"]}
"""


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A BeforeAllowTraffic hook reporting Failed fails the deployment, marks that event Failed and
    leaves the alias unmoved; the identical deployment with a Succeeded hook shifts traffic.

    Reference: https://docs.aws.amazon.com/codedeploy/latest/userguide/reference-appspec-file-structure-hooks.html
    Reference: https://docs.aws.amazon.com/codedeploy/latest/APIReference/API_PutLifecycleEventHookExecutionStatus.html
    """
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")

    exec_role = _create_hook_exec_role(ctx)
    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    v3 = _publish_version(lam, fn, 3)
    assert len({v1, v2, v3}) == 3, f"setup: versions collided: {(v1, v2, v3)!r}"

    hook_ok = _create_hook_function(ctx, lam, exec_role, "Succeeded")
    hook_bad = _create_hook_function(ctx, lam, exec_role, "Failed")

    app = _create_application(ctx, compute_platform="Lambda")
    dg = _create_deployment_group(
        ctx, app, deployment_config="CodeDeployDefault.LambdaAllAtOnce")

    # Control first: a hook CodeDeploy cannot invoke also ends Failed, mimicking the negative.
    ok_id, ok = _deploy_and_wait(
        ctx, cd, app, dg, _hook_revision(fn, alias, v1, v2, hook_ok))
    assert ok.get("status") == "Succeeded", (
        f"positive control: the deployment whose {HOOK_EVENT} hook reports 'Succeeded' "
        f"ended {ok.get('status')!r} with errorInformation "
        f"{ok.get('errorInformation')!r}; until this leg passes, a Failed deployment on "
        f"the other leg proves nothing about the hook's verdict"
    )
    ok_event = _hook_event_status(cd, ok_id)
    assert ok_event == "Succeeded", (
        f"positive control: the {HOOK_EVENT} lifecycle event reads {ok_event!r} on the "
        f"deployment that completed, expected 'Succeeded'"
    )
    at_v2 = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                  lambda a: a.get("FunctionVersion") == v2,
                  timeout_s=120, interval_s=2)
    assert at_v2["FunctionVersion"] == v2, (
        f"positive control: the hook-approved deployment left the alias at "
        f"{at_v2['FunctionVersion']!r}, expected {v2!r}"
    )

    # --- break exactly one thing: the status the hook reports back ---
    bad_id, bad = _deploy_and_wait(
        ctx, cd, app, dg, _hook_revision(fn, alias, v2, v3, hook_bad))
    assert bad.get("status") == "Failed", (
        f"a deployment whose {HOOK_EVENT} hook reports 'Failed' ended "
        f"{bad.get('status')!r}, expected 'Failed' (errorInformation="
        f"{bad.get('errorInformation')!r})"
    )
    bad_event = _hook_event_status(cd, bad_id)
    assert bad_event == "Failed", (
        f"the {HOOK_EVENT} lifecycle event reads {bad_event!r} on the deployment whose "
        f"hook reported 'Failed'; the hook's verdict must be recorded on the event it "
        f"gated, not just on the deployment"
    )

    # --- the effect is absent: no traffic moved, not even partially ---
    unmoved = lam.get_alias(FunctionName=fn, Name=alias)
    assert unmoved["FunctionVersion"] == v2, (
        f"effect not absent: the alias is at {unmoved['FunctionVersion']!r} after a "
        f"deployment its {HOOK_EVENT} hook refused; it must still be at {v2!r}. A hook "
        f"that gates traffic is not advisory"
    )
    assert not (unmoved.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"effect not absent: the refused deployment left weighted routing on the alias: "
        f"{unmoved!r}"
    )

    # --- second positive control: the same version pair, the approving hook ---
    after_id, after = _deploy_and_wait(
        ctx, cd, app, dg, _hook_revision(fn, alias, v2, v3, hook_ok))
    assert after.get("status") == "Succeeded", (
        f"positive control: the identical v2 -> v3 shift with the approving hook ended "
        f"{after.get('status')!r} (errorInformation={after.get('errorInformation')!r}); "
        f"the hook's reported status is then not the only difference"
    )
    at_v3 = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                  lambda a: a.get("FunctionVersion") == v3,
                  timeout_s=120, interval_s=2)
    assert at_v3["FunctionVersion"] == v3, (
        f"positive control: the approving-hook re-run left the alias at "
        f"{at_v3['FunctionVersion']!r}, expected {v3!r}"
    )
    ids = _list_group_deployments(cd, app, dg)
    assert {ok_id, bad_id, after_id} <= set(ids), (
        f"the paginated deployment listing {ids!r} does not contain all three of "
        f"{(ok_id, bad_id, after_id)!r}"
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
    """The raised ClientError's code; raises if the call unexpectedly succeeds."""
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
    """An execution role this check creates for its own functions (cached per run)."""
    cached = getattr(ctx, "_cd_lambda_exec_role_arn", None)
    if cached:
        return cached
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cd-fnexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
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
        PolicyName="lambda-logs",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }],
        }),
    )
    arn = resp["Role"]["Arn"]
    ctx._cd_lambda_exec_role_arn = arn
    return arn


def _create_function_retrying(lam, timeout_s=120, **kwargs):
    """CreateFunction, retried only through the window where a freshly created execution
    role is not yet assumable by Lambda (InvalidParameterValueException naming the role)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            unpropagated = err.get("Code") == "InvalidParameterValueException" and (
                "role" in (err.get("Message") or "").lower())
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
    _create_function_retrying(
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
    # IAM propagation is waited out by the bounded InvalidRoleException retry in the caller.
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


def _create_hook_exec_role(ctx):
    """The execution role for the hook Lambda. It needs exactly one non-default permission:
    the callback CodeDeploy is waiting on."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cd-hookexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )

    def _del_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for arn in [p["PolicyArn"] for p in iam.list_attached_role_policies(
                RoleName=role_name).get("AttachedPolicies", [])]:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    basic = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codedeploy-hook-callback",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "codedeploy:PutLifecycleEventHookExecutionStatus",
                "Resource": "*",
            }],
        }),
    )
    # Role propagation is waited out by the bounded retry in _create_hook_function.
    return resp["Role"]["Arn"]


def _create_hook_function(ctx, lam, exec_role_arn, hook_status, timeout_s=120):
    name = ctx.unique_name("sim2real-behav-cd-hook-")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Handler="index.handler",
                Role=exec_role_arn,
                Code={"ZipFile": _make_zip(_HOOK_SRC)},
                MemorySize=128,
                Timeout=30,
                Environment={"Variables": {"HOOK_STATUS": hook_status}},
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            unpropagated = err.get("Code") == "InvalidParameterValueException" and (
                "role" in (err.get("Message") or "").lower())
            if unpropagated and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: _cleanup_function(ctx, lam, name))
    _wait_lambda_active(lam, name)
    echoed = lam.get_function_configuration(FunctionName=name).get(
        "Environment", {}).get("Variables", {}).get("HOOK_STATUS")
    assert echoed == hook_status, (
        f"the hook function {name!r} reports HOOK_STATUS {echoed!r}, expected "
        f"{hook_status!r}; the one thing this check varies must be what it says it is"
    )
    return name


def _hook_revision(fn, alias, current_version, target_version, hook_function_name):
    body = _appspec_body(fn, alias, current_version, target_version)
    body["Hooks"] = [{HOOK_EVENT: hook_function_name}]
    return {"revisionType": "AppSpecContent",
            "appSpecContent": {"content": json.dumps(body)}}


def _hook_event_status(cd, dep_id):
    """The HOOK_EVENT lifecycle event's status on the deployment's Lambda target."""
    target_ids, token = [], None
    while True:
        kwargs = {"deploymentId": dep_id}
        if token:
            kwargs["nextToken"] = token
        resp = cd.list_deployment_targets(**kwargs)
        target_ids.extend(resp.get("targetIds") or [])
        token = resp.get("nextToken")
        if not token:
            break
    assert target_ids, f"deployment {dep_id!r} exposed no deployment targets"
    seen = []
    for target_id in target_ids:
        target = cd.get_deployment_target(
            deploymentId=dep_id, targetId=target_id)["deploymentTarget"]
        for event in (target.get("lambdaTarget") or {}).get("lifecycleEvents", []):
            seen.append((event.get("lifecycleEventName"), event.get("status")))
            if event.get("lifecycleEventName") == HOOK_EVENT:
                return event.get("status")
    raise AssertionError(
        f"deployment {dep_id!r} recorded no {HOOK_EVENT} lifecycle event; the events "
        f"present were {seen!r}, so the AppSpec hook was never run"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
