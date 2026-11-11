"""after-allow-traffic-hook-failure-triggers-deployment-failure-rollback."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "after-allow-traffic-hook-failure-triggers-deployment-failure-rollback"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")
HOOK_EVENT = "AfterAllowTraffic"
_FAILED_CODE = "HOOK_EXECUTION_FAILURE"
_ROLLBACK_CREATOR = "codeDeployRollback"
# CodeDeploy invokes this hook itself, during the AfterAllowTraffic lifecycle event.
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AfterAllowTraffic hook reporting Failed fails an already-shifted Lambda deployment with
    HOOK_EXECUTION_FAILURE, and DEPLOYMENT_FAILURE auto-rollback spawns a codeDeployRollback
    deployment that moves live invokes and the alias back to the prior version.

    Reference: https://docs.aws.amazon.com/codedeploy/latest/userguide/reference-appspec-file-structure-hooks.html
    Reference: https://docs.aws.amazon.com/codedeploy/latest/userguide/deployments-rollback-and-redeploy.html
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
        ctx, app, deployment_config="CodeDeployDefault.LambdaAllAtOnce",
        autoRollbackConfiguration={"enabled": True, "events": ["DEPLOYMENT_FAILURE"]},
    )
    group_info = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=dg)["deploymentGroupInfo"]
    assert group_info.get("autoRollbackConfiguration", {}).get("events") == \
        ["DEPLOYMENT_FAILURE"], (
        f"the deployment group echoed autoRollbackConfiguration "
        f"{group_info.get('autoRollbackConfiguration')!r}, expected events "
        f"['DEPLOYMENT_FAILURE']"
    )

    # Control first: an approving AfterAllowTraffic hook must not be mistaken for no hook at all.
    control_id, control = _deploy_and_wait(
        ctx, cd, app, dg, _hook_revision(fn, alias, v1, v2, hook_ok))
    assert control.get("status") == "Succeeded", (
        f"positive control: the deployment whose {HOOK_EVENT} hook reports 'Succeeded' ended "
        f"{control.get('status')!r} with errorInformation {control.get('errorInformation')!r}; "
        f"until this leg passes, a Failed deployment on the other leg proves nothing about "
        f"the hook's verdict"
    )
    control_event = _hook_event_status(cd, control_id)
    assert control_event == "Succeeded", (
        f"positive control: the {HOOK_EVENT} lifecycle event reads {control_event!r} on the "
        f"deployment that completed, expected 'Succeeded'"
    )
    at_v2 = lam.get_alias(FunctionName=fn, Name=alias)
    assert at_v2["FunctionVersion"] == v2, (
        f"positive control: the approved deployment left the alias at "
        f"{at_v2['FunctionVersion']!r}, expected TargetVersion {v2!r}"
    )
    assert not (at_v2.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"positive control: AllAtOnce must leave no residual weighted routing: {at_v2!r}"
    )
    assert not (control.get("rollbackInfo") or {}).get("rollbackDeploymentId"), (
        f"positive control: an approved deployment must spawn no rollback, got rollbackInfo "
        f"{control.get('rollbackInfo')!r}"
    )

    # --- break exactly one thing: the status the AfterAllowTraffic hook reports back ---
    breach_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg,
        revision=_hook_revision(fn, alias, v2, v3, hook_bad))["deploymentId"]
    _register_deployment_teardown(ctx, cd, breach_id)

    # AllAtOnce shifts the alias to TargetVersion before AfterAllowTraffic ever runs, so the
    # alias (and live invokes) must reach v3 even though the deployment is about to fail.
    shifted = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                    lambda a: a.get("FunctionVersion") == v3,
                    timeout_s=_budget_s(ctx, 180), interval_s=2, ctx=ctx)
    assert shifted["FunctionVersion"] == v3, (
        f"the alias never reached TargetVersion {v3!r} before the {HOOK_EVENT} hook settled; "
        f"it reads {shifted['FunctionVersion']!r}. AfterAllowTraffic runs AFTER the shift, "
        f"so a hook failure must not be able to prevent the shift it is meant to validate"
    )
    live_at_shift = _invoked_version(lam, fn, alias)
    assert str(live_at_shift) == v3, (
        f"a live invoke of {alias!r} returned version {live_at_shift!r} while the alias "
        f"reads TargetVersion {v3!r}; GetAlias and the version invocations actually reach "
        f"must agree"
    )

    failed = _poll(lambda: cd.get_deployment(deploymentId=breach_id)["deploymentInfo"],
                   lambda i: i.get("status") in TERMINAL,
                   timeout_s=_budget_s(ctx, 300), interval_s=3, ctx=ctx)
    assert failed.get("status") == "Failed", (
        f"a deployment whose {HOOK_EVENT} hook reports 'Failed' ended {failed.get('status')!r}, "
        f"expected 'Failed' (errorInformation={failed.get('errorInformation')!r})"
    )
    err = failed.get("errorInformation") or {}
    assert err.get("code") == _FAILED_CODE, (
        f"expected errorInformation code {_FAILED_CODE!r} after an {HOOK_EVENT} hook reports "
        f"'Failed', got {err!r}"
    )
    breach_event = _hook_event_status(cd, breach_id)
    assert breach_event == "Failed", (
        f"the {HOOK_EVENT} lifecycle event reads {breach_event!r} on the deployment whose "
        f"hook reported 'Failed'; the hook's verdict must be recorded on the event it gated, "
        f"not just on the deployment"
    )

    # rollbackInfo is populated a beat AFTER the deployment first reads terminal, so this polls
    # an observable condition rather than reading the terminal snapshot.
    attributed = _poll(
        lambda: cd.get_deployment(deploymentId=breach_id)["deploymentInfo"],
        lambda i: bool((i.get("rollbackInfo") or {}).get("rollbackDeploymentId")),
        timeout_s=_budget_s(ctx, 180), interval_s=3, ctx=ctx)
    rollback_id = (attributed.get("rollbackInfo") or {}).get("rollbackDeploymentId")
    assert rollback_id, (
        f"a Failed deployment under a DEPLOYMENT_FAILURE autoRollbackConfiguration must name "
        f"the rollback it spawned in rollbackInfo.rollbackDeploymentId; it reads "
        f"{attributed.get('rollbackInfo')!r}"
    )
    assert rollback_id != breach_id, (
        f"the rollback must be a separate deployment record, not the same id {breach_id!r}"
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
    rollback = _poll(lambda: cd.get_deployment(deploymentId=rollback_id)["deploymentInfo"],
                     lambda i: i.get("status") in TERMINAL,
                     timeout_s=_budget_s(ctx, 240), interval_s=3, ctx=ctx)
    assert rollback.get("status") == "Succeeded", (
        f"the rollback deployment {rollback_id!r} ended {rollback.get('status')!r} with "
        f"errorInformation {rollback.get('errorInformation')!r}, expected 'Succeeded'"
    )
    assert rollback.get("creator") == _ROLLBACK_CREATOR, (
        f"the rollback deployment {rollback_id!r} must be attributed to {_ROLLBACK_CREATOR!r}, "
        f"not {rollback.get('creator')!r}; a rollback the service performed on its own is "
        f"not a user deployment"
    )
    assert (rollback.get("rollbackInfo") or {}).get("rollbackTriggeringDeploymentId") == \
        breach_id, (
        f"the rollback deployment must point back at the deployment that triggered it "
        f"({breach_id!r}); its rollbackInfo reads {rollback.get('rollbackInfo')!r}"
    )

    restored = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                     lambda a: a.get("FunctionVersion") == v2
                     and not (a.get("RoutingConfig") or {}).get("AdditionalVersionWeights"),
                     timeout_s=_budget_s(ctx, 180), interval_s=2, ctx=ctx)
    assert restored["FunctionVersion"] == v2, (
        f"the DEPLOYMENT_FAILURE auto-rollback must restore the alias to the version the "
        f"failed shift started from ({v2!r}), it reads {restored['FunctionVersion']!r}"
    )
    assert not (restored.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"the auto-rollback must leave no residual weighted routing: {restored!r}"
    )
    live_after_rollback = _invoked_version(lam, fn, alias)
    assert str(live_after_rollback) == v2, (
        f"a live invoke of {alias!r} returned version {live_after_rollback!r} after the "
        f"rollback restored GetAlias to {v2!r}; the alias and the version invocations "
        f"actually reach must agree once more"
    )

    ids = _list_group_deployments(cd, app, dg)
    assert {control_id, breach_id, rollback_id} <= set(ids), (
        f"the paginated deployment listing {ids!r} does not contain the control "
        f"{control_id!r}, the failed deployment {breach_id!r} and the rollback {rollback_id!r}"
    )


# ===== helpers =====

def _teardown(undo, *not_found):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes mean
    the resource is already gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(fn, pred, *, timeout_s, interval_s, ctx=None):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(
                    "the run budget ended before this wait finished; not graded")
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _deploy_and_wait(ctx, cd, app, dg, revision, *, timeout_s=300, **extra):
    """create_deployment, register its teardown immediately, then poll to a terminal state."""
    dep_id = cd.create_deployment(applicationName=app, deploymentGroupName=dg,
                                  revision=revision, **extra)["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)
    info = _poll(lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
                 lambda i: i.get("status") in TERMINAL,
                 timeout_s=_budget_s(ctx, timeout_s), interval_s=3, ctx=ctx)
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
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_del_role)
    # No permissions beyond AssumeRole: this function's code calls nothing, and granting it log
    # permissions would create a /aws/lambda/<fn> log group this check would then have to reap.
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
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_alias(FunctionName=name, Name=alias_name),
        "ResourceNotFoundException"))
    return name, v1, v2, alias_name


def _invoked_version(lam, fn, alias):
    """Invoke the alias and read back the version number the handler reports."""
    resp = lam.invoke(FunctionName=f"{fn}:{alias}", Payload=b"{}")
    assert resp.get("FunctionError") is None, (
        f"invoking {fn}:{alias} reported FunctionError {resp.get('FunctionError')!r}: "
        f"{resp['Payload'].read()[:200]!r}"
    )
    return json.loads(resp["Payload"].read())["v"]


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


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cd-app-")
    cd.create_application(
        applicationName=name,
        computePlatform=compute_platform,
        tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(
        lambda: cd.delete_application(applicationName=name),
        "ApplicationDoesNotExistException"))
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
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

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
    # A freshly minted service role is not immediately assumable by CodeDeploy; until the trust
    # relationship propagates, CreateDeploymentGroup answers InvalidRoleException.
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
    ctx.on_cleanup(_teardown(
        lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=name),
        "DeploymentGroupDoesNotExistException"))
    return name


def _register_deployment_teardown(ctx, cd, dep_id):
    """Drive the deployment to a terminal state at teardown: a non-terminal deployment blocks
    its deployment group's deletion, so this must run before the group's own cleanup (LIFO
    gives that ordering for free)."""

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
    """The execution role for the hook Lambdas. Needs exactly one non-default permission:
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
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_del_role)
    # No log permissions: this check never reads logs, and granting them would create a
    # /aws/lambda/<fn> log group on the hook's first invoke that this check would then have
    # to reap.
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
        f"deployment {dep_id!r} recorded no {HOOK_EVENT} lifecycle event; the events present "
        f"were {seen!r}, so the AppSpec hook was never run"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
