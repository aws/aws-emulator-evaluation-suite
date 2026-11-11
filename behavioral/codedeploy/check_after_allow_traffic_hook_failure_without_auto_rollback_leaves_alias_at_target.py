"""after-allow-traffic-hook-failure-without-auto-rollback-leaves-alias-at-target."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "after-allow-traffic-hook-failure-without-auto-rollback-leaves-alias-at-target"
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


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Auto-rollback is opt-in: a deployment group with NO autoRollbackConfiguration leaves the
    alias and live invokes parked at the version an AfterAllowTraffic hook just failed on, with
    no rollback spawned, proven by a same-group follow-up deployment rather than a measured wait.

    Reference: https://docs.aws.amazon.com/codedeploy/latest/APIReference/API_CreateDeploymentGroup.html
    Reference: https://docs.aws.amazon.com/codedeploy/latest/userguide/deployments-rollback-and-redeploy.html
    Reference: https://docs.aws.amazon.com/codedeploy/latest/userguide/reference-appspec-file-structure-hooks.html
    """
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")

    exec_role = _create_hook_exec_role(ctx)
    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    hook_bad = _create_hook_function(ctx, lam, exec_role, "Failed")

    app = _create_application(ctx, compute_platform="Lambda")
    dg = _create_deployment_group(
        ctx, app, deployment_config="CodeDeployDefault.LambdaAllAtOnce",
        name=ctx.unique_name("sim2real-behav-cd-dg-norb-"),
    )
    group_info = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=dg)["deploymentGroupInfo"]
    assert not group_info.get("autoRollbackConfiguration", {}).get("enabled"), (
        f"a deployment group created with no autoRollbackConfiguration argument must echo it "
        f"disabled, got {group_info.get('autoRollbackConfiguration')!r}"
    )

    # --- the leg: v1 -> v2, an AfterAllowTraffic hook reporting Failed, no rollback configured ---
    bad_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg,
        revision=_hook_revision(fn, alias, v1, v2, hook_bad))["deploymentId"]
    _register_deployment_teardown(ctx, cd, bad_id)
    shifted = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                    lambda a: a.get("FunctionVersion") == v2,
                    timeout_s=_budget_s(ctx, 180), interval_s=2, ctx=ctx)
    assert shifted["FunctionVersion"] == v2, (
        f"the alias never reached TargetVersion {v2!r} before the {HOOK_EVENT} hook settled; "
        f"it reads {shifted['FunctionVersion']!r}"
    )
    bad_failed = _poll(lambda: cd.get_deployment(deploymentId=bad_id)["deploymentInfo"],
                       lambda i: i.get("status") in TERMINAL,
                       timeout_s=_budget_s(ctx, 300), interval_s=3, ctx=ctx)
    assert bad_failed.get("status") == "Failed", (
        f"the deployment on the no-rollback group whose {HOOK_EVENT} hook reports 'Failed' "
        f"ended {bad_failed.get('status')!r}, expected 'Failed' (errorInformation="
        f"{bad_failed.get('errorInformation')!r})"
    )
    err = bad_failed.get("errorInformation") or {}
    assert err.get("code") == _FAILED_CODE, (
        f"expected errorInformation code {_FAILED_CODE!r} after the {HOOK_EVENT} hook reports "
        f"'Failed', got {err!r}"
    )

    # --- everything the opt-in claim needs, read BEFORE the ordered control's own deployment
    # moves the alias away from v2 ---
    final = lam.get_alias(FunctionName=fn, Name=alias)
    assert final["FunctionVersion"] == v2, (
        f"with no autoRollbackConfiguration the alias must stay parked at the failed "
        f"deployment's TargetVersion {v2!r}; it reads {final['FunctionVersion']!r}. Auto-"
        f"rollback is opt-in, not the default consequence of a Failed deployment"
    )
    assert not (final.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"AllAtOnce must leave no residual weighted routing even on the un-rolled-back leg: "
        f"{final!r}"
    )
    live = _invoked_version(lam, fn, alias)
    assert str(live) == v2, (
        f"a live invoke of {alias!r} returned version {live!r} while GetAlias reads "
        f"{v2!r}; with no rollback the alias and the version invocations reach must still "
        f"agree, on the hook's rejected version rather than being reverted"
    )

    # --- the ordered control: a plain v2 -> v1 deployment, no hook, on the SAME group. The
    # group runs one deployment at a time, so this is only accepted and can only complete once
    # anything bad_id might have spawned is already terminal; that makes its own completion
    # proof that no rollback for bad_id exists, with no window to measure or guess at. ---
    follow_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg,
        revision=_plain_revision(fn, alias, v2, v1))["deploymentId"]
    _register_deployment_teardown(ctx, cd, follow_id)
    follow_info = _poll(lambda: cd.get_deployment(deploymentId=follow_id)["deploymentInfo"],
                        lambda i: i.get("status") in TERMINAL,
                        timeout_s=_budget_s(ctx, 300), interval_s=3, ctx=ctx)
    assert follow_info.get("status") == "Succeeded", (
        f"the ordered control's plain follow-up deployment {follow_id!r} ended "
        f"{follow_info.get('status')!r} with errorInformation "
        f"{follow_info.get('errorInformation')!r}, expected 'Succeeded'"
    )

    bad_final = cd.get_deployment(deploymentId=bad_id)["deploymentInfo"]
    assert not (bad_final.get("rollbackInfo") or {}).get("rollbackDeploymentId"), (
        f"a deployment group with no autoRollbackConfiguration must spawn no rollback for "
        f"{bad_id!r}, but by the time the ordered control's follow-up deployment "
        f"{follow_id!r} completed on the same group, rollbackInfo read "
        f"{bad_final.get('rollbackInfo')!r}"
    )
    ids = _list_group_deployments(cd, app, dg)
    assert set(ids) == {bad_id, follow_id}, (
        f"deployment group {dg!r} must show exactly the failed deployment and its follow-up, "
        f"got {ids!r}"
    )
    for dep_id in ids:
        creator = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"].get("creator")
        assert creator != _ROLLBACK_CREATOR, (
            f"deployment {dep_id!r} in {ids!r} is attributed to {_ROLLBACK_CREATOR!r}; no "
            f"rollback should exist on a group with no autoRollbackConfiguration"
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

    def _teardown_deployment():
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

    ctx.on_cleanup(_teardown_deployment)


def _create_hook_exec_role(ctx):
    """The execution role for the hook Lambda. Needs exactly one non-default permission:
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


def _plain_revision(fn, alias, current_version, target_version):
    """A revision with no Hooks entry: nothing runs an AfterAllowTraffic hook for it."""
    body = _appspec_body(fn, alias, current_version, target_version)
    return {"revisionType": "AppSpecContent",
            "appSpecContent": {"content": json.dumps(body)}}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
