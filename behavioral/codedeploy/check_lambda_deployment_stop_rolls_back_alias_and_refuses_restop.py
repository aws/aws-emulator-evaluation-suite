"""lambda-deployment-stop-rolls-back-alias-and-refuses-restop."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "lambda-deployment-stop-rolls-back-alias-and-refuses-restop"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")

# StopDeployment's response status reports
# whether the STOP was accepted, so it is 'Succeeded' for a deployment that ends 'Stopped'.
_STOP_REQUEST_ACCEPTED = "Succeeded"
_STOP_STATUS_MESSAGE = (
    "No more commands will be scheduled for execution in the deployment instances"
)
_MANUAL_STOP_MESSAGE = "the deployment is cancelled due to an abort request"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopDeployment with auto-rollback stops a canary and restores the alias; re-stopping a Stopped
    deployment is idempotent, stopping a Succeeded one raises DeploymentAlreadyCompletedException,
    and ListDeployments lists both, the canary's createTime before the control's.
    """
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")

    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    app = _create_application(ctx, compute_platform="Lambda")
    # A 5-minute canary gives a wide, deterministic window in which the deployment is
    # non-terminal so StopDeployment has something to stop.
    cfg = _create_deployment_config(
        ctx,
        compute_platform="Lambda",
        traffic_routing_config={
            "type": "TimeBasedCanary",
            "timeBasedCanary": {"canaryPercentage": 10, "canaryInterval": 5},
        },
    )
    dg = _create_deployment_group(ctx, app, deployment_config=cfg)

    dep_id = cd.create_deployment(
        applicationName=app,
        deploymentGroupName=dg,
        deploymentConfigName=cfg,
        revision=_lambda_revision(fn, alias, v1, v2),
        autoRollbackConfiguration={
            "enabled": True,
            "events": ["DEPLOYMENT_STOP_ON_REQUEST"],
        },
    )["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)

    running = _poll(
        lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
        lambda i: i.get("status") in ("InProgress", "Baking", "Ready") + TERMINAL,
        timeout_s=180,
        interval_s=3,
    )
    assert running.get("status") not in TERMINAL, (
        f"deployment {dep_id} reached terminal {running.get('status')!r} before it could "
        "be stopped; a TimeBasedCanary with a 5-minute interval must not complete "
        "immediately"
    )
    assert running.get("autoRollbackConfiguration", {}).get("events") == [
        "DEPLOYMENT_STOP_ON_REQUEST"
    ], running

    stop_resp = cd.stop_deployment(deploymentId=dep_id, autoRollbackEnabled=True)
    # StopDeployment's own status reports the fate of the REQUEST, not of the deployment:
    # it is 'Succeeded' even though the deployment it stopped ends up 'Stopped'. An
    # emulator that echoes the deployment's status here inverts the meaning of the field.
    assert stop_resp.get("status") == _STOP_REQUEST_ACCEPTED, (
        f"StopDeployment reports whether the STOP was accepted, so status must be "
        f"{_STOP_REQUEST_ACCEPTED!r}, got {stop_resp.get('status')!r}"
    )
    assert stop_resp.get("statusMessage") == _STOP_STATUS_MESSAGE, (
        f"expected statusMessage {_STOP_STATUS_MESSAGE!r}, got "
        f"{stop_resp.get('statusMessage')!r}"
    )

    stopped = _poll(
        lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
        lambda i: i.get("status") in TERMINAL,
        timeout_s=300,
        interval_s=5,
    )
    assert stopped.get("status") == "Stopped", (
        f"a stopped deployment must be Stopped, not {stopped.get('status')!r} "
        f"(errorInformation={stopped.get('errorInformation')!r})"
    )
    stop_err = stopped.get("errorInformation") or {}
    assert stop_err.get("code") == "MANUAL_STOP", (
        f"a deployment ended by StopDeployment must attribute itself to MANUAL_STOP, got "
        f"{stop_err!r}"
    )
    assert stop_err.get("message") == _MANUAL_STOP_MESSAGE, (
        f"expected {_MANUAL_STOP_MESSAGE!r}, got {stop_err.get('message')!r}"
    )

    # The observable effect of the rollback: the alias is back on the original
    # version with no residual canary weight.
    restored = _poll(
        lambda: lam.get_alias(FunctionName=fn, Name=alias),
        lambda a: a.get("FunctionVersion") == v1
        and not (a.get("RoutingConfig") or {}).get("AdditionalVersionWeights"),
        timeout_s=180,
        interval_s=3,
    )
    assert restored["FunctionVersion"] == v1, (
        f"auto-rollback must restore the alias to CurrentVersion {v1}, got "
        f"{restored['FunctionVersion']!r}"
    )
    assert not (restored.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"auto-rollback must clear the canary weight, got {restored!r}"
    )

    # Re-stopping an ALREADY-STOPPED deployment is IDEMPOTENT, not refused: the same
    # accepted response comes back and nothing changes. Twice, because idempotence is a
    # claim about repetition.
    for attempt in (2, 3):
        again_resp = cd.stop_deployment(deploymentId=dep_id, autoRollbackEnabled=False)
        assert again_resp.get("status") == _STOP_REQUEST_ACCEPTED, (
            f"stopping an already-Stopped deployment is idempotent, so attempt {attempt} "
            f"must also report {_STOP_REQUEST_ACCEPTED!r}, got "
            f"{again_resp.get('status')!r}"
        )
        assert again_resp.get("statusMessage") == _STOP_STATUS_MESSAGE, (
            f"attempt {attempt} returned a different statusMessage: "
            f"{again_resp.get('statusMessage')!r}"
        )
        # Nothing moved: not the status, not the alias.
        again = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"]
        assert again.get("status") == "Stopped", (
            f"a repeated StopDeployment must not alter the status: "
            f"{again.get('status')!r}"
        )
        assert (again.get("errorInformation") or {}).get("code") == "MANUAL_STOP", (
            f"nor rewrite the errorInformation: {again.get('errorInformation')!r}"
        )
        held = lam.get_alias(FunctionName=fn, Name=alias)
        assert held["FunctionVersion"] == v1, (
            f"a repeated StopDeployment must not move the alias off {v1}, got "
            f"{held['FunctionVersion']!r}"
        )

    # THE refused transition: a deployment that COMPLETED cannot be stopped. This is where
    # DeploymentAlreadyCompletedException actually lives -- 'Stopped' and 'Succeeded' are
    # both terminal but only one of them refuses. AllAtOnce so it completes without waiting
    # out a canary.
    done_id = cd.create_deployment(
        applicationName=app,
        deploymentGroupName=dg,
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
        revision=_lambda_revision(fn, alias, v1, v2),
    )["deploymentId"]
    _register_deployment_teardown(ctx, cd, done_id)
    succeeded = _poll(
        lambda: cd.get_deployment(deploymentId=done_id)["deploymentInfo"],
        lambda i: i.get("status") in TERMINAL,
        timeout_s=420,
        interval_s=5,
    )
    assert succeeded.get("status") == "Succeeded", (
        f"the AllAtOnce control deployment must Succeed, got "
        f"{succeeded.get('status')!r} errorInformation="
        f"{succeeded.get('errorInformation')!r}"
    )
    done_code, done_message = _error(
        lambda: cd.stop_deployment(deploymentId=done_id, autoRollbackEnabled=False)
    )
    assert done_code == "DeploymentAlreadyCompletedException", (
        f"StopDeployment on a SUCCEEDED deployment must raise "
        f"DeploymentAlreadyCompletedException, got {done_code!r}"
    )
    assert done_message == f"The deployment {done_id} is already in state SUCCEEDED", (
        done_message
    )
    # and the refused call left it alone.
    unchanged = cd.get_deployment(deploymentId=done_id)["deploymentInfo"]
    assert unchanged.get("status") == "Succeeded", (
        f"a refused StopDeployment must not alter the status: "
        f"{unchanged.get('status')!r}"
    )

    # ListDeployments documents no order, so createTime (not list position) orders the two.
    ids = cd.list_deployments(applicationName=app, deploymentGroupName=dg)["deployments"]
    assert dep_id in ids, f"ListDeployments must include {dep_id}: {ids!r}"
    assert done_id in ids, f"ListDeployments must include {done_id}: {ids!r}"
    created = dict(zip(ids, _create_times(cd, ids)))
    assert created[dep_id] < created[done_id], (
        f"the canary {dep_id} was created before the control {done_id}, but createTimes are "
        f"{created[dep_id]!r} and {created[done_id]!r}"
    )
    for extra_id in ids:
        if extra_id != dep_id:
            _register_deployment_teardown(ctx, cd, extra_id)





def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _error(fn):
    """(code, message) of the ClientError fn() raises. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_times(cd, ids):
    """createTime for each id, in the order the ids were returned."""
    infos = cd.batch_get_deployments(deploymentIds=list(ids))["deploymentsInfo"]
    by_id = {i["deploymentId"]: i for i in infos}
    out = []
    for d in ids:
        info = by_id.get(d)
        assert info is not None, (
            f"BatchGetDeployments omitted {d}, which ListDeployments returned: "
            f"{sorted(by_id)!r}"
        )
        ct = info.get("createTime")
        assert ct is not None, f"deployment {d} has no createTime: {info!r}"
        out.append(ct)
    return out


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


def _wait_lambda_active(lam, fn, timeout_s=90):
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
    lam.update_function_code(
        FunctionName=name, ZipFile=_make_zip("def handler(e, c): return {'v': 2}")
    )
    _wait_lambda_active(lam, name)
    v2 = lam.publish_version(FunctionName=name, Description="v2")["Version"]
    assert v1 != v2, f"publish_version returned the same version twice: {v1}"
    lam.create_alias(FunctionName=name, Name=alias_name, FunctionVersion=v1)
    return name, v1, v2, alias_name


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
    arn = resp["Role"]["Arn"]
    ctx._cd_service_role_arn = arn
    return arn


def _create_deployment_group(ctx, app, *, deployment_config, name=None, **extra):
    cd = ctx.client("codedeploy")
    name = name or ctx.unique_name("sim2real-behav-cd-dg-")
    kwargs = {
        "applicationName": app,
        "deploymentGroupName": name,
        "deploymentConfigName": deployment_config,
        "serviceRoleArn": _create_service_role(ctx),
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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
