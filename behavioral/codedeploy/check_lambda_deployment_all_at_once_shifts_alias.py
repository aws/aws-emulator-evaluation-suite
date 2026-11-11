"""lambda-deployment-all-at-once-shifts-alias."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "lambda-deployment-all-at-once-shifts-alias"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")


@tags("axis:happy-path", "cap:c3", "cap:c4", "plane:control")
def run(ctx) -> None:
    """A Lambda AllAtOnce deployment runs to Succeeded and the alias moves from CurrentVersion
    to TargetVersion with no residual weighted routing, so a deployment reported Succeeded
    without updating the alias is caught."""
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")

    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    app = _create_application(ctx, compute_platform="Lambda")
    dg = _create_deployment_group(
        ctx, app, deployment_config="CodeDeployDefault.LambdaAllAtOnce"
    )

    before = lam.get_alias(FunctionName=fn, Name=alias)
    assert before["FunctionVersion"] == v1, (
        f"pre-deployment alias must point at CurrentVersion {v1}, got {before['FunctionVersion']}"
    )

    dep = cd.create_deployment(
        applicationName=app,
        deploymentGroupName=dg,
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
        description="sim2real-behav all-at-once traffic shift",
        revision=_lambda_revision(fn, alias, v1, v2),
    )
    dep_id = dep["deploymentId"]
    assert dep_id, f"CreateDeployment returned no deploymentId: {dep!r}"
    _register_deployment_teardown(ctx, cd, dep_id)

    info = _poll(
        lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
        lambda i: i.get("status") in TERMINAL,
        timeout_s=420,
        interval_s=5,
    )
    status = info.get("status")
    assert status == "Succeeded", (
        f"deployment {dep_id} terminal status is {status!r} "
        f"(errorInformation={info.get('errorInformation')!r}, "
        f"messages={info.get('deploymentStatusMessages')!r})"
    )
    assert info.get("computePlatform") == "Lambda", info
    assert info.get("deploymentGroupName") == dg, info
    assert info.get("revision", {}).get("revisionType") == "AppSpecContent", info

    after = _poll(
        lambda: lam.get_alias(FunctionName=fn, Name=alias),
        lambda a: a.get("FunctionVersion") == v2,
        timeout_s=60,
        interval_s=3,
    )
    assert after["FunctionVersion"] == v2, (
        f"deployment reported Succeeded but alias {alias} still points at "
        f"{after['FunctionVersion']!r}, expected TargetVersion {v2}"
    )
    weights = (after.get("RoutingConfig") or {}).get("AdditionalVersionWeights") or {}
    assert weights == {}, (
        f"AllAtOnce must leave no residual weighted routing, got {weights!r}"
    )

    listed = cd.list_deployments(applicationName=app, deploymentGroupName=dg)
    assert listed.get("deployments") == [dep_id], (
        f"ListDeployments for the group must be exactly [{dep_id}], got "
        f"{listed.get('deployments')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


# ===== helpers =====

def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


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
    """Create a function, publish v1 and v2, and point an alias at v1."""
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
    """Build a Lambda appspec as an inline AppSpecContent revision (no S3)."""
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
    # JSON is a subset of YAML, so this is a valid appspec document and needs no
    # YAML serializer.
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
    """Create a Lambda/ECS blue-green deployment group. Provisions no compute:
    without autoScalingGroups / ecsServices there is no fleet to launch."""
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
    # A freshly minted service role is not immediately assumable by CodeDeploy;
    # until the trust relationship propagates, CreateDeploymentGroup answers
    # InvalidRoleException. Poll through that window only, so a genuinely bad
    # config still fails fast.
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
    """Registered at creation time: stop the deployment if it is still running and
    poll it to a terminal state, so DeleteDeploymentGroup in a later teardown is not
    refused for an in-flight deployment. A cleanup that merely fires StopDeployment
    and returns fails while the deployment is still settling, which leaks the
    deployment group."""

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
