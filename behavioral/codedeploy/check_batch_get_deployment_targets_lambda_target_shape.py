"""batch-get-deployment-targets-lambda-target-shape."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "batch-get-deployment-targets-lambda-target-shape"
GROUP = "state-machine"
SERVICES = ["codedeploy"]

TERMINAL = ("Succeeded", "Failed", "Stopped")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Lambda deployment lists exactly one target id naming the function, and its
    BatchGetDeploymentTargets entry is a LambdaTarget whose status reaches Succeeded and whose
    lifecycleEvents include AllowTraffic, the hook that flips the alias.
    """
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")

    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    app = _create_application(ctx, compute_platform="Lambda")
    dg = _create_deployment_group(ctx, app, deployment_config="CodeDeployDefault.LambdaAllAtOnce")

    dep = cd.create_deployment(
        applicationName=app,
        deploymentGroupName=dg,
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
        description="sim2real-behav lambda target shape",
        revision=_lambda_revision(fn, alias, v1, v2),
    )
    dep_id = dep["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)

    info = _poll(
        lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
        lambda i: i.get("status") in TERMINAL,
        timeout_s=420,  # an all-at-once Lambda deployment settles in about a minute on real AWS
        interval_s=5,
        description=f"deployment {dep_id} reaches a terminal status",
    )
    assert info.get("status") == "Succeeded", (
        f"deployment {dep_id} terminal status is {info.get('status')!r}, expected Succeeded "
        f"(errorInformation={info.get('errorInformation')!r})"
    )

    target_ids = cd.list_deployment_targets(deploymentId=dep_id)["targetIds"]
    assert len(target_ids) == 1, f"expected exactly one target id, got {target_ids!r}"
    assert fn in target_ids[0], (
        f"expected the lone target id to contain the function name {fn!r}, got {target_ids[0]!r}"
    )

    batch = cd.batch_get_deployment_targets(deploymentId=dep_id, targetIds=target_ids)
    targets = batch["deploymentTargets"]
    assert len(targets) == 1, f"expected exactly one deployment target, got {len(targets)}: {targets!r}"
    target = targets[0]
    # The wire value is "LambdaTarget", not the Smithy union member name "LambdaFunction".
    assert target.get("deploymentTargetType") == "LambdaTarget", (
        f"expected deploymentTargetType LambdaTarget, got {target.get('deploymentTargetType')!r}"
    )
    lambda_target = target.get("lambdaTarget")
    assert lambda_target is not None, f"expected a populated lambdaTarget, got {target!r}"
    assert lambda_target.get("status") == "Succeeded", (
        f"expected lambdaTarget.status Succeeded, got {lambda_target.get('status')!r}"
    )
    event_names = [e.get("lifecycleEventName") for e in lambda_target.get("lifecycleEvents", [])]
    assert "AllowTraffic" in event_names, (
        f"expected lifecycleEvents to include AllowTraffic (the alias-flip hook), got {event_names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


def _poll(fn, pred, *, timeout_s, interval_s, description="condition"):
    """Poll fn() until pred holds; RAISE on timeout, naming the last value."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_LAMBDA_BASIC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _lambda_exec_role_arn(ctx):
    """Mint this check's own Lambda execution role (tagged); its teardown is registered."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-cdt-fn-")
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
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]

    def _del_role():
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_LAMBDA_BASIC)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_LAMBDA_BASIC)
    return arn


def _create_function_with_role_retry(lam, **kwargs):
    """CreateFunction against a role minted moments ago: until its trust propagates Lambda
    refuses it with InvalidParameterValueException. Retry only that transient, bounded."""
    deadline = time.monotonic() + 90  # IAM trust propagation is typically ~10 s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (err.get("Code") == "InvalidParameterValueException"
                         and "cannot be assumed" in (err.get("Message") or ""))
            if transient and time.monotonic() < deadline:
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
    name = ctx.unique_name("sim2real-behav-cdt-fn-")
    _create_function_with_role_retry(
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
    return {"revisionType": "AppSpecContent", "appSpecContent": {"content": json.dumps(appspec)}}


def _register_deployment_teardown(ctx, cd, dep_id):
    def _stop():
        try:
            cd.stop_deployment(deploymentId=dep_id, autoRollbackEnabled=False)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DeploymentAlreadyCompletedException",
                "DeploymentDoesNotExistException",
                "DeploymentGroupDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_stop)


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-app-")
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
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


def _create_deployment_group(ctx, app, *, deployment_config="CodeDeployDefault.LambdaAllAtOnce", blue_green=True):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-dg-")
    role = _create_service_role(ctx)
    kwargs = {
        "applicationName": app,
        "deploymentGroupName": name,
        "deploymentConfigName": deployment_config,
        "serviceRoleArn": role,
    }
    if blue_green:
        kwargs["deploymentStyle"] = {
            "deploymentType": "BLUE_GREEN",
            "deploymentOption": "WITH_TRAFFIC_CONTROL",
        }
    deadline = time.monotonic() + 75  # the minted service role's trust propagates within ~a minute
    while True:
        try:
            cd.create_deployment_group(**kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            msg = (err.get("Message") or "").lower()
            transient_role = code == "InvalidRoleException" or ("assume" in msg or "not authorized" in msg)
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=name))
    return name
