"""create-deployment-rejects-malformed-appspec-content."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "create-deployment-rejects-malformed-appspec-content"
GROUP = 'overly-permissive'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")

# An appspec that is not a parseable document at all: unbalanced brackets and a bare
# dangling key. Hand-written as a string -- the import allowlist has no YAML library,
# and a serializer could not emit an invalid document anyway.
MALFORMED_APPSPEC = 'version: 0.0\nResources: [{"broken": {"Type": \nhooks - - :\n'

# Parseable as YAML, but semantically incomplete: no Resources section. Separates "could
# not parse the document" from "parsed it and it said nothing usable".
NO_RESOURCES_APPSPEC = 'version: 0.0\n'

# Real AWS validates appspec CONTENT
# asynchronously, by the deployment, and the failure always carries this one error code;
# the message is the only discriminator between the two causes above.
_ASYNC_ERROR_CODE = 'INVALID_LAMBDA_CONFIGURATION'
_ASYNC_MESSAGE_PREFIX = (
    'The deployment failed because the AppSpec file that specifies the AWS Lambda deployment '
    'configuration is missing or has an invalid configuration. '
)
_UNPARSEABLE_MESSAGE = (
    _ASYNC_MESSAGE_PREFIX + 'The input AppSpec file is a not well-formed yaml. The template cannot be parsed.'
)
_NO_RESOURCES_MESSAGE = _ASYNC_MESSAGE_PREFIX + 'A Resources section must be specified in the Lambda AppSpec file.'

# The one thing CreateDeployment DOES validate synchronously: an appSpecContent that
# carries neither content nor a sha256.
_EMPTY_CONTENT_MESSAGE = "Content and Sha256 value of the string can't both be empty"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A malformed or Resources-less appspec is accepted by CreateDeployment but the deployment
    ends Failed with INVALID_LAMBDA_CONFIGURATION and a cause-specific message, never moving
    the alias; only empty appSpecContent is refused synchronously (InvalidRevisionException)."""
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")

    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    app = _create_application(ctx, compute_platform="Lambda")
    dg = _create_deployment_group(
        ctx, app, deployment_config="CodeDeployDefault.LambdaAllAtOnce"
    )

    baseline = cd.list_deployments(applicationName=app, deploymentGroupName=dg)
    assert baseline.get("deployments") == [], (
        f"a fresh deployment group must have no deployments: {baseline!r}"
    )

    # --- The one SYNCHRONOUS rejection: an appSpecContent with no body at all. ---
    sync_code, sync_message = _error(
        lambda: cd.create_deployment(
            applicationName=app,
            deploymentGroupName=dg,
            deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
            revision={
                "revisionType": "AppSpecContent",
                "appSpecContent": {"content": ""},
            },
        )
    )
    assert sync_code == "InvalidRevisionException", (
        f"an appSpecContent carrying neither content nor a sha256 is not a revision at "
        f"all and must be refused synchronously with InvalidRevisionException, got "
        f"{sync_code!r}"
    )
    assert sync_message == _EMPTY_CONTENT_MESSAGE, (
        f"the synchronous rejection must say what is missing, so it is distinguishable "
        f"from the async content failures below; expected "
        f"{_EMPTY_CONTENT_MESSAGE!r}, got {sync_message!r}"
    )

    # The effect is absent: no deployment was recorded and the alias did not move.
    after_reject = cd.list_deployments(applicationName=app, deploymentGroupName=dg)
    assert after_reject.get("deployments") == [], (
        f"a synchronously rejected CreateDeployment must record no deployment, found "
        f"{after_reject.get('deployments')!r}"
    )
    unmoved = lam.get_alias(FunctionName=fn, Name=alias)
    assert unmoved["FunctionVersion"] == v1, (
        f"a rejected deployment must not touch the alias; it points at "
        f"{unmoved['FunctionVersion']!r} instead of {v1}"
    )

    # --- Break exactly one thing: the appspec body. ACCEPTED, then fails. ---
    bad_id = cd.create_deployment(
        applicationName=app,
        deploymentGroupName=dg,
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
        revision={
            "revisionType": "AppSpecContent",
            "appSpecContent": {"content": MALFORMED_APPSPEC},
        },
    )["deploymentId"]
    _register_deployment_teardown(ctx, cd, bad_id)
    assert bad_id, "CreateDeployment with a malformed appspec returned no deploymentId"

    # It really was recorded -- the request was accepted, so the deployment exists and is
    # pollable. An emulator that refuses this call synchronously breaks a customer whose
    # code goes straight from CreateDeployment to GetDeployment.
    recorded = cd.list_deployments(applicationName=app, deploymentGroupName=dg)
    assert recorded.get("deployments") == [bad_id], (
        f"the accepted-but-doomed deployment must be listed, got "
        f"{recorded.get('deployments')!r}"
    )

    bad_info = _wait_terminal(cd, bad_id)
    assert bad_info.get("status") == "Failed", (
        f"an unparseable appspec must make the deployment Failed, not "
        f"{bad_info.get('status')!r}; reporting Succeeded is the #1 over-permissiveness "
        f"failure mode for this service"
    )
    bad_err = bad_info.get("errorInformation") or {}
    assert bad_err.get("code") == _ASYNC_ERROR_CODE, (
        f"the failure must be attributed to the appspec via "
        f"errorInformation.code == {_ASYNC_ERROR_CODE}, got {bad_err!r}"
    )
    unparseable_message = bad_err.get("message")
    assert unparseable_message == _UNPARSEABLE_MESSAGE, (
        f"the message must say the appspec could not be PARSED, which is the only way a "
        f"caller can tell this cause from the other one sharing the same code; expected "
        f"{_UNPARSEABLE_MESSAGE!r}, got {unparseable_message!r}"
    )

    # The effect is still absent: a Failed deployment must not have shifted traffic.
    still_unmoved = lam.get_alias(FunctionName=fn, Name=alias)
    assert still_unmoved["FunctionVersion"] == v1, (
        f"a deployment that Failed on its appspec must leave the alias on {v1}, got "
        f"{still_unmoved['FunctionVersion']!r} -- traffic was shifted for a revision that "
        f"was never valid"
    )

    # --- A parseable appspec that says nothing usable: same code, DIFFERENT message. ---
    empty_id = cd.create_deployment(
        applicationName=app,
        deploymentGroupName=dg,
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
        revision={
            "revisionType": "AppSpecContent",
            "appSpecContent": {"content": NO_RESOURCES_APPSPEC},
        },
    )["deploymentId"]
    _register_deployment_teardown(ctx, cd, empty_id)
    empty_info = _wait_terminal(cd, empty_id)
    assert empty_info.get("status") == "Failed", (
        f"an appspec with no Resources section deploys nothing and must Fail, got "
        f"{empty_info.get('status')!r}"
    )
    empty_err = empty_info.get("errorInformation") or {}
    assert empty_err.get("code") == _ASYNC_ERROR_CODE, (
        f"both appspec content failures share errorInformation.code "
        f"{_ASYNC_ERROR_CODE}, got {empty_err!r}"
    )
    no_resources_message = empty_err.get("message")
    assert no_resources_message == _NO_RESOURCES_MESSAGE, (
        f"a document that parsed but declared no Resources must be reported as such, not "
        f"as a parse failure; expected {_NO_RESOURCES_MESSAGE!r}, got "
        f"{no_resources_message!r}"
    )
    assert no_resources_message != unparseable_message, (
        f"one error code covers both causes, so the messages must differ or the two are "
        f"indistinguishable to a caller; both were {no_resources_message!r}"
    )

    # --- The control case: the identical call with a well-formed appspec succeeds. ---
    dep_id = cd.create_deployment(
        applicationName=app,
        deploymentGroupName=dg,
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
        revision=_lambda_revision(fn, alias, v1, v2),
    )["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)
    assert dep_id, "the control CreateDeployment returned no deploymentId"

    controlled = set(cd.list_deployments(
        applicationName=app, deploymentGroupName=dg
    ).get("deployments") or [])
    assert controlled == {bad_id, empty_id, dep_id}, (
        f"the group must list exactly the three ACCEPTED deployments "
        f"{sorted({bad_id, empty_id, dep_id})}, got {sorted(controlled)} -- the "
        f"synchronously refused call must not appear among them"
    )
    info = _wait_terminal(cd, dep_id)
    assert info.get("revision", {}).get("revisionType") == "AppSpecContent", info
    assert info.get("status") == "Succeeded", (
        f"a well-formed appspec must deploy successfully, got {info.get('status')!r} "
        f"errorInformation={info.get('errorInformation')!r}"
    )
    assert info.get("errorInformation") is None, (
        f"a Succeeded deployment must carry no errorInformation, got "
        f"{info.get('errorInformation')!r}"
    )
    # The positive effect, which is what makes every "alias unmoved" assertion above a
    # measurement rather than a no-op: this deployment DOES shift the alias.
    moved = lam.get_alias(FunctionName=fn, Name=alias)
    assert moved["FunctionVersion"] == v2, (
        f"the control deployment must shift the alias to the target version {v2}, got "
        f"{moved['FunctionVersion']!r}"
    )




# ===== helpers =====

def _error(fn):
    """(code, message) of the raised ClientError. An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_terminal(cd, dep_id, timeout_s=600, interval_s=5):
    """deploymentInfo once the deployment has reached a terminal status."""
    deadline = time.monotonic() + timeout_s
    info = None
    while time.monotonic() < deadline:
        info = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"]
        if info.get("status") in TERMINAL:
            return info
        time.sleep(interval_s)
    raise AssertionError(
        f"deployment {dep_id} never reached a terminal status within {timeout_s}s; last "
        f"status {info.get('status') if info else None!r}"
    )


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _lambda_exec_role_arn(ctx):
    """An execution role this check creates (and cleans up) for its own Lambda functions."""
    cached = getattr(ctx, "_cd_lambda_exec_role_arn", None)
    if cached:
        return cached
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cd-lambdarole-")
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
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    ctx._cd_lambda_exec_role_arn = arn
    return arn


def _create_function_when_role_assumable(lam, timeout_s=60, **kwargs):
    """create_function, retried only while Lambda reports the fresh execution role as not
    yet assumable (IAM propagation); any other refusal raises at once."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            role_not_ready = (
                err.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed" in (err.get("Message") or "")
            )
            if not role_not_ready or time.monotonic() >= deadline:
                raise
            time.sleep(2)


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
