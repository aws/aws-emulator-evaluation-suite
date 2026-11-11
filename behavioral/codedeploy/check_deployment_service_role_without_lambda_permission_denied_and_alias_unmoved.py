"""deployment-service-role-without-lambda-permission-denied-and-alias-unmoved."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deployment-service-role-without-lambda-permission-denied-and-alias-unmoved"
GROUP = 'overly-permissive'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")
# A service role with no Lambda actions is accepted by CreateDeploymentGroup and
# CreateDeployment; the denial surfaces only in the deployment's errorInformation.
_DENIED_CODE = "IAM_ROLE_PERMISSIONS"
_DENIED_SERVICE = "AWSLambda"


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A deployment whose service role grants no Lambda actions fails with IAM_ROLE_PERMISSIONS
    naming AWSLambda and leaves the alias unmoved; the same shift via a permissioned role succeeds.

    Reference: https://docs.aws.amazon.com/codedeploy/latest/userguide/getting-started-create-service-role.html
    """
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")

    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    v3 = _publish_version(lam, fn, 3)
    assert len({v1, v2, v3}) == 3, f"setup: versions collided: {(v1, v2, v3)!r}"

    app = _create_application(ctx, compute_platform="Lambda")
    dg_ok = _create_deployment_group(
        ctx, app, deployment_config="CodeDeployDefault.LambdaAllAtOnce")

    # Created before the control runs so its IAM propagation is off the negative leg's path.
    role_bad = _make_codedeploy_role(ctx, "sim2real-behav-role-cdnolam-", [
        {"Effect": "Allow",
         "Action": ["codedeploy:*", "cloudwatch:DescribeAlarms", "s3:Get*", "s3:List*",
                    "sns:Publish", "tag:GetResources"],
         "Resource": "*"},
    ])
    dg_bad = _create_deployment_group(
        ctx, app, deployment_config="CodeDeployDefault.LambdaAllAtOnce",
        serviceRoleArn=role_bad)
    echoed_role = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=dg_bad
    )["deploymentGroupInfo"].get("serviceRoleArn")
    assert echoed_role == role_bad, (
        f"the deployment group echoed serviceRoleArn {echoed_role!r}, expected the "
        f"unprivileged {role_bad!r}"
    )

    # Control first, so a propagation delay fails the control rather than faking the denial.
    control_id, control = _deploy_and_wait(
        ctx, cd, app, dg_ok, _lambda_revision(fn, alias, v1, v2))
    assert control.get("status") == "Succeeded", (
        f"positive control: the permissioned-role deployment {control_id!r} ended "
        f"{control.get('status')!r} with errorInformation "
        f"{control.get('errorInformation')!r}; the role cannot be isolated until the "
        f"permissioned path is known to work"
    )
    at_v2 = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                  lambda a: a.get("FunctionVersion") == v2,
                  timeout_s=120, interval_s=2)
    assert at_v2["FunctionVersion"] == v2, (
        f"positive control: the permissioned-role deployment did not reach {v2!r}, the "
        f"alias is at {at_v2['FunctionVersion']!r}"
    )

    denied_id, denied = _deploy_and_wait(
        ctx, cd, app, dg_bad, _lambda_revision(fn, alias, v2, v3))
    assert denied.get("status") == "Failed", (
        f"a deployment whose service role grants no Lambda actions ended "
        f"{denied.get('status')!r}, expected 'Failed' "
        f"(errorInformation={denied.get('errorInformation')!r})"
    )
    err = denied.get("errorInformation") or {}
    assert err.get("code") == _DENIED_CODE, (
        f"expected errorInformation code {_DENIED_CODE!r} for a service role without "
        f"Lambda permissions, got {err!r}"
    )
    expected_message = (
        f"The IAM role {role_bad} does not give you permission to perform operations in "
        f"the following AWS service: {_DENIED_SERVICE}. Contact your AWS administrator if "
        f"you need help. If you are an AWS administrator, you can grant permissions to your "
        f"users or groups by creating IAM policies."
    )
    assert err.get("message") == expected_message, (
        f"the denial must name the role and the service it could not reach; expected "
        f"{expected_message!r}, got {err.get('message')!r}"
    )

    unmoved = lam.get_alias(FunctionName=fn, Name=alias)
    assert unmoved["FunctionVersion"] == v2, (
        f"effect not absent: the alias moved to {unmoved['FunctionVersion']!r} even though "
        f"the deployment was denied; it must still be at {v2!r}"
    )
    assert not (unmoved.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"effect not absent: the denied deployment left weighted routing on the alias: "
        f"{unmoved!r}"
    )

    after_id, after = _deploy_and_wait(
        ctx, cd, app, dg_ok, _lambda_revision(fn, alias, v2, v3))
    assert after.get("status") == "Succeeded", (
        f"positive control: the identical v2 -> v3 shift through the permissioned role "
        f"ended {after.get('status')!r} (errorInformation="
        f"{after.get('errorInformation')!r}); the service role is then not the only "
        f"difference"
    )
    at_v3 = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                  lambda a: a.get("FunctionVersion") == v3,
                  timeout_s=120, interval_s=2)
    assert at_v3["FunctionVersion"] == v3, (
        f"positive control: the permissioned-role re-run left the alias at "
        f"{at_v3['FunctionVersion']!r}, expected {v3!r}"
    )
    ids = _list_group_deployments(cd, app, dg_bad)
    assert ids == [denied_id], (
        f"the unprivileged group's paginated deployment listing is {ids!r}, expected only "
        f"the denied deployment {denied_id!r}"
    )
    ok_ids = _list_group_deployments(cd, app, dg_ok)
    assert {control_id, after_id} <= set(ok_ids), (
        f"the permissioned group's listing {ok_ids!r} does not contain both "
        f"{control_id!r} and {after_id!r}"
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
    """An execution role the check creates for its own function, removed at teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cd-fn-role-")
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

    def _del_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return arn


def _create_function_with_role_retry(lam, **kwargs):
    """CreateFunction refuses a freshly created execution role until IAM propagates it;
    retry only that refusal, under one deadline on every target."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = err.get("Code") == "InvalidParameterValueException" and (
                "cannot be assumed" in (err.get("Message") or "")
            )
            if transient and time.monotonic() < deadline:
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
    # IAM has no "policy is effective" signal; _create_deployment_group retries on InvalidRole.
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
    """Stop the deployment at teardown: a non-terminal deployment blocks its group's deletion.

    LIFO cleanup runs this before the group's own cleanup."""
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
