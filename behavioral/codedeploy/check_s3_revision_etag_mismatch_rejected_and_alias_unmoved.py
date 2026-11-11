"""s3-revision-etag-mismatch-rejected-and-alias-unmoved."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "s3-revision-etag-mismatch-rejected-and-alias-unmoved"
GROUP = 'error-semantics'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")
APPSPEC_KEY = "appspec.yaml"
# A mismatched eTag is accepted by CreateDeployment and then fails the deployment, reported
# as an unlocatable AppSpec rather than a digest mismatch.
_MISMATCH_CODE = "INVALID_REVISION"
_MISMATCH_MESSAGE = (
    "The AppSpec file cannot be located in the specified S3 bucket. Verify your AppSpec file "
    "is present and that the name and key value pair specified for your S3 bucket are "
    "correct. The S3 bucket must be in your current region"
)


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """An S3 revision with a mismatched eTag fails the deployment with INVALID_REVISION, echoes
    the sent eTag and leaves the alias unmoved, while the same object with its real eTag deploys.

    Reference: https://docs.aws.amazon.com/codedeploy/latest/APIReference/API_S3Location.html
    """
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")

    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    v3 = _publish_version(lam, fn, 3)
    assert len({v1, v2, v3}) == 3, f"setup: versions collided: {(v1, v2, v3)!r}"

    bucket = _create_revision_bucket(ctx, s3)
    app = _create_application(ctx, compute_platform="Lambda")
    dg = _create_deployment_group(
        ctx, app, deployment_config="CodeDeployDefault.LambdaAllAtOnce")

    # Control first: an unpropagated s3:GetObject grant fails with the same INVALID_REVISION.
    etag_ok = _put_appspec(s3, bucket, APPSPEC_KEY, _appspec_yaml(fn, alias, v1, v2))
    control_id, control = _deploy_and_wait(
        ctx, cd, app, dg, _s3_revision(bucket, APPSPEC_KEY, etag_ok))
    assert control.get("status") == "Succeeded", (
        f"positive control: the correct-eTag deployment {control_id!r} ended "
        f"{control.get('status')!r} with errorInformation "
        f"{control.get('errorInformation')!r}; the eTag cannot be isolated until the "
        f"S3-revision path is known to work"
    )
    at_v2 = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                  lambda a: a.get("FunctionVersion") == v2,
                  timeout_s=120, interval_s=2)
    assert at_v2["FunctionVersion"] == v2, (
        f"positive control: the correct-eTag deployment did not reach {v2!r}, the alias "
        f"is at {at_v2['FunctionVersion']!r}"
    )

    # Change one character of the eTag.
    etag_next = _put_appspec(s3, bucket, APPSPEC_KEY, _appspec_yaml(fn, alias, v2, v3))
    etag_bad = ("0" if etag_next[0] != "0" else "1") + etag_next[1:]
    assert etag_bad != etag_next and len(etag_bad) == len(etag_next), (
        f"setup: the altered eTag {etag_bad!r} is not a one-character mutation of "
        f"{etag_next!r}"
    )
    bad_id, bad = _deploy_and_wait(
        ctx, cd, app, dg, _s3_revision(bucket, APPSPEC_KEY, etag_bad))
    assert bad.get("status") == "Failed", (
        f"a deployment naming a mismatched S3 eTag ended {bad.get('status')!r}, expected "
        f"'Failed' (errorInformation={bad.get('errorInformation')!r})"
    )
    err = bad.get("errorInformation") or {}
    assert err.get("code") == _MISMATCH_CODE, (
        f"expected errorInformation code {_MISMATCH_CODE!r} for a mismatched S3 eTag, got "
        f"{err!r}"
    )
    assert err.get("message") == _MISMATCH_MESSAGE, (
        f"expected the failure message {_MISMATCH_MESSAGE!r}, got {err.get('message')!r}"
    )
    echoed = bad.get("revision", {}).get("s3Location", {})
    assert echoed.get("eTag") == etag_bad, (
        f"the failed deployment echoed eTag {echoed.get('eTag')!r}; it must record the "
        f"eTag that was SENT ({etag_bad!r}), not silently substitute the stored "
        f"{etag_next!r}"
    )

    unmoved = lam.get_alias(FunctionName=fn, Name=alias)
    assert unmoved["FunctionVersion"] == v2, (
        f"effect not absent: the alias moved to {unmoved['FunctionVersion']!r} despite the "
        f"revision being rejected; it must still be at {v2!r}"
    )
    assert not (unmoved.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"effect not absent: the rejected revision left weighted routing on the alias: "
        f"{unmoved!r}"
    )

    # Second control: the same object with its real eTag deploys.
    good_id, good = _deploy_and_wait(
        ctx, cd, app, dg, _s3_revision(bucket, APPSPEC_KEY, etag_next))
    assert good.get("status") == "Succeeded", (
        f"positive control: the same object with its real eTag {etag_next!r} ended "
        f"{good.get('status')!r} (errorInformation={good.get('errorInformation')!r}); the "
        f"eTag is then not the only difference"
    )
    at_v3 = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                  lambda a: a.get("FunctionVersion") == v3,
                  timeout_s=120, interval_s=2)
    assert at_v3["FunctionVersion"] == v3, (
        f"positive control: the correct-eTag re-run left the alias at "
        f"{at_v3['FunctionVersion']!r}, expected {v3!r}"
    )
    ids = _list_group_deployments(cd, app, dg)
    assert {control_id, bad_id, good_id} <= set(ids), (
        f"the paginated deployment listing {ids!r} does not contain all three of "
        f"{(control_id, bad_id, good_id)!r}"
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
    """An execution role for the function; it is never invoked, so the role has no permissions."""
    cached = getattr(ctx, "_cd_lambda_exec_role_arn", None)
    if cached:
        return cached
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
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx._cd_lambda_exec_role_arn = arn
    return arn


def _create_function_when_role_assumable(lam, timeout_s=90, **kwargs):
    """CreateFunction, retried while a freshly created execution role has not yet
    propagated to Lambda. Bounded: the last refusal is raised once the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = err.get("Code") == "InvalidParameterValueException" and (
                "cannot be assumed" in (err.get("Message") or "")
            )
            if not propagating or time.monotonic() >= deadline:
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


def _appspec_yaml(fn, alias, current_version, target_version):
    """The AppSpec as YAML text; a Lambda S3 revision must be the AppSpec file itself.

    A zip bundle is accepted by CreateDeployment and then fails with INVALID_REVISION."""
    return (
        "version: 0.0\n"
        "Resources:\n"
        "  - myLambdaFunction:\n"
        "      Type: AWS::Lambda::Function\n"
        "      Properties:\n"
        f'        Name: "{fn}"\n'
        f'        Alias: "{alias}"\n'
        f'        CurrentVersion: "{current_version}"\n'
        f'        TargetVersion: "{target_version}"\n'
    )


def _create_revision_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-behav-cd-rev-")
    s3.create_bucket(Bucket=name,
                     CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _drop():
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            for obj in page.get("Contents") or []:
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_drop)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real", "Value": CHECK}]})
    return name


def _put_appspec(s3, bucket, key, body):
    """Upload the AppSpec and return the ETag reported by head_object.

    Under SSE-KMS default encryption the ETag is not an MD5, so read the stored value."""
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode())
    return s3.head_object(Bucket=bucket, Key=key)["ETag"].strip('"')


def _s3_revision(bucket, key, etag):
    return {"revisionType": "S3",
            "s3Location": {"bucket": bucket, "key": key, "bundleType": "YAML",
                           "eTag": etag}}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
