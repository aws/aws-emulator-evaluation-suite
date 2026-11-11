"""linear-traffic-shift-walks-the-weight-ladder-over-time."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "linear-traffic-shift-walks-the-weight-ladder-over-time"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")
LINEAR_PERCENTAGE = 25
LINEAR_INTERVAL_MINUTES = 1
# linearPercentage=25 fully determines the ladder: 25% then 50% then 75% of traffic on the
# target version, one step per linearInterval, then a wholesale cutover (~184 s end to end).
EXPECTED_LADDER = [0.25, 0.5, 0.75]
# Three one-minute intervals cannot elapse in less than this. Well below the ~184 s a real
# shift takes, so jitter cannot reach it, while a state machine that advances on read count
# rather than the clock cannot avoid it.
MIN_ELAPSED_S = 100


# timing:real-time — schedule: 180 s https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-configurations.html
@tags("axis:happy-path", "concern:representation", "plane:control", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """A TimeBasedLinear deployment walks the alias through 25/50/75% weights on the target version,
    in order, with the pre-deployment primary kept throughout, takes at least the paced wall-clock
    time, then cuts over fully with weighted routing cleared.
    """
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")

    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    app = _create_application(ctx, compute_platform="Lambda")
    cfg = _create_deployment_config(
        ctx,
        compute_platform="Lambda",
        traffic_routing_config={
            "type": "TimeBasedLinear",
            "timeBasedLinear": {"linearPercentage": LINEAR_PERCENTAGE,
                                "linearInterval": LINEAR_INTERVAL_MINUTES},
        },
    )
    echoed = cd.get_deployment_config(
        deploymentConfigName=cfg)["deploymentConfigInfo"].get("trafficRoutingConfig") or {}
    assert echoed.get("type") == "TimeBasedLinear", (
        f"the deployment config echoed trafficRoutingConfig {echoed!r}, expected type "
        f"'TimeBasedLinear'"
    )
    assert echoed.get("timeBasedLinear") == {
        "linearPercentage": LINEAR_PERCENTAGE,
        "linearInterval": LINEAR_INTERVAL_MINUTES,
    }, (
        f"the deployment config echoed timeBasedLinear {echoed.get('timeBasedLinear')!r}, "
        f"expected linearPercentage {LINEAR_PERCENTAGE!r} and linearInterval "
        f"{LINEAR_INTERVAL_MINUTES!r}"
    )
    dg = _create_deployment_group(ctx, app, deployment_config=cfg)

    started = time.monotonic()
    dep_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg, deploymentConfigName=cfg,
        revision=_lambda_revision(fn, alias, v1, v2))["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)

    # Sample the live alias until the deployment is terminal -- an observable condition, not
    # a fixed sleep. Every distinct (primary, weights) pair is recorded in the order seen.
    samples = []
    status = None
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        a = lam.get_alias(FunctionName=fn, Name=alias)
        state = (a.get("FunctionVersion"),
                 tuple(sorted(((a.get("RoutingConfig") or {}).get(
                     "AdditionalVersionWeights") or {}).items())))
        if not samples or samples[-1] != state:
            samples.append(state)
        status = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"].get("status")
        if status in TERMINAL:
            break
        time.sleep(2)
    elapsed = time.monotonic() - started

    assert status == "Succeeded", (
        f"the TimeBasedLinear deployment {dep_id!r} ended {status!r} after {elapsed:.1f}s; "
        f"the alias states observed were {samples!r}"
    )

    weighted = [s for s in samples if s[1]]
    ladder = sorted({round(w, 6) for s in weighted for _, w in s[1]})
    assert ladder == EXPECTED_LADDER, (
        f"a TimeBasedLinear shift at {LINEAR_PERCENTAGE}% must expose the weight ladder "
        f"{EXPECTED_LADDER!r}; the alias exposed {ladder!r} across samples {samples!r}. "
        f"A single cutover is not a linear shift"
    )
    in_order = [w for s in weighted for _, w in s[1]]
    assert in_order == sorted(in_order), (
        f"the routing weights did not increase monotonically in the order observed: "
        f"{in_order!r}"
    )
    assert all(list(dict(s[1])) == [v2] for s in weighted), (
        f"every weighted state must weight exactly the TargetVersion {v2!r}; observed "
        f"{[dict(s[1]) for s in weighted]!r}"
    )
    assert all(s[0] == v1 for s in weighted), (
        f"while traffic is split the alias PRIMARY must remain the pre-deployment version "
        f"{v1!r}; observed primaries {[s[0] for s in weighted]!r}. A primary that flips "
        f"early means 100% of traffic already moved and the weight is decorative"
    )
    assert elapsed >= MIN_ELAPSED_S, (
        f"three {LINEAR_INTERVAL_MINUTES}-minute linear intervals completed in "
        f"{elapsed:.1f}s, under the {MIN_ELAPSED_S}s floor; the shift is not paced by the "
        f"clock (a state machine that advances on read count reaches Succeeded in "
        f"milliseconds while still producing the right weights)"
    )

    final = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                  lambda a: a.get("FunctionVersion") == v2
                  and not (a.get("RoutingConfig") or {}).get("AdditionalVersionWeights"),
                  timeout_s=120, interval_s=2)
    assert final["FunctionVersion"] == v2, (
        f"after the last linear step the alias must cut over to {v2!r}, it reads "
        f"{final['FunctionVersion']!r}"
    )
    assert not (final.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"a completed linear shift must clear weighted routing, alias reads {final!r}"
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
    """The raised ClientError's code. Raises if the call unexpectedly succeeds, so an
    over-permissive target can never pass as a code mismatch.
    """
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
    # IAM exposes no condition reporting that a policy has become effective; the bounded
    # InvalidRoleException retry in _create_deployment_group is the actual wait mechanism,
    # so no sleep is needed here.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
