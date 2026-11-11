"""concurrent-create-deployment-one-wins-rest-rejected."""
from __future__ import annotations

import io
import json
import textwrap
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-create-deployment-one-wins-rest-rejected"
GROUP = 'concurrency'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")
RACERS = 5
CANARY_PERCENTAGE = 10
# A canary interval keeps the winner non-terminal for about a minute, so the losers arrive
# while it runs; an AllAtOnce deployment finishes in ~5 s and would make the race vacuous.
CANARY_INTERVAL_MINUTES = 1
_LIMIT_CODE = "DeploymentLimitExceededException"


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-configurations.html
@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """Of five simultaneous CreateDeployment calls on one group exactly one is accepted and the rest
    fail DeploymentLimitExceededException naming it; the group never holds two non-terminal
    deployments, and once the winner Succeeded a new deployment runs and moves the alias again."""
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")

    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    v3 = _publish_version(lam, fn, 3)
    assert len({v1, v2, v3}) == 3, f"setup: versions collided: {(v1, v2, v3)!r}"

    app = _create_application(ctx, compute_platform="Lambda")
    cfg = _create_deployment_config(
        ctx,
        compute_platform="Lambda",
        traffic_routing_config={
            "type": "TimeBasedCanary",
            "timeBasedCanary": {"canaryPercentage": CANARY_PERCENTAGE,
                                "canaryInterval": CANARY_INTERVAL_MINUTES},
        },
    )
    dg = _create_deployment_group(ctx, app, deployment_config=cfg)
    revision = _lambda_revision(fn, alias, v1, v2)

    gate = threading.Barrier(RACERS)
    accepted, refused, refused_messages = [], [], []
    lock = threading.Lock()

    def _race(_i):
        gate.wait(timeout=60)
        try:
            dep_id = cd.create_deployment(
                applicationName=app, deploymentGroupName=dg,
                deploymentConfigName=cfg, revision=revision)["deploymentId"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            with lock:
                refused.append(err.get("Code"))
                refused_messages.append(err.get("Message"))
            return
        with lock:
            accepted.append(dep_id)

    with ThreadPoolExecutor(max_workers=RACERS) as pool:
        list(pool.map(_race, range(RACERS)))

    # Register every accepted deployment's teardown before asserting anything: if the
    # service wrongly accepted several, they all exist and all block the group's deletion.
    for dep_id in accepted:
        _register_deployment_teardown(ctx, cd, dep_id)

    assert len(accepted) == 1, (
        f"{len(accepted)!r} of {RACERS!r} concurrent CreateDeployment calls were accepted "
        f"against one deployment group ({accepted!r}); CodeDeploy admits exactly one "
        f"non-terminal deployment per group, so the rest must be refused rather than queued"
    )
    assert set(refused) == {_LIMIT_CODE}, (
        f"the {len(refused)!r} refused calls returned {sorted(set(refused))!r}, expected "
        f"only {_LIMIT_CODE!r}"
    )
    assert len(refused) == RACERS - 1, (
        f"{len(refused)!r} calls were refused out of {RACERS!r} with one accepted; the "
        f"counts do not add up: accepted={accepted!r} refused={refused!r}"
    )
    winner = accepted[0]
    dg_id = cd.get_deployment_group(applicationName=app, deploymentGroupName=dg)[
        "deploymentGroupInfo"]["deploymentGroupId"]
    # Real CodeDeploy words the same refusal two ways within one race, with and without the
    # deployment group id; each refused call must carry one of the two exact texts.
    expected_messages = {
        f"The Deployment Group '{dg} (id={dg_id})' already has an active Deployment '{winner}'",
        f"The Deployment Group '{dg}' already has an active Deployment '{winner}'",
    }
    assert refused_messages and set(refused_messages) <= expected_messages, (
        f"the refused calls returned messages {sorted(set(refused_messages))!r}, expected "
        f"each to be one of {sorted(expected_messages)!r}"
    )

    # The invariant, read back from the service rather than inferred from the responses.
    ids = _list_group_deployments(cd, app, dg)
    assert winner in ids, (
        f"the accepted deployment {winner!r} is absent from the group's paginated listing "
        f"{ids!r}"
    )
    statuses = _statuses(cd, ids)
    nonterminal = [d for d, s in statuses.items() if s not in TERMINAL]
    assert len(nonterminal) <= 1, (
        f"the group held {len(nonterminal)!r} deployments in a non-terminal state at once "
        f"({nonterminal!r}); statuses were {statuses!r}. Two concurrent deployments to one "
        f"group is a state CodeDeploy cannot be in"
    )

    # A refusal while the winner is still running must not be a permanent lockout.
    won = _poll(lambda: cd.get_deployment(deploymentId=winner)["deploymentInfo"],
                lambda i: i.get("status") in TERMINAL,
                timeout_s=420, interval_s=3)
    assert won.get("status") == "Succeeded", (
        f"the winning deployment {winner!r} ended {won.get('status')!r} with "
        f"errorInformation {won.get('errorInformation')!r}"
    )
    at_v2 = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                  lambda a: a.get("FunctionVersion") == v2
                  and not (a.get("RoutingConfig") or {}).get("AdditionalVersionWeights"),
                  timeout_s=180, interval_s=2)
    assert at_v2["FunctionVersion"] == v2, (
        f"the winning deployment left the alias at {at_v2['FunctionVersion']!r}, expected "
        f"{v2!r}"
    )

    # --- positive control: the group is usable again, so the exclusion was temporal ---
    next_id, nxt = _deploy_and_wait(
        ctx, cd, app, dg, _lambda_revision(fn, alias, v2, v3),
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce")
    assert nxt.get("status") == "Succeeded", (
        f"positive control: a deployment created after the winner reached a terminal state "
        f"ended {nxt.get('status')!r} (errorInformation={nxt.get('errorInformation')!r}); "
        f"the exclusion must be temporal, not a lockout"
    )
    at_v3 = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                  lambda a: a.get("FunctionVersion") == v3,
                  timeout_s=120, interval_s=2)
    assert at_v3["FunctionVersion"] == v3, (
        f"positive control: the post-race deployment left the alias at "
        f"{at_v3['FunctionVersion']!r}, expected {v3!r}"
    )
    assert next_id not in ids, (
        f"the control deployment {next_id!r} was already in the listing {ids!r} taken "
        f"during the race, so it is not a fresh deployment"
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
    # IAM exposes no condition reporting that a policy has become effective; the bounded
    # InvalidRoleException retry in _create_deployment_group (a deadline, not a sleep) is
    # what makes the check correct against real IAM propagation delay.
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


def _statuses(cd, ids):
    """deploymentId -> status for every id, batched 25 at a time (BatchGetDeployments' cap)."""
    out = {}
    ids = list(ids)
    for i in range(0, len(ids), 25):
        for info in cd.batch_get_deployments(
                deploymentIds=ids[i:i + 25])["deploymentsInfo"]:
            out[info["deploymentId"]] = info.get("status")
    missing = [d for d in ids if d not in out]
    assert not missing, (
        f"BatchGetDeployments omitted {missing!r}, which ListDeployments returned"
    )
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
