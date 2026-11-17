"""image-create-with-handler-and-runtime-rejected."""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "image-create-with-handler-and-runtime-rejected"
GROUP = "container-image"
SERVICES = ["ecr", "lambda"]

_BASE_REPO = "lambda/python"
#: The multi-arch index of AWS's Lambda Python 3.13 base image, pinned by digest.
_BASE_INDEX = "sha256:56f309719d88b680ecd398f13358f57a2fd43f1a932ed8ade39ab24664f38589"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "dp:native", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction naming PackageType=Image together with Handler and Runtime is refused up
    front and leaves no function behind; the identical call with neither field creates a function
    that reaches Active, reports no Runtime or Handler, and runs the image's CMD.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/images-create.html
    """
    require_tools("docker")
    ctx.verify_account_safety()
    lam = ctx.client("lambda")
    ecr = ctx.client("ecr")

    work = _workdir(ctx)
    env = _docker_env(ctx, work)
    _assert_docker_daemon_alive(env)

    role_arn = _execution_role(ctx)
    repo = _repository(ctx)
    registry_host = _registry_login(ctx, env)
    base_ref = f"{_BASE_REPO}@{_base_image_digest(ctx, env)}"
    ref = _build_and_push(ctx, env, work, registry_host, repo["uri"], base_ref)

    bad_name = ctx.unique_name("sim2real-imghr-fn-")
    ctx.on_cleanup(lambda: _cleanup_function(ctx, lam, bad_name))
    code, message = _error(lambda: lam.create_function(
        FunctionName=bad_name, PackageType="Image", Role=role_arn, Code={"ImageUri": ref},
        Handler="app.handler", Runtime="python3.13", Timeout=20, MemorySize=128,
        Tags={"sim2real": CHECK}))
    assert code == "InvalidParameterValueException", (
        f"CreateFunction naming PackageType=Image with Handler and Runtime gave {code!r}: "
        f"{message!r}")
    expected_message = (
        "The Runtime parameter is not supported for functions created with container images.")
    assert message == expected_message, f"refusal message was {message!r}, expected {expected_message!r}"

    absent_code, absent_message = _error(lambda: lam.get_function(FunctionName=bad_name))
    assert absent_code == "ResourceNotFoundException", (
        f"GetFunction answered {absent_code!r}/{absent_message!r} for {bad_name!r} after the "
        f"refused CreateFunction")
    expected_absent = f"Function not found: {_function_arn(ctx, bad_name)}"
    assert absent_message == expected_absent, (
        f"GetFunction's not-found message was {absent_message!r}, expected {expected_absent!r}")
    names = {f["FunctionName"] for page in lam.get_paginator("list_functions").paginate()
            for f in page["Functions"]}
    assert bad_name not in names, f"{bad_name!r} appears in ListFunctions despite the refusal"

    good_name = _image_function(ctx, role_arn, ref)
    conf = lam.get_function_configuration(FunctionName=good_name)
    assert conf.get("Runtime") is None, (
        f"the control function's PackageType=Image create reported Runtime={conf.get('Runtime')!r}")
    assert conf.get("Handler") is None, (
        f"the control function's PackageType=Image create reported Handler={conf.get('Handler')!r}")
    resp = lam.invoke(FunctionName=good_name, Payload=b"{}")
    raw = resp["Payload"].read()
    assert "FunctionError" not in resp and json.loads(raw) == {"ok": True}, (
        f"invoking the control function returned FunctionError={resp.get('FunctionError')!r} "
        f"payload={raw[:300]!r}, expected the image CMD's {{'ok': True}}")


def _function_arn(ctx, name: str) -> str:
    return f"arn:{ctx.client('sts').get_caller_identity()['Arn'].split(':')[1]}:lambda:{ctx.region}:{ctx.account}:function:{name}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s: float) -> float:
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _workdir(ctx) -> Path:
    work = Path(tempfile.mkdtemp(prefix="sim2real-imghr-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    return work


def _docker_env(ctx, work: Path) -> dict[str, str]:
    env = ctx.subprocess_env()
    if not env.get("DOCKER_CONFIG"):
        config_dir = work / "docker-config"
        config_dir.mkdir(mode=0o700)
        env["DOCKER_CONFIG"] = str(config_dir)
    return env


def _docker(ctx, env, args, *, timeout_s: float, stdin: str | None = None) -> str:
    r = subprocess.run(["docker", *args], env=env, input=stdin, capture_output=True, text=True,
                       timeout=_budget_s(ctx, timeout_s))
    assert r.returncode == 0, (
        f"`docker {' '.join(args[:2])}` exited {r.returncode}: {(r.stdout + r.stderr)[-1200:]!r}")
    return r.stdout


def _assert_docker_daemon_alive(env) -> None:
    r = subprocess.run(["docker", "info"], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"docker daemon unreachable: {r.stderr.strip()[-400:]!r}"


def _execution_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-imghr-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]

    def _delete_role():
        try:
            iam.detach_role_policy(
                RoleName=name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_delete_role)
    iam.attach_role_policy(
        RoleName=name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    return role["Arn"]


def _repository(ctx) -> dict:
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-imghr-")
    repo = ecr.create_repository(
        repositoryName=name, imageScanningConfiguration={"scanOnPush": False},
        tags=[{"Key": "sim2real", "Value": CHECK}])["repository"]
    ctx.on_cleanup(_teardown(lambda: ecr.delete_repository(repositoryName=name, force=True),
                             "RepositoryNotFoundException"))
    return {"name": name, "uri": repo["repositoryUri"]}


def _registry_login(ctx, env) -> str:
    auth = ctx.client("ecr").get_authorization_token()["authorizationData"][0]
    password = base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)[1]
    registry = urlsplit(ctx.endpoint_url(auth["proxyEndpoint"])).netloc
    _docker(ctx, env, ["login", "--username", "AWS", "--password-stdin", registry],
           timeout_s=120.0, stdin=password)
    return registry


def _base_image_digest(ctx, env) -> str:
    raw = _docker(ctx, env, [
        "buildx", "imagetools", "inspect", f"public.ecr.aws/{_BASE_REPO}@{_BASE_INDEX}", "--raw"],
        timeout_s=60.0)
    index = json.loads(raw)
    for entry in index["manifests"]:
        platform = entry["platform"]
        if platform["architecture"] == "amd64" and platform["os"] == "linux":
            return entry["digest"]
    raise AssertionError(
        f"public.ecr.aws/{_BASE_REPO}@{_BASE_INDEX} offers no linux/amd64 child manifest: {raw[:300]!r}")


def _remove_local_image(env, ref: str) -> None:
    r = subprocess.run(["docker", "image", "rm", "-f", ref], env=env, capture_output=True,
                       text=True, timeout=120)
    if r.returncode != 0 and "No such image" not in r.stderr:
        raise RuntimeError(f"`docker image rm {ref}` exited {r.returncode}: {r.stderr[-400:]!r}")


def _build_and_push(ctx, env, work: Path, registry_host: str, repo_uri: str, base_ref: str) -> str:
    image_dir = work / "img"
    image_dir.mkdir()
    (image_dir / "Dockerfile").write_text(
        f"FROM public.ecr.aws/{base_ref}\n"
        "COPY app.py ${LAMBDA_TASK_ROOT}/\n"
        'CMD ["app.handler"]\n'
    )
    (image_dir / "app.py").write_text(
        "def handler(event, context):\n    return {\"ok\": True}\n"
    )
    ref = f"{registry_host}/{repo_uri.split('/', 1)[1]}:img"
    ctx.on_cleanup(lambda: _remove_local_image(env, ref))
    _docker(ctx, env, ["build", "--platform", "linux/amd64", "-t", ref, str(image_dir)],
           timeout_s=600.0)
    _docker(ctx, env, ["push", ref], timeout_s=600.0)
    return ref


def _cleanup_function(ctx, lam, name: str) -> None:
    logs = ctx.client("logs")
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _reap_log_group(logs, f"/aws/lambda/{name}")


def _image_function(ctx, role_arn: str, image_uri: str) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-imghr-fn-")
    ctx.on_cleanup(lambda: _cleanup_function(ctx, lam, name))
    kwargs = {"FunctionName": name, "PackageType": "Image", "Role": role_arn,
             "Code": {"ImageUri": image_uri}, "Architectures": ["x86_64"], "Timeout": 20,
             "MemorySize": 128, "Tags": {"sim2real": CHECK}}
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            last_err = exc.response["Error"]
            if last_err.get("Code") == "InvalidParameterValueException" and (
                "cannot be assumed" in last_err.get("Message", "")):
                time.sleep(3.0)
                continue
            raise
    else:
        raise AssertionError(f"CreateFunction never got past role propagation: {last_err!r}")
    conf = _poll_until(ctx, lambda: lam.get_function_configuration(FunctionName=name),
                      lambda c: c.get("State") in ("Active", "Failed"), timeout_s=300.0)
    assert conf["State"] == "Active", f"function {name} ended State={conf['State']!r}: {conf.get('StateReason')!r}"
    return name


def _poll_until(ctx, probe, done, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s; last={last!r}")
        time.sleep(2.0)


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {name!r} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
