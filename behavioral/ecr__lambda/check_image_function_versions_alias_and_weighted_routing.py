"""image-function-versions-alias-and-weighted-routing."""
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

CHECK = "image-function-versions-alias-and-weighted-routing"
GROUP = "container-image"
SERVICES = ["ecr", "lambda"]

_BASE_REPO = "lambda/python"
#: The multi-arch index of AWS's Lambda Python 3.13 base image, pinned by digest.
_BASE_INDEX = "sha256:56f309719d88b680ecd398f13358f57a2fd43f1a932ed8ade39ab24664f38589"
_BUILD_TIMEOUT_S = 600.0
_PUSH_TIMEOUT_S = 600.0
_ACTIVE_TIMEOUT_S = 300.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:api", "dp:native", "plane:control", "plane:data")
def run(ctx) -> None:
    """A published image-function version keeps its publish-time digest after $LATEST moves, an
    alias pinned to it keeps running it, an alias on it weighted {newer: 1.0} runs only the newer
    version, and removing that routing returns every invoke to the alias's own version.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-traffic-shifting-using-aliases.html
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

    ref_a = _build_and_push(ctx, env, work, registry_host, repo["uri"], base_ref, "a", "stamp-a")
    fn = _image_function(ctx, role_arn, ref_a)
    digest_a = _pushed_digest(ecr, repo["name"], "a")

    resp, body = _invoke(lam, fn)
    assert body == {"stamp": "stamp-a", "echo": None}, (
        f"the first invoke of the image-a function returned {body!r}")
    assert resp.get("ExecutedVersion") == "$LATEST", (
        f"invoking FunctionName alone reported ExecutedVersion={resp.get('ExecutedVersion')!r}, "
        f"expected '$LATEST'")

    v1 = lam.publish_version(FunctionName=fn)["Version"]
    conf_v1 = lam.get_function(FunctionName=fn, Qualifier=v1)
    assert conf_v1["Code"]["ResolvedImageUri"] == f"{repo['uri']}@{digest_a}", (
        f"published version {v1} resolved to {conf_v1['Code']['ResolvedImageUri']!r}, expected "
        f"{repo['uri']}@{digest_a}")

    pin_alias = ctx.unique_name("sim2real-img-pin-")
    lam.create_alias(FunctionName=fn, Name=pin_alias, FunctionVersion=v1)
    ctx.on_cleanup(_teardown(lambda: lam.delete_alias(FunctionName=fn, Name=pin_alias),
                             "ResourceNotFoundException"))
    resp, body = _invoke(lam, fn, Qualifier=pin_alias)
    assert resp.get("ExecutedVersion") == v1, (
        f"invoking alias {pin_alias!r}, pinned to version {v1}, reported "
        f"ExecutedVersion={resp.get('ExecutedVersion')!r}")
    assert body["stamp"] == "stamp-a", f"alias {pin_alias!r} returned {body!r}"

    ref_b = _build_and_push(ctx, env, work, registry_host, repo["uri"], base_ref, "b", "stamp-b")
    lam.update_function_code(FunctionName=fn, ImageUri=ref_b)
    conf = _wait_update_settled(lam, fn)
    digest_b = _pushed_digest(ecr, repo["name"], "b")
    assert conf["Code"]["ResolvedImageUri"] == f"{repo['uri']}@{digest_b}", (
        f"after UpdateFunctionCode to {ref_b!r}, $LATEST resolved to "
        f"{conf['Code']['ResolvedImageUri']!r}, expected {repo['uri']}@{digest_b}")

    resp, body = _invoke(lam, fn)
    assert body["stamp"] == "stamp-b", f"invoking $LATEST after the code update returned {body!r}"
    assert resp.get("ExecutedVersion") == "$LATEST", (
        f"invoking FunctionName alone after the update reported "
        f"ExecutedVersion={resp.get('ExecutedVersion')!r}")

    v2 = lam.publish_version(FunctionName=fn)["Version"]
    conf_v2 = lam.get_function(FunctionName=fn, Qualifier=v2)
    assert conf_v2["Code"]["ResolvedImageUri"] == f"{repo['uri']}@{digest_b}", (
        f"published version {v2} resolved to {conf_v2['Code']['ResolvedImageUri']!r}, expected "
        f"{repo['uri']}@{digest_b}")

    conf_v1_again = lam.get_function(FunctionName=fn, Qualifier=v1)
    assert conf_v1_again["Code"]["ResolvedImageUri"] == f"{repo['uri']}@{digest_a}", (
        f"version {v1} resolved to {conf_v1_again['Code']['ResolvedImageUri']!r} after $LATEST "
        f"moved to the new image, expected its own pinned {repo['uri']}@{digest_a} to survive")

    resp, body = _invoke(lam, fn, Qualifier=pin_alias)
    assert resp.get("ExecutedVersion") == v1, (
        f"alias {pin_alias!r} reported ExecutedVersion={resp.get('ExecutedVersion')!r} after "
        f"$LATEST moved, expected it to keep running version {v1}")
    assert body["stamp"] == "stamp-a", (
        f"alias {pin_alias!r} returned {body!r} after $LATEST moved to the new image")

    canary_alias = ctx.unique_name("sim2real-img-canary-")
    # The alias's own version is v1; a weight of 1.0 on v2 sends every invoke to v2, so an
    # ignored RoutingConfig (every invoke on v1) and an honored one (every invoke on v2) differ.
    lam.create_alias(FunctionName=fn, Name=canary_alias, FunctionVersion=v1,
                     RoutingConfig={"AdditionalVersionWeights": {v2: 1.0}})
    ctx.on_cleanup(_teardown(lambda: lam.delete_alias(FunctionName=fn, Name=canary_alias),
                             "ResourceNotFoundException"))
    alias = lam.get_alias(FunctionName=fn, Name=canary_alias)
    assert (alias["FunctionVersion"], alias.get("RoutingConfig")) == (
        v1, {"AdditionalVersionWeights": {v2: 1.0}}
    ), (
        f"GetAlias {canary_alias!r} returned FunctionVersion={alias['FunctionVersion']!r} "
        f"RoutingConfig={alias.get('RoutingConfig')!r}, expected {v1!r} with {{{v2!r}: 1.0}}")

    _assert_routing_converges(ctx, lam, fn, canary_alias, v2, "stamp-b",
                              what=f"FunctionVersion {v1} with AdditionalVersionWeights {{{v2}: 1.0}}")

    # Removing the routing returns every invoke to the alias's own version, v1.
    lam.update_alias(FunctionName=fn, Name=canary_alias,
                     RoutingConfig={"AdditionalVersionWeights": {}})
    _assert_routing_converges(ctx, lam, fn, canary_alias, v1, "stamp-a",
                              what=f"FunctionVersion {v1} with no AdditionalVersionWeights")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only ``not_found`` codes mean the resource is already gone."""

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
    """A scratch directory for the Dockerfiles this check writes, removed at cleanup."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-imgver-"))
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
    """A fresh Lambda execution role with only AWSLambdaBasicExecutionRole attached."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-imgver-role-")
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
    """A private ECR repository, scanning off, force-deleted at cleanup."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-imgver-")
    repo = ecr.create_repository(
        repositoryName=name, imageScanningConfiguration={"scanOnPush": False},
        tags=[{"Key": "sim2real", "Value": CHECK}])["repository"]
    ctx.on_cleanup(_teardown(lambda: ecr.delete_repository(repositoryName=name, force=True),
                             "RepositoryNotFoundException"))
    return {"name": name, "uri": repo["repositoryUri"]}


def _registry_login(ctx, env) -> str:
    """`docker login` to this account's private registry; returns the registry host."""
    auth = ctx.client("ecr").get_authorization_token()["authorizationData"][0]
    password = base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)[1]
    registry = urlsplit(ctx.endpoint_url(auth["proxyEndpoint"])).netloc
    _docker(ctx, env, ["login", "--username", "AWS", "--password-stdin", registry],
           timeout_s=120.0, stdin=password)
    return registry


def _base_image_digest(ctx, env) -> str:
    """The linux/amd64 manifest digest of AWS's own public Lambda Python base image, read once."""
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


def _build_and_push(ctx, env, work: Path, registry_host: str, repo_uri: str, base_ref: str,
                    tag: str, stamp: str) -> str:
    """Build a one-layer image over AWS's own pinned Lambda Python base and push it as *tag*."""
    image_dir = work / tag
    image_dir.mkdir()
    (image_dir / "Dockerfile").write_text(
        f"FROM public.ecr.aws/{base_ref}\n"
        "COPY app.py ${LAMBDA_TASK_ROOT}/\n"
        'CMD ["app.handler"]\n'
    )
    (image_dir / "app.py").write_text(
        f'STAMP = "{stamp}"\n\n\ndef handler(event, context):\n'
        '    return {"stamp": STAMP, "echo": event.get("echo")}\n'
    )
    ref = f"{registry_host}/{repo_uri.split('/', 1)[1]}:{tag}"
    ctx.on_cleanup(lambda: _remove_local_image(env, ref))
    _docker(ctx, env, ["build", "--platform", "linux/amd64", "-t", ref, str(image_dir)],
           timeout_s=_BUILD_TIMEOUT_S)
    _docker(ctx, env, ["push", ref], timeout_s=_PUSH_TIMEOUT_S)
    return ref


def _pushed_digest(ecr, repo: str, tag: str) -> str:
    detail = ecr.describe_images(repositoryName=repo, imageIds=[{"imageTag": tag}])["imageDetails"][0]
    assert tag in detail.get("imageTags", []), (
        f"DescribeImages for tag {tag!r} in {repo!r} returned tags {detail.get('imageTags')!r}")
    return detail["imageDigest"]


def _image_function(ctx, role_arn: str, image_uri: str) -> str:
    """A PackageType=Image function from *image_uri*, created through IAM propagation and Active."""
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-imgver-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
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
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll_until_left(
        ctx, lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") in ("Active", "Failed"), timeout_s=_ACTIVE_TIMEOUT_S)
    assert conf["State"] == "Active", f"function {name} ended State={conf['State']!r}: {conf.get('StateReason')!r}"
    return name


def _wait_update_settled(lam, fn: str, timeout_s: float = _ACTIVE_TIMEOUT_S) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function(FunctionName=fn)
        conf = last["Configuration"]
        if conf.get("LastUpdateStatus") != "InProgress" and conf["State"] != "Pending":
            assert conf.get("LastUpdateStatus") == "Successful", (
                f"{fn} LastUpdateStatus={conf.get('LastUpdateStatus')!r} "
                f"{conf.get('LastUpdateStatusReason')!r}")
            return last
        time.sleep(2.0)
    raise AssertionError(f"{fn} update never settled in {timeout_s}s: {last!r}")


def _poll_until_left(ctx, probe, done, *, timeout_s: float) -> dict:
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
    """Delete log group *name* until *reads* consecutive reads find it absent, since a buffered
    stream can flush and recreate it after the function's own delete returns."""
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


def _invoke(lam, fn: str, **extra):
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse",
                      Payload=json.dumps({}).encode(), **extra)
    raw = resp["Payload"].read()
    assert "FunctionError" not in resp, (
        f"invoke of {fn!r} ({extra}) returned FunctionError={resp.get('FunctionError')!r}: "
        f"{raw[:600]!r}")
    return resp, json.loads(raw)


def _assert_routing_converges(ctx, lam, fn: str, qualifier: str, want_version: str,
                              want_stamp: str, *, what: str, streak: int = 5,
                              timeout_s: float = 90.0) -> None:
    """Invoke through *qualifier* until *streak* calls land on *want_version* in a row.

    A RoutingConfig of weight 1.0, or none, is deterministic, but it can take a moment after
    CreateAlias or UpdateAlias to take effect; this polls through that window rather than grading
    on the single invoke right after the call.
    """
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    hits = 0
    last_resp = last_body = None
    while True:
        last_resp, last_body = _invoke(lam, fn, Qualifier=qualifier)
        if last_resp.get("ExecutedVersion") == want_version and last_body.get("stamp") == want_stamp:
            hits += 1
            if hits >= streak:
                return
        else:
            hits = 0
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"invoking {qualifier!r} under {what} never settled on version {want_version!r} "
                f"for {streak} calls in a row within {timeout_s}s; last ExecutedVersion="
                f"{last_resp.get('ExecutedVersion')!r} body={last_body!r}")
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
