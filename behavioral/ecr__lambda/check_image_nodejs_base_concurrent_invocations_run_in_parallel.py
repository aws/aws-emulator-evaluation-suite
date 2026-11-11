"""image-nodejs-base-concurrent-invocations-run-in-parallel."""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "image-nodejs-base-concurrent-invocations-run-in-parallel"
GROUP = "container-image"
SERVICES = ["ecr", "lambda"]

_BUILD_TIMEOUT_S = 900.0
_PUSH_TIMEOUT_S = 600.0
_LOGIN_TIMEOUT_S = 120.0
_ACTIVE_TIMEOUT_S = 300.0

_CONCURRENCY = 3
_SLEEP_MS = 5000

# The base image is pinned by tag and by its multi-platform index digest; `--platform
# linux/amd64` selects the index's amd64 child.
_DOCKERFILE = """\
FROM public.ecr.aws/lambda/nodejs:22@sha256:d4d50c79b7f5476510311454ec7b2c15dc09af853c53e182ae2daff193d4d420
COPY index.mjs ${LAMBDA_TASK_ROOT}/
CMD ["index.handler"]
"""

_HANDLER = """\
import { randomUUID } from "node:crypto";

const SANDBOX = randomUUID();

export const handler = async (event) => {
  await new Promise((resolve) => setTimeout(resolve, event.sleep_ms));
  return { i: event.i, sandbox: SANDBOX };
};
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:representation", "dp:native", "dp:api", "plane:data")
def run(ctx) -> None:
    """Three simultaneous invokes of a function built FROM the Lambda Node.js 22 base image, each
    awaiting a 5 s timer, all succeed and each get their own execution environment instead of
    queueing onto one.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-concurrency.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-image.html
    """
    require_tools("docker")
    ctx.verify_account_safety()
    work = _workdir(ctx)
    env = _docker_env(ctx, work)
    _assert_docker_daemon_alive(env)
    role_arn = _execution_role(ctx)
    repo = _repository(ctx)
    registry = _registry_login(ctx, env)
    image_dir = work / "image"
    image_dir.mkdir()
    (image_dir / "Dockerfile").write_text(_DOCKERFILE)
    (image_dir / "index.mjs").write_text(_HANDLER)
    image_uri = f"{repo['uri']}:v1"
    _build_and_push(ctx, env, image_dir, registry, repo["uri"], "v1")
    digest = _pushed_digest(ctx, repo["name"], "v1")

    fn = _image_function(ctx, role_arn, image_uri)
    _assert_runs_image(ctx, fn, image_uri, repo["uri"], digest)

    results = _concurrent_round(ctx, fn)
    got = sorted(r["i"] for r in results)
    assert got == list(range(_CONCURRENCY)), (
        f"invokes answered for i={got!r}, expected {list(range(_CONCURRENCY))!r}")
    # An environment serves one request at a time, so requests held in flight together are served
    # by as many environments; a target that queues them reuses one warm environment.
    sandboxes = len({r["sandbox"] for r in results})
    assert sandboxes == _CONCURRENCY, (
        f"expected {_CONCURRENCY} simultaneous invokes to run in {_CONCURRENCY} execution "
        f"environments, they ran in {sandboxes}: {results!r}")


def _concurrent_round(ctx, fn: str) -> list[dict]:
    """``_CONCURRENCY`` RequestResponse invokes issued at once; every one must succeed."""
    with ThreadPoolExecutor(max_workers=_CONCURRENCY) as pool:
        return list(pool.map(lambda i: _invoke(ctx, fn, {"i": i, "sleep_ms": _SLEEP_MS}),
                             range(_CONCURRENCY)))


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s so the wait fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _workdir(ctx) -> Path:
    """A scratch directory of this run's own, removed at cleanup."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-img-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    return work


def _docker_env(ctx, work: Path) -> dict[str, str]:
    """ctx's tool environment for every docker command; the registry login lands in a
    DOCKER_CONFIG of this run's own when ctx does not already supply one."""
    env = ctx.subprocess_env()
    if not env.get("DOCKER_CONFIG"):
        config_dir = work / "docker-config"
        config_dir.mkdir(mode=0o700)
        env["DOCKER_CONFIG"] = str(config_dir)
    return env


def _docker(ctx, env, args, *, timeout_s, stdin=None) -> str:
    """Run ``docker *args``; asserts it exits 0 and returns its stdout."""
    try:
        r = subprocess.run(["docker", *args], env=env, input=stdin, capture_output=True,
                           text=True, timeout=_budget_s(ctx, timeout_s))
    except subprocess.TimeoutExpired:
        if _budget_spent(ctx):
            raise TimeoutError(f"`docker {args[0]}`: the run budget ended first; not graded")
        raise
    assert r.returncode == 0, (
        f"`docker {args[0]}` rc={r.returncode}, expected 0: {(r.stdout + r.stderr)[-1200:]!r}"
    )
    return r.stdout


def _assert_docker_daemon_alive(env) -> None:
    """A dead daemon fails loudly here, not as an opaque non-zero rc minutes into a build."""
    r = subprocess.run(["docker", "info"], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"docker daemon unreachable: {r.stderr.strip()[-400:]!r}"


def _registry_login(ctx, env) -> str:
    """`docker login` to the account's private registry with an ECR authorization token; returns
    the registry host, reached through the target's own published proxyEndpoint."""
    auth = ctx.client("ecr").get_authorization_token()["authorizationData"][0]
    password = base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)[1]
    registry = urlsplit(ctx.endpoint_url(auth["proxyEndpoint"])).netloc
    _docker(ctx, env, ["login", "--username", "AWS", "--password-stdin", registry],
            timeout_s=_LOGIN_TIMEOUT_S, stdin=password)
    return registry


def _repository(ctx) -> dict:
    """A private repository this check owns, force-deleted at cleanup."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-img-")
    repo = ecr.create_repository(repositoryName=name,
                                 tags=[{"Key": "sim2real", "Value": CHECK}])["repository"]
    ctx.on_cleanup(_teardown(lambda: ecr.delete_repository(repositoryName=name, force=True),
                             "RepositoryNotFoundException"))
    return {"name": name, "uri": repo["repositoryUri"]}


def _remove_local_image(env, ref: str) -> None:
    """Remove the local tag this check built; an image that is already gone is fine."""
    r = subprocess.run(["docker", "image", "rm", "-f", ref], env=env, capture_output=True,
                       text=True, timeout=120)
    if r.returncode != 0 and "No such image" not in r.stderr:
        raise RuntimeError(f"`docker image rm {ref}` rc={r.returncode}: {r.stderr[-400:]!r}")


def _build_and_push(ctx, env, context_dir: Path, registry: str, repo_uri: str,
                    tag: str) -> None:
    """`docker build` *context_dir* for linux/amd64, then `docker push` it to *repo_uri*:*tag*
    through the logged-in *registry*."""
    ref = f"{registry}/{repo_uri.split('/', 1)[1]}:{tag}"
    ctx.on_cleanup(lambda: _remove_local_image(env, ref))
    _docker(ctx, env, ["build", "--platform", "linux/amd64", "-t", ref, str(context_dir)],
            timeout_s=_BUILD_TIMEOUT_S)
    _docker(ctx, env, ["push", ref], timeout_s=_PUSH_TIMEOUT_S)


def _pushed_digest(ctx, repo: str, tag: str) -> str:
    """The manifest digest ECR holds under *tag*."""
    detail = ctx.client("ecr").describe_images(
        repositoryName=repo, imageIds=[{"imageTag": tag}])["imageDetails"][0]
    assert tag in detail.get("imageTags", []), (
        f"DescribeImages for tag {tag!r} in {repo!r} returned tags {detail.get('imageTags')!r}"
    )
    return detail["imageDigest"]


def _execution_role(ctx) -> str:
    """A Lambda execution role with no permissions, so the function writes no log group that
    could outlive the check."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-img-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return role["Arn"]


def _image_function(ctx, role_arn: str, image_uri: str, *, name: str | None = None,
                    timeout: int = 30) -> str:
    """A PackageType=Image x86_64 function from *image_uri*, created through the
    role-propagation window and Active; returns its name."""
    lam = ctx.client("lambda")
    name = name or ctx.unique_name("sim2real-img-fn-")
    kwargs = {"FunctionName": name, "PackageType": "Image", "Role": role_arn,
              "Code": {"ImageUri": image_uri}, "Architectures": ["x86_64"],
              "Timeout": timeout, "MemorySize": 512, "Tags": {"sim2real": CHECK}}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    _poll(ctx, create, lambda r: r is not None, timeout_s=90, interval_s=3,
          what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State") in ("Active", "Failed"),
                 timeout_s=_ACTIVE_TIMEOUT_S, interval_s=2, what=f"function {name} leaves Pending")
    assert conf["State"] == "Active", (
        f"function {name} ended {conf['State']!r}: {conf.get('StateReason')!r}")
    return name


def _assert_runs_image(ctx, fn: str, image_uri: str, repo_uri: str, digest: str) -> None:
    """GetFunction reports the configured tag and the digest Lambda resolved it to."""
    code = ctx.client("lambda").get_function(FunctionName=fn)["Code"]
    assert code["ImageUri"] == image_uri, (
        f"function ImageUri is {code['ImageUri']!r}, expected {image_uri!r}")
    assert code["ResolvedImageUri"] == f"{repo_uri}@{digest}", (
        f"function ResolvedImageUri is {code['ResolvedImageUri']!r}, expected "
        f"{repo_uri + '@' + digest!r}")


def _invoke(ctx, fn: str, event) -> dict:
    """The decoded payload of one RequestResponse invoke; asserts it carried no FunctionError."""
    resp = ctx.client("lambda").invoke(FunctionName=fn, InvocationType="RequestResponse",
                                       Payload=json.dumps(event).encode())
    raw = resp["Payload"].read()
    assert "FunctionError" not in resp, (
        f"invoke of {fn!r} returned FunctionError={resp.get('FunctionError')!r}: {raw[:600]!r}")
    return json.loads(raw)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
