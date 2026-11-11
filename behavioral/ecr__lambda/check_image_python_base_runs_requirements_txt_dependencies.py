"""image-python-base-runs-requirements-txt-dependencies."""
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

CHECK = "image-python-base-runs-requirements-txt-dependencies"
GROUP = "container-image"
SERVICES = ["ecr", "lambda"]

_BUILD_TIMEOUT_S = 900.0
_PUSH_TIMEOUT_S = 600.0
_LOGIN_TIMEOUT_S = 120.0
_ACTIVE_TIMEOUT_S = 300.0

# The base image is pinned by tag and by its multi-platform index digest; `--platform
# linux/amd64` selects the index's amd64 child. Every wheel is pinned by the sha256 PyPI
# publishes, so pip runs in hash-checking mode and installs nothing else.
_DOCKERFILE = """\
FROM public.ecr.aws/lambda/python:3.12@sha256:238f6bfd2c1c188aff3955c2f7ceb767fe9da1b3597d84264426a11690fcf2d7
COPY requirements.txt ${LAMBDA_TASK_ROOT}/
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt --target "${LAMBDA_TASK_ROOT}"
COPY app.py ${LAMBDA_TASK_ROOT}/
CMD ["app.handler"]
"""

_REQUIREMENTS = """\
requests==2.32.3 \\
    --hash=sha256:70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6
certifi==2024.8.30 \\
    --hash=sha256:922820b53db7a7257ffbda3f597266d435245903d80737e34f8a45ff3e3230d8
charset-normalizer==3.4.0 \\
    --hash=sha256:8cda06946eac330cbe6598f77bb54e690b4ca93f593dee1568ad22b04f347c15 \\
    --hash=sha256:fe9f97feb71aa9896b81973a7bbada8c49501dc73e58a10fcef6663af95e5079
idna==3.10 \\
    --hash=sha256:946d195a0d259cbba61165e88e65941f16e9b36ea6ddb97f00452bae8b1287d3
urllib3==2.2.3 \\
    --hash=sha256:ca899ca043dcb1bafa3e262d73aa25c465bfb49e0bd9dd5d59f1d0acba2f8fac
orjson==3.10.7 \\
    --hash=sha256:a0c6a008e91d10a2564edbb6ee5069a9e66df3fbe11c9a005cb411f441fd2c09
"""

_HANDLER = """\
import platform
import sys


def handler(event, context):
    try:
        import orjson
        import requests

        return {
            "requests_version": requests.__version__,
            "requests_file": requests.__file__,
            "orjson_version": orjson.__version__,
            "orjson_dumps": orjson.dumps(event["doc"], option=orjson.OPT_SORT_KEYS).decode(),
            "python": list(sys.version_info[:2]),
            "implementation": platform.python_implementation(),
        }
    except Exception as exc:
        return {"error": type(exc).__name__, "message": str(exc)}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:representation", "dp:native", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function built FROM the Lambda Python 3.12 base image, with requirements.txt installed
    into LAMBDA_TASK_ROOT, imports those exact package versions at invoke time.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/python-image.html
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
    (image_dir / "requirements.txt").write_text(_REQUIREMENTS)
    (image_dir / "app.py").write_text(_HANDLER)
    image_uri = f"{repo['uri']}:v1"
    _build_and_push(ctx, env, image_dir, registry, repo["uri"], "v1")
    digest = _pushed_digest(ctx, repo["name"], "v1")

    fn = _image_function(ctx, role_arn, image_uri)
    _assert_runs_image(ctx, fn, image_uri, repo["uri"], digest)

    doc = {"b": 1, "a": [1, 2, "\u00e9"], "n": None}
    out = _invoke(ctx, fn, {"doc": doc})
    assert "error" not in out, f"handler raised: {out!r}"
    assert out["requests_version"] == "2.32.3", (
        f"requests.__version__ is {out['requests_version']!r}, expected '2.32.3'")
    assert out["requests_file"] == "/var/task/requests/__init__.py", (
        f"requests imported from {out['requests_file']!r}, expected the copy pip installed "
        f"into LAMBDA_TASK_ROOT, '/var/task/requests/__init__.py'")
    assert out["orjson_version"] == "3.10.7", (
        f"orjson.__version__ is {out['orjson_version']!r}, expected '3.10.7'")
    expected = '{"a":[1,2,"\u00e9"],"b":1,"n":null}'
    assert out["orjson_dumps"] == expected, (
        f"orjson.dumps(OPT_SORT_KEYS) returned {out['orjson_dumps']!r}, expected {expected!r}")
    assert out["python"] == [3, 12], f"sys.version_info[:2] is {out['python']!r}, expected [3, 12]"
    assert out["implementation"] == "CPython", (
        f"platform.python_implementation() is {out['implementation']!r}, expected 'CPython'")


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
