"""image-function-url-aws-iam-signed-served-unsigned-forbidden-delete-stops-resolving."""

from __future__ import annotations

import json
import os
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-function-url-aws-iam-signed-served-unsigned-forbidden-delete-stops-resolving"
GROUP = "function_url"
SERVICES = ["ecr", "iam", "lambda", "logs"]

#: AWS's Lambda Python 3.12 base image, pinned by the digest of its multi-arch index.
_BASE_IMAGE = "public.ecr.aws/lambda/python:3.12@sha256:238f6bfd2c1c188aff3955c2f7ceb767fe9da1b3597d84264426a11690fcf2d7"
_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"

_HANDLER_SOURCE = """import json


def handler(event, context):
    return {{
        "statusCode": 200,
        "headers": {{"content-type": "application/json"}},
        "body": json.dumps({{"marker": "{marker}"}}),
    }}
"""

_URL_GONE = ("ResourceNotFoundException", "The resource you requested does not exist.")


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


def _teardown(undo, *not_found: str):
    """Run ``undo()``; only the resource's own not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 4.0,
                    budget_s: float = 60.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent; raise if not."""
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
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry on an observable condition. Raises on timeout, never returns a stale value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _run(ctx, argv, *, timeout_s: float, description: str, input_text: str | None = None):
    """One subprocess call with the check's own AWS identity and an isolated HOME/DOCKER_CONFIG."""
    ctx.verify_account_safety()
    result = subprocess.run(
        argv, env=ctx.subprocess_env(), input=input_text, capture_output=True, text=True,
        timeout=timeout_s,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"{description} failed (rc={result.returncode}): {result.stderr[-500:]}"
        )
    return result


def _base_image_digest_ref(ctx) -> str:
    """Pull the pinned AWS Lambda Python base image once and return its digest-pinned reference."""
    _run(ctx, ["docker", "pull", _BASE_IMAGE], timeout_s=180, description="pulling the Lambda base image")
    return _BASE_IMAGE


def _write_build_context(base_ref: str, marker: str) -> str:
    """A build directory with only a Dockerfile and the handler the check writes; no installs."""
    build_dir = tempfile.mkdtemp(prefix="sim2real-image-url-")
    with open(os.path.join(build_dir, "handler.py"), "w", encoding="utf-8") as fh:
        fh.write(_HANDLER_SOURCE.format(marker=marker))
    with open(os.path.join(build_dir, "Dockerfile"), "w", encoding="utf-8") as fh:
        fh.write(
            f"FROM {base_ref}\n"
            "COPY handler.py ${LAMBDA_TASK_ROOT}\n"
            'CMD ["handler.handler"]\n'
        )
    return build_dir


def _create_repo(ctx, ecr) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-img-url-")
    repo = ecr.create_repository(
        repositoryName=name,
        imageScanningConfiguration={"scanOnPush": False},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )["repository"]
    ctx.on_cleanup(
        _teardown(lambda: ecr.delete_repository(repositoryName=name, force=True),
                 "RepositoryNotFoundException")
    )
    return repo["repositoryName"], repo["repositoryUri"]


def _build_and_push(ctx, repo_uri: str, tag: str, build_dir: str) -> str:
    image_ref = f"{repo_uri}:{tag}"
    _run(
        ctx, ["docker", "build", "--provenance=false", "--sbom=false", "-t", image_ref, build_dir],
        timeout_s=300, description="building the function's image",
    )
    registry = repo_uri.split("/", 1)[0]
    token = _run(
        ctx, ["aws", "ecr", "get-login-password", "--region", ctx.region],
        timeout_s=30, description="fetching an ECR authorization token",
    ).stdout
    login = subprocess.run(
        ["docker", "login", "--username", "AWS", "--password-stdin", registry],
        env=ctx.subprocess_env(), input=token, capture_output=True, text=True, timeout=30,
    )
    assert login.returncode == 0, f"docker login to {registry} failed: {login.stderr[-300:]}"
    _run(ctx, ["docker", "push", image_ref], timeout_s=300, description="pushing the function's image")
    return image_ref


def _create_exec_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-behav-img-url-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(
        _teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY),
                 "NoSuchEntity")
    )
    return arn


def _create_image_function(ctx, lam, logs, *, name: str, role_arn: str, image_uri: str) -> None:
    """CreateFunction, retrying only the role-propagation refusal; torn down function-then-logs."""
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 90.0
    while True:
        try:
            lam.create_function(
                FunctionName=name, PackageType="Image", Role=role_arn,
                Code={"ImageUri": image_uri}, MemorySize=128, Timeout=10,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidParameterValueException" or _ROLE_PROPAGATION not in err.get(
                "Message", ""
            ):
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"CreateFunction kept failing on role propagation: {err}")
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_function_until_gone(lam, name))


def _delete_function_until_gone(lam, name: str, *, timeout_s: float = 120.0) -> None:
    """DeleteFunction, then wait until it is truly absent so a later repository delete is safe."""
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            lam.get_function(FunctionName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2.0)
    raise AssertionError(f"function {name} still visible {timeout_s}s after DeleteFunction")


def _wait_active(lam, name: str, *, timeout_s: float = 240.0) -> None:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(f"{name} entered State=Failed: {cfg.get('StateReason')!r}")
        return cfg

    _poll_until(_probe, lambda cfg: cfg.get("State") == "Active", timeout_s=timeout_s,
               interval_s=2.0, description=f"{name} reaching State=Active")


def _create_url(ctx, lam, fn: str) -> str:
    cfg = lam.create_function_url_config(FunctionName=fn, AuthType="AWS_IAM")
    ctx.on_cleanup(
        _teardown(lambda: lam.delete_function_url_config(FunctionName=fn), "ResourceNotFoundException")
    )
    assert not (problem := ctx.published_url_mismatch(cfg["FunctionUrl"])), problem
    return cfg["FunctionUrl"]


def _ssl_context(ctx) -> ssl.SSLContext:
    verify = ctx.http_verify
    if verify is False:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if isinstance(verify, str) and verify:
        return ssl.create_default_context(cafile=verify)
    return ssl.create_default_context()


def _signed_headers(ctx, url: str) -> dict:
    """SigV4 headers for a GET to ``url``, signed with THIS check's credentials."""
    env = ctx.subprocess_env()
    akid, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
    assert akid and secret, "ctx.subprocess_env() carried no credentials to sign with"
    creds = Credentials(akid, secret, env.get("AWS_SESSION_TOKEN"))
    request = AWSRequest(method="GET", url=url)
    SigV4Auth(creds, "lambda", ctx.region).add_auth(request)
    return dict(request.headers.items())


def _get(ctx, url: str, *, signed: bool, timeout_s: float = 40.0):
    """One raw HTTPS GET against the published function URL. Never raises on 4xx; a transport
    error is returned as status None with the error as the body, for a poll to retry."""
    headers = _signed_headers(ctx, url) if signed else {}
    target, route = ctx.endpoint_route(url)
    request = urllib.request.Request(target, method="GET", headers={**headers, **route})
    try:
        response = urllib.request.urlopen(request, timeout=timeout_s, context=_ssl_context(ctx))
    except urllib.error.HTTPError as exc:
        response = exc
    except (urllib.error.URLError, OSError) as exc:
        return None, {}, repr(exc).encode()
    with response:
        body = response.read()
    status = response.status if hasattr(response, "status") else response.code
    return status, {k.lower(): v for k, v in response.headers.items()}, body


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """A container-image function's AWS_IAM function URL serves a SigV4-signed GET with the
    handler's exact body, refuses an unsigned GET with the IAM authorizer's exact Forbidden body,
    and settles on the deleted-config refusal once DeleteFunctionUrlConfig runs.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/images-create.html
    """
    from fidelity_tests_runner import require_tools

    require_tools("docker", "aws")
    daemon = _run(ctx, ["docker", "info"], timeout_s=30, description="checking the docker daemon")
    assert daemon.returncode == 0, f"the docker daemon is unreachable: {daemon.stderr[-300:]}"

    ecr = ctx.client("ecr")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    base_ref = _base_image_digest_ref(ctx)
    marker = ctx.unique_name("sim2real-url-marker-")
    build_dir = _write_build_context(base_ref, marker)
    try:
        _, repo_uri = _create_repo(ctx, ecr)
        image_ref = _build_and_push(ctx, repo_uri, "v1", build_dir)
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)

    role_arn = _create_exec_role(ctx, iam)
    fn = ctx.unique_name("sim2real-behav-img-url-")
    _create_image_function(ctx, lam, logs, name=fn, role_arn=role_arn, image_uri=image_ref)
    _wait_active(lam, fn)

    url = _create_url(ctx, lam, fn)

    unsigned_status, unsigned_headers, unsigned_body = _poll_until(
        lambda: _get(ctx, url, signed=False), lambda obs: obs[0] is not None,
        timeout_s=60.0, interval_s=3.0, description="the unsigned GET reaching the function URL",
    )
    assert unsigned_status == 403, f"an unsigned GET must be refused 403, got {unsigned_status}"
    assert unsigned_headers.get("x-amzn-errortype") == "AccessDeniedException", unsigned_headers
    assert json.loads(unsigned_body) == {"Message": "Forbidden"}, (
        f"the AWS_IAM authorizer's refusal body must be {{'Message': 'Forbidden'}}, "
        f"got {unsigned_body!r}"
    )

    served_status, _served_headers, served_body = _poll_until(
        lambda: _get(ctx, url, signed=True), lambda obs: obs[0] == 200,
        timeout_s=120.0, interval_s=3.0, description="the signed GET reaching the handler",
    )
    assert served_status == 200, f"the signed GET must be served 200, got {served_status}"
    assert json.loads(served_body) == {"marker": marker}, (
        f"the signed GET must return the handler's exact body, got {served_body!r}"
    )

    lam.delete_function_url_config(FunctionName=fn)
    streak = {"n": 0}

    def _probe():
        obs = _get(ctx, url, signed=True)
        streak["n"] = streak["n"] + 1 if obs[0] == 403 else 0
        return obs

    _gone_status, gone_headers, gone_body = _poll_until(
        _probe, lambda obs: streak["n"] >= 5, timeout_s=180.0, interval_s=2.0,
        description="five consecutive refusals after DeleteFunctionUrlConfig",
    )
    assert gone_headers.get("x-amzn-errortype") == "AccessDeniedException", gone_headers
    assert json.loads(gone_body) == {"Message": None}, (
        f"a deleted function URL must answer {{'Message': None}}, got {gone_body!r}"
    )
    assert marker.encode() not in gone_body, (
        f"the handler must not have run after the URL config was deleted: {gone_body!r}"
    )
    expect_error(lambda: lam.get_function_url_config(FunctionName=fn), *_URL_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
