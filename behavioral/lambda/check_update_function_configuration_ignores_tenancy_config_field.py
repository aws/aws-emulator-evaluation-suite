"""update-function-configuration-ignores-tenancy-config-field."""
from __future__ import annotations

import io
import json
import ssl
import time
import urllib.error
import urllib.request
import zipfile

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-function-configuration-ignores-tenancy-config-field"
GROUP = "tenant-isolation"
SERVICES = ["lambda"]

_HANDLER = """\
def handler(event, context):
    return {"ok": True}
"""

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


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


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 2.0,
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


def _role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-tcy-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_settled(ctx, lam, fn: str, timeout_s: float = 120.0) -> dict:
    """Poll to the terminal state: ``State`` Active and ``LastUpdateStatus`` no longer InProgress."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed" or last.get("LastUpdateStatus") == "Failed":
            raise AssertionError(f"{fn} failed: {last.get('StateReason')!r} "
                                 f"{last.get('LastUpdateStatusReason')!r}")
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(2.0)
    raise TimeoutError(f"{fn} never settled to Active/Successful in {timeout_s:.0f}s; last={last!r}")


def _create(ctx, lam, role: str) -> str:
    fn = ctx.unique_name("sim2real-behav-tcy-")
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    deadline = time.monotonic() + _budget_s(ctx, 90)
    while True:
        try:
            lam.create_function(
                FunctionName=fn, Role=role, Runtime="python3.13", Handler="index.handler",
                Code={"ZipFile": _zip({"index.py": _HANDLER})}, Timeout=10, MemorySize=128,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            if "cannot be assumed" not in exc.response["Error"].get("Message", ""):
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(f"the execution role was never assumable: {exc}") from exc
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn),
                             "ResourceNotFoundException"))
    _wait_settled(ctx, lam, fn)
    return fn


def _raw_update(ctx, lam, fn: str, body: dict) -> tuple[int, dict]:
    """A hand-built, SigV4-signed PUT to UpdateFunctionConfiguration carrying ``body`` verbatim,
    including a field the operation's model does not declare — the SDK would refuse to send it."""
    env = ctx.subprocess_env()
    akid, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
    assert akid and secret, "ctx.subprocess_env() carried no credentials to sign with"
    token = env.get("AWS_SESSION_TOKEN")

    endpoint = lam.meta.endpoint_url
    url = f"{endpoint}/2015-03-31/functions/{fn}/configuration"
    payload = json.dumps(body).encode()
    req = AWSRequest(method="PUT", url=url, data=payload,
                      headers={"Content-Type": "application/json"})
    SigV4Auth(Credentials(akid, secret, token), "lambda", ctx.region).add_auth(req)

    http_req = urllib.request.Request(url, data=payload, method="PUT",
                                       headers=dict(req.headers.items()))
    try:
        with urllib.request.urlopen(  # noqa: S310 - the URL is the Lambda endpoint ctx's client uses
                http_req, timeout=30, context=_ssl_context(ctx.http_verify)) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def _ssl_context(verify) -> ssl.SSLContext:
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFunctionConfiguration ignores a TenancyConfig member: a signed request naming it is
    accepted and its modeled Timeout takes effect, while a function created without TenancyConfig
    still reports none.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-tenancyconfig.html
    """
    lam = ctx.client("lambda")
    fn = _create(ctx, lam, _role(ctx))

    before = lam.get_function_configuration(FunctionName=fn)
    assert before.get("TenancyConfig") is None, (
        f"precondition: a plain function must carry no TenancyConfig, got {before.get('TenancyConfig')!r}"
    )
    new_timeout = before["Timeout"] + 7

    status, body = _raw_update(
        ctx, lam, fn, {"Timeout": new_timeout, "TenancyConfig": {"TenantIsolationMode": "PER_TENANT"}}
    )
    assert status == 200, f"the signed update request must be accepted, got HTTP {status}: {body!r}"
    assert body.get("TenancyConfig") is None, (
        f"UpdateFunctionConfiguration's own response must still carry no TenancyConfig, "
        f"got {body.get('TenancyConfig')!r} after naming it in the request body"
    )
    assert body.get("Timeout") == new_timeout, (
        f"the request's modeled Timeout field must take effect; response carried "
        f"{body.get('Timeout')!r}, expected {new_timeout!r}"
    )

    after = _wait_settled(ctx, lam, fn)
    assert after.get("TenancyConfig") is None, (
        f"after the update settled, GetFunctionConfiguration TenancyConfig was "
        f"{after.get('TenancyConfig')!r}, expected it to remain unset"
    )
    assert after["Timeout"] == new_timeout, (
        f"after the update settled, Timeout was {after['Timeout']!r}, expected {new_timeout!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
