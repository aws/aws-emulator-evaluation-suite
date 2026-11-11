"""exec-wrapper-script-starts-the-runtime-with-its-environment-and-arguments."""
from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "exec-wrapper-script-starts-the-runtime-with-its-environment-and-arguments"
GROUP = "extensions_runtime"
SERVICES = ["lambda"]

_WRAPPER = """\
#!/bin/bash
printf '%s\\n' "$@" > /tmp/wrapper-argv
export PROBE_WRAPPED="set-by-wrapper"
exec "$@"
"""

_HANDLER = """\
import json, os, sys

def handler(event, context):
    argv = None
    if os.path.exists("/tmp/wrapper-argv"):
        with open("/tmp/wrapper-argv") as f:
            argv = f.read().splitlines()
    return {"wrapped": os.environ.get("PROBE_WRAPPED"), "argv": argv,
            "executable": sys.executable, "wrapperEnv": os.environ.get("AWS_LAMBDA_EXEC_WRAPPER")}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With AWS_LAMBDA_EXEC_WRAPPER naming a package script, the runtime starts through it: the script
    gets the interpreter path as its first argument and its export reaches the handler; removing
    the variable starts the next environment without the script.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-modify.html#runtime-wrapper
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-wrap-")
    wrapper_path = "/var/task/wrap.sh"
    _function(ctx, FunctionName=fn, Runtime="python3.12", Handler="index.handler",
              Role=_execution_role(ctx), MemorySize=256, Timeout=15,
              Code={"ZipFile": _zip({"index.py": (_HANDLER, 0o644), "wrap.sh": (_WRAPPER, 0o755)})},
              Environment={"Variables": {"AWS_LAMBDA_EXEC_WRAPPER": wrapper_path}})

    r = _invoke(lam, fn, b"{}")
    assert r["error"] is None, f"wrapped invoke failed: {r['error']!r} {r['raw'][:400]!r}"
    body = json.loads(r["raw"])
    assert body["wrapped"] == "set-by-wrapper", (
        f"the wrapper's export is not in the handler's environment: {body['wrapped']!r}")
    argv = body["argv"]
    assert isinstance(argv, list) and len(argv) >= 2, f"wrapper argument record {argv!r}"
    assert argv[0] == body["executable"], (
        f"the wrapper's first argument {argv[0]!r} is not the interpreter the handler runs in "
        f"{body['executable']!r}")
    assert body["wrapperEnv"] == wrapper_path, f"AWS_LAMBDA_EXEC_WRAPPER={body['wrapperEnv']!r}"

    lam.update_function_configuration(FunctionName=fn, Environment={"Variables": {}})
    _wait_active(lam, fn)
    plain = _invoke(lam, fn, b"{}")
    assert plain["error"] is None, f"unwrapped invoke failed: {plain['error']!r}"
    pbody = json.loads(plain["raw"])
    assert (pbody["wrapped"], pbody["argv"], pbody["wrapperEnv"]) == (None, None, None), (
        f"without AWS_LAMBDA_EXEC_WRAPPER the environment still shows the wrapper: {pbody!r}")


def _zip(files: dict) -> bytes:
    """A zip of ``{arcname: (text, mode)}``; the mode lands in the entry's Unix permission bits."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, (text, mode) in files.items():
            info = zipfile.ZipInfo(arc, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, textwrap.dedent(text))
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


def _poll(probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _execution_role(ctx, statements=None) -> str:
    """A Lambda execution role holding exactly ``statements`` and no logs: grant, so no function
    of this check ever creates a log group that could outlive it (LogType=Tail needs none)."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(_teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
            "NoSuchEntity"))
    return arn


def _function(ctx, **kwargs) -> dict:
    """CreateFunction through the role-propagation window, its delete registered, then Active."""
    lam = ctx.client("lambda")
    kwargs.setdefault("Tags", {"sim2real": CHECK})

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    name = kwargs["FunctionName"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _wait_active(lam, name)
    return out


def _wait_active(lam, name, qualifier=None) -> dict:
    args = {"FunctionName": name}
    if qualifier:
        args["Qualifier"] = qualifier
    conf = _poll(lambda: lam.get_function_configuration(**args),
                 lambda c: c.get("State", "Active") in ("Active", "Failed")
                 and c.get("LastUpdateStatus", "Successful") != "InProgress",
                 timeout_s=300, interval_s=2, what=f"function {name} settles")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return conf


def _invoke(lam, name, payload: bytes, qualifier=None) -> dict:
    """One RequestResponse invoke with the log tail: status, error flag, raw payload, request id."""
    args = {"FunctionName": name, "InvocationType": "RequestResponse", "LogType": "Tail",
            "Payload": payload}
    if qualifier:
        args["Qualifier"] = qualifier
    resp = lam.invoke(**args)
    return {"status": resp["StatusCode"], "error": resp.get("FunctionError"),
            "raw": resp["Payload"].read(),
            "log": base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace"),
            "request_id": resp["ResponseMetadata"]["RequestId"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
