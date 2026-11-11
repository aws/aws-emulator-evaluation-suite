"""nodejs-context-object-describes-the-invocation."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "nodejs-context-object-describes-the-invocation"
GROUP = 'nodejs-context'
SERVICES = ['lambda']


_HANDLER = r"""
exports.handler = async (event, context) => {
  const before = context.getRemainingTimeInMillis();
  await new Promise((resolve) => setTimeout(resolve, 250));
  const after = context.getRemainingTimeInMillis();
  return {
    functionName: context.functionName,
    functionVersion: context.functionVersion,
    invokedFunctionArn: context.invokedFunctionArn,
    memoryLimitInMB: context.memoryLimitInMB,
    awsRequestId: context.awsRequestId,
    logGroupName: context.logGroupName,
    logStreamName: context.logStreamName,
    callbackWaitsForEmptyEventLoop: context.callbackWaitsForEmptyEventLoop,
    before, after,
  };
};
"""
# ===== helpers =====
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


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


def _exec_role(ctx) -> str:
    """This check's own execution role. It carries no policy, so the function cannot write a log
    group: nothing outlives the function's delete."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _deploy(ctx, lam, role: str, files: dict, *, runtime: str = "nodejs22.x",
            handler: str = "index.handler", env: dict | None = None, timeout: int = 10) -> str:
    """Create a function from inline ``files``, wait for Active, and register its delete."""
    name = ctx.unique_name("sim2real-behav-fn-")
    kwargs = dict(
        FunctionName=name, Runtime=runtime, Handler=handler, Role=role,
        Code={"ZipFile": _zip(files)}, MemorySize=128, Timeout=timeout,
        Tags={"sim2real": CHECK},
    )
    if env is not None:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "InvalidParameterValueException"
                           and err.get("Message") == _ROLE_NOT_READY)
            if not propagating or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    deadline = time.monotonic() + 90
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} entered State=Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active":
            return name
        assert time.monotonic() < deadline, f"{name} not Active within 90s; last {cfg['State']!r}"
        time.sleep(1)


def _invoke(lam, name: str, payload) -> tuple:
    """RequestResponse invoke: ``(FunctionError or None, raw payload bytes)``; HTTP 200 asserted."""
    resp = lam.invoke(FunctionName=name, InvocationType="RequestResponse",
                      Payload=json.dumps(payload).encode())
    assert resp["StatusCode"] == 200, f"Invoke {name}: StatusCode {resp['StatusCode']!r}, expected 200"
    return resp.get("FunctionError"), resp["Payload"].read()


def _ok(lam, name: str, payload):
    """Invoke and return the decoded result, failing on any FunctionError."""
    err, raw = _invoke(lam, name, payload)
    assert err is None, f"Invoke {name}: FunctionError={err!r}, payload {raw[:600]!r}"
    return json.loads(raw)


def _unhandled(lam, name: str, payload) -> dict:
    """Invoke and return the error envelope, requiring FunctionError=Unhandled."""
    err, raw = _invoke(lam, name, payload)
    assert err == "Unhandled", f"Invoke {name}: FunctionError={err!r}, expected 'Unhandled'; payload {raw[:600]!r}"
    body = json.loads(raw)
    assert isinstance(body, dict), f"Invoke {name}: error payload {body!r} is not an object"
    return body


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The Node.js context carries functionName, functionVersion and invokedFunctionArn per qualifier,
    memoryLimitInMB "128", awsRequestId equal to the Invoke request id, logGroupName and stream, and
    getRemainingTimeInMillis counting down within the configured timeout.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-context.html
    """
    import re

    lam = ctx.client("lambda")
    fn = _deploy(ctx, lam, _exec_role(ctx), {"index.js": _HANDLER}, timeout=7)
    cfg = lam.get_function_configuration(FunctionName=fn)
    base_arn = cfg["FunctionArn"]
    version = lam.publish_version(FunctionName=fn)["Version"]
    assert version == "1", f"the first published version was {version!r}, expected '1'"

    for qualifier, want_version, want_arn in ((None, "$LATEST", base_arn),
                                              ("1", "1", f"{base_arn}:1")):
        kwargs = {"FunctionName": fn, "Payload": b"{}"}
        if qualifier:
            kwargs["Qualifier"] = qualifier
        resp = lam.invoke(**kwargs)
        assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
            f"qualifier={qualifier!r}: invoke failed {resp.get('FunctionError')!r}"
        )
        c = json.loads(resp["Payload"].read())
        assert c["functionName"] == fn, f"qualifier={qualifier!r}: functionName {c['functionName']!r}"
        assert c["functionVersion"] == want_version, (
            f"qualifier={qualifier!r}: functionVersion {c['functionVersion']!r}, expected {want_version!r}"
        )
        assert c["invokedFunctionArn"] == want_arn, (
            f"qualifier={qualifier!r}: invokedFunctionArn {c['invokedFunctionArn']!r}, expected {want_arn!r}"
        )
        assert c["memoryLimitInMB"] == "128", f"memoryLimitInMB {c['memoryLimitInMB']!r}, expected '128'"
        assert c["awsRequestId"] == resp["ResponseMetadata"]["RequestId"], (
            f"awsRequestId {c['awsRequestId']!r} is not the Invoke request id "
            f"{resp['ResponseMetadata']['RequestId']!r}"
        )
        assert c["logGroupName"] == f"/aws/lambda/{fn}", f"logGroupName {c['logGroupName']!r}"
        assert re.fullmatch(r"\d{4}/\d{2}/\d{2}/\[" + re.escape(want_version) + r"\][0-9a-f]{32}",
                            c["logStreamName"]), f"logStreamName {c['logStreamName']!r}"
        assert c["callbackWaitsForEmptyEventLoop"] is True, (
            f"callbackWaitsForEmptyEventLoop defaults to true, got {c['callbackWaitsForEmptyEventLoop']!r}"
        )
        assert 0 < c["after"] < c["before"] <= 7000, (
            f"remaining time must count down within the 7 s timeout: before={c['before']!r}, after={c['after']!r}"
        )
        assert c["before"] - c["after"] >= 200, (
            f"remaining time fell by {c['before'] - c['after']} ms across a 250 ms wait"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
