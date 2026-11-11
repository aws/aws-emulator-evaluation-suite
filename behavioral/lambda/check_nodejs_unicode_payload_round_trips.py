"""nodejs-unicode-payload-round-trips."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "nodejs-unicode-payload-round-trips"
GROUP = 'nodejs-handler'
SERVICES = ['lambda']


_HANDLER = r"""
exports.handler = async (event) => ({
  echo: event.s,
  utf16Length: event.s.length,
  codePoints: [...event.s].length,
  utf8Bytes: Buffer.byteLength(event.s, 'utf8'),
  made: String.fromCodePoint(0xe9, 0x4e2d, 0x1f600),
  lone: String.fromCharCode(0xd800),
});
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
    """Non-ASCII text crosses a Node.js function intact both ways: the handler sees the UTF-16 length,
    code-point count and UTF-8 byte length of the event string, built characters (an astral emoji
    too) return as the same code points, and a lone surrogate is emitted as the escape \\ud800.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html
    """
    lam = ctx.client("lambda")
    fn = _deploy(ctx, lam, _exec_role(ctx), {"index.js": _HANDLER})
    s = "café-中文-\U0001F600-" + ctx.unique_name("u-")

    err, raw = _invoke(lam, fn, {"s": s})
    assert err is None, f"FunctionError={err!r}, payload {raw!r}"
    assert b"\\ud800" in raw, f"the lone surrogate must be serialized as the escape \\ud800, raw payload {raw!r}"
    got = json.loads(raw)
    assert got["echo"] == s, f"echo {got['echo']!r} != sent {s!r}"
    assert got["utf16Length"] == len(s.encode("utf-16-le")) // 2, f"utf16Length {got['utf16Length']!r}"
    assert got["codePoints"] == len(s), f"codePoints {got['codePoints']!r}, expected {len(s)}"
    assert got["utf8Bytes"] == len(s.encode("utf-8")), f"utf8Bytes {got['utf8Bytes']!r}"
    assert got["made"] == "é中\U0001F600", f"constructed string came back as {got['made']!r}"
    assert got["lone"] == "\ud800", f"lone surrogate came back as {got['lone']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
