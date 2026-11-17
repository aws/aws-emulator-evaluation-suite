"""nodejs-webassembly-bad-magic-number-rejected."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs-webassembly-bad-magic-number-rejected"
GROUP = "nodejs-environment"
SERVICES = ['lambda']


# A minimal WebAssembly module exporting add(i32, i32) -> i32: local.get 0; local.get 1; i32.add.
_WASM_ADD_B64 = "AGFzbQEAAAABBwFgAn9/AX8DAgEABwcBA2FkZAAACgkBBwAgACABags="
# The same bytes with the 4-byte magic number zeroed out, so decoding fails before any section.
_WASM_BAD_MAGIC_B64 = "AAAAAAEAAAABBwFgAn9/AX8DAgEABwcBA2FkZAAACgkBBwAgACABags="

_GOOD_FILES = {"index.js": f"""\
exports.handler = async () => {{
  const bytes = Buffer.from("{_WASM_ADD_B64}", "base64");
  const {{ instance }} = await WebAssembly.instantiate(bytes);
  return {{ sum: instance.exports.add(2, 3) }};
}};
"""}
_BAD_FILES = {"index.js": f"""\
exports.handler = async () => {{
  const bytes = Buffer.from("{_WASM_BAD_MAGIC_B64}", "base64");
  await WebAssembly.instantiate(bytes);
  return {{ reached: true }};
}};
"""}


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Node.js handler that instantiates a WebAssembly module whose magic number was
    overwritten with zero bytes throws a CompileError, and Invoke reports it as an unhandled
    function error while a function given the unmodified module still computes correctly.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-exceptions.html
    """
    role = _execution_role(ctx)

    bad_fn = _function(ctx, role["arn"], _BAD_FILES)
    err, payload = _invoke(ctx, bad_fn["name"])
    assert err == "Unhandled", f"expected FunctionError 'Unhandled', got {err!r}: {payload!r}"
    assert payload["errorType"] == "CompileError", (
        f"expected errorType 'CompileError', got {payload.get('errorType')!r}: {payload!r}"
    )
    assert payload["errorMessage"] == (
        "WebAssembly.instantiate(): expected magic word 00 61 73 6d, found 00 00 00 00 @+0"
    ), f"unexpected errorMessage {payload.get('errorMessage')!r}"

    good_fn = _function(ctx, role["arn"], _GOOD_FILES)
    out = _invoke_ok(ctx, good_fn["name"])
    assert out == {"sum": 5}, f"the unmodified module returned {out!r}, expected {{'sum': 5}}"


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
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _zip(files: dict) -> bytes:
    """A deployment package holding ``files`` (archive path -> source text)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, text in sorted(files.items()):
            zf.writestr(path, textwrap.dedent(text))
    return buf.getvalue()


def _execution_role(ctx) -> dict:
    """A Lambda execution role with no permissions, so the function never creates a log group."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"]}


def _function(ctx, role_arn, code, *, timeout=30) -> dict:
    """A function from ``code`` under nodejs22.x, created through role-propagation and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    kwargs = {"FunctionName": name, "Runtime": "nodejs22.x", "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code)}, "Timeout": timeout,
              "MemorySize": 256, "Tags": {"sim2real": CHECK}}

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
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"),
                 timeout_s=90, interval_s=1, what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _invoke(ctx, fn, event=None) -> tuple:
    """(FunctionError or None, decoded payload) of one RequestResponse invoke of ``event``."""
    resp = ctx.client("lambda").invoke(FunctionName=fn, InvocationType="RequestResponse",
                                       Payload=json.dumps(event or {}).encode())
    raw = resp["Payload"].read()
    return resp.get("FunctionError"), (json.loads(raw) if raw else None)


def _invoke_ok(ctx, fn, event=None) -> dict:
    """The payload of one invoke that must not report a FunctionError."""
    err, out = _invoke(ctx, fn, event)
    assert err is None, f"the function failed: {err!r} {out!r}"
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
