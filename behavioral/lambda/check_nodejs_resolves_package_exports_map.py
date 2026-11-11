"""nodejs-resolves-package-exports-map."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs-resolves-package-exports-map"
GROUP = "nodejs-modules"
SERVICES = ['lambda']


_RUNTIME = "nodejs22.x"
_FILES = {
    "index.js": """\
exports.handler = async () => {
  const cjs = require("expkg");
  const sub = require("expkg/sub");
  const esm = await import("expkg");
  let hidden;
  try {
    require("expkg/lib/hidden.js");
    hidden = { loaded: true };
  } catch (e) {
    hidden = { loaded: false, name: e.name, code: e.code, message: e.message };
  }
  return { cjs: cjs.id, sub: sub.id, esm: esm.id, hidden };
};
""",
    "node_modules/expkg/package.json": """\
{
  "name": "expkg",
  "version": "1.0.0",
  "main": "./lib/legacy-main.js",
  "exports": {
    ".": { "import": "./lib/entry-esm.mjs", "require": "./lib/entry-cjs.js" },
    "./sub": "./lib/subpath-impl.js"
  }
}
""",
    "node_modules/expkg/lib/entry-cjs.js": 'module.exports = { id: "entry-cjs" };\n',
    "node_modules/expkg/lib/entry-esm.mjs": 'export const id = "entry-esm";\n',
    "node_modules/expkg/lib/subpath-impl.js": 'module.exports = { id: "subpath-impl" };\n',
    "node_modules/expkg/lib/legacy-main.js": 'module.exports = { id: "legacy-main" };\n',
    "node_modules/expkg/lib/hidden.js": 'module.exports = { id: "hidden" };\n',
}



@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A bundled package's "exports" map decides what require and import resolve: "." picks the
    require or import condition over "main", "./sub" maps to its target file, and a file the map
    does not export is refused with ERR_PACKAGE_PATH_NOT_EXPORTED.

    Reference: https://nodejs.org/docs/latest-v22.x/api/packages.html#package-entry-points
    """
    role = _execution_role(ctx, [])
    fn = _function(ctx, role["arn"], _FILES)
    out = _invoke_ok(ctx, fn["name"])
    assert out["cjs"] == "entry-cjs", f"require('expkg') loaded {out['cjs']!r}, expected the require condition"
    assert out["esm"] == "entry-esm", f"import('expkg') loaded {out['esm']!r}, expected the import condition"
    assert out["sub"] == "subpath-impl", f"require('expkg/sub') loaded {out['sub']!r}"
    hidden = out["hidden"]
    assert hidden.get("loaded") is False, f"an unexported subpath loaded: {hidden!r}"
    assert hidden.get("code") == "ERR_PACKAGE_PATH_NOT_EXPORTED", (
        f"an unexported subpath was refused with {hidden!r}, expected ERR_PACKAGE_PATH_NOT_EXPORTED")



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


def _execution_role(ctx, statements) -> dict:
    """A Lambda execution role holding exactly ``statements`` and no logs: grant, so the function
    never creates a log group that could outlive the check."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(_teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
            "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"], "id": role["RoleId"]}


def _function(ctx, role_arn, code, *, timeout=60) -> dict:
    """A function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": _RUNTIME, "Handler": "index.handler",
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
