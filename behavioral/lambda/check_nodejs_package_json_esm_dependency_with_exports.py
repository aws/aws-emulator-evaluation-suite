"""nodejs-package-json-esm-dependency-with-exports."""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "nodejs-package-json-esm-dependency-with-exports"
GROUP = "packaging"
SERVICES = ["lambda"]

_RUNTIME = "nodejs22.x"
_PACKAGE_FIELDS = {"type": "module"}
_DEPENDENCIES = {"uuid": "10.0.0"}
_HANDLER = """\
import { v4, validate, version } from 'uuid';

export const handler = async () => {
  const id = v4();
  return { id, valid: validate(id), version: version(id), resolved: import.meta.resolve('uuid') };
};
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A nodejs22.x package whose package.json is `type: module` imports an npm-installed
    dependency by its exports map: `import { v4, validate, version } from 'uuid'` binds the
    node/import entry, and a fresh v4 id validates as version 4.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-package.html
    """
    require_tools("npm", "node")
    package = _npm_package(ctx, {"index.js": _HANDLER})
    role = _execution_role(ctx)
    fn = _function(ctx, role["arn"], package)

    out = _invoke(ctx, fn["name"])
    assert out["resolved"] == "file:///var/task/node_modules/uuid/wrapper.mjs", (
        f"import.meta.resolve('uuid') is {out['resolved']!r}, not its exports' node import")
    assert out["valid"] is True, f"validate(v4()) is {out['valid']!r} for id {out['id']!r}"
    assert out["version"] == 4, f"version(v4()) is {out['version']!r} for id {out['id']!r}"


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


def _execution_role(ctx) -> dict:
    """A Lambda execution role with no policy at all, so the function never creates a log group
    that could outlive the check."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-pkg-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"]}


def _function(ctx, role_arn, package: bytes) -> dict:
    """An x86_64 function from the zip ``package``, created through the role-propagation window
    and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-pkg-fn-")
    kwargs = {"FunctionName": name, "Runtime": _RUNTIME, "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": package}, "Architectures": ["x86_64"],
              "Timeout": 30, "MemorySize": 512, "Tags": {"sim2real": CHECK}}

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


def _invoke(ctx, fn, event=None) -> dict:
    """The decoded payload of one RequestResponse invoke; a function error fails the check."""
    resp = ctx.client("lambda").invoke(FunctionName=fn, InvocationType="RequestResponse",
                                       Payload=json.dumps(event or {}).encode())
    raw = resp["Payload"].read()
    out = json.loads(raw) if raw else None
    assert resp.get("FunctionError") is None, (
        f"the function failed: {resp.get('FunctionError')!r} {out!r}")
    assert isinstance(out, dict) and "error" not in out, f"the handler reported {out!r}"
    return out


def _npm_package(ctx, sources: dict) -> bytes:
    """A deployment package: ``sources`` and package.json beside the node_modules tree
    ``npm install`` builds from the pins, which must be exactly the installed tree."""
    workdir = tempfile.mkdtemp(prefix="sim2real-npm-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    root = Path(workdir)
    manifest = {"name": "sim2real-fn", "version": "1.0.0", "private": True, **_PACKAGE_FIELDS,
                "dependencies": _DEPENDENCIES}
    (root / "package.json").write_text(json.dumps(manifest, indent=2))
    for name, code in sources.items():
        (root / name).write_text(code)
    # side-channel: the check fetches its pinned packages from the public npm registry at run
    # time, exactly as `npm install` on the customer's machine would.
    r = subprocess.run(
        ["npm", "install", "--omit=dev", "--no-audit", "--no-fund", "--ignore-scripts"],
        cwd=workdir, env=ctx.subprocess_env(), capture_output=True, text=True, timeout=240)
    if r.returncode != 0:
        raise RuntimeError(f"npm install exited {r.returncode}: {r.stderr[-2000:]}")
    lock = json.loads((root / "node_modules" / ".package-lock.json").read_text())
    installed = {path.rsplit("node_modules/", 1)[-1]: meta["version"]
                 for path, meta in lock["packages"].items() if path}
    if installed != _DEPENDENCIES:
        raise RuntimeError(f"npm installed {installed!r}, the pins are {_DEPENDENCIES!r}")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in (*sources, "package.json"):
            zf.write(root / name, name)
        for dirpath, _dirs, files in os.walk(root / "node_modules"):
            for file in files:
                path = Path(dirpath, file)
                zf.write(path, path.relative_to(root).as_posix())
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
