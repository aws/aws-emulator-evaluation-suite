"""nodejs-package-json-lodash-and-dayjs."""
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

CHECK = "nodejs-package-json-lodash-and-dayjs"
GROUP = "packaging"
SERVICES = ["lambda"]

_RUNTIME = "nodejs22.x"
_DEPENDENCIES = {"dayjs": "1.11.13", "lodash": "4.17.21"}
_HANDLER = """\
exports.handler = async () => {
  try {
    const _ = require('lodash');
    const dayjs = require('dayjs');
    return {
      chunk: _.chunk([1, 2, 3, 4, 5], 2),
      date: dayjs('2026-01-15').add(1, 'month').format('YYYY-MM-DD'),
      lodash: _.VERSION,
      dayjs: require('dayjs/package.json').version,
      resolved: [require.resolve('lodash'), require.resolve('dayjs')],
    };
  } catch (e) {
    return { error: `${e.name}: ${e.message}` };
  }
};
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A nodejs22.x package carrying two npm-installed dependencies runs both from /var/task:
    lodash's _.chunk splits [1..5] by two, and dayjs adds one month to a mid-January date.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-package.html
    """
    require_tools("npm", "node")
    package = _npm_package(ctx, {"index.js": _HANDLER})
    role = _execution_role(ctx)
    fn = _function(ctx, role["arn"], package)

    out = _invoke(ctx, fn["name"])
    assert out["resolved"] == ["/var/task/node_modules/lodash/lodash.js",
                               "/var/task/node_modules/dayjs/dayjs.min.js"], (
        f"lodash and dayjs resolved to {out['resolved']!r}, not the package's node_modules")
    assert out["lodash"] == "4.17.21", f"_.VERSION is {out['lodash']!r}, not 4.17.21"
    assert out["dayjs"] == "1.11.13", f"dayjs resolved at version {out['dayjs']!r}, not 1.11.13"
    assert out["chunk"] == [[1, 2], [3, 4], [5]], f"_.chunk([1..5], 2) is {out['chunk']!r}"
    want = "2026-02-15"
    assert out["date"] == want, (
        f"dayjs add(1, 'month') of the handler's date formats as {out['date']!r}, not {want!r}")


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
    manifest = {"name": "sim2real-fn", "version": "1.0.0", "private": True,
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
