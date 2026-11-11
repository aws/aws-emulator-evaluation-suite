"""python-importlib-metadata-reads-vendored-dist-info."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "python-importlib-metadata-reads-vendored-dist-info"
GROUP = "python-runtime"
SERVICES = ["lambda"]

_RUNTIME = "python3.12"
_SOURCE_FILE = "index.py"

_PKG_INIT = 'VALUE = "vendored"\n'
_METADATA = "Metadata-Version: 2.1\nName: mypkg\nVersion: 1.2.3\nSummary: A vendored package.\n"
_HANDLER = """\
import importlib.metadata

import mypkg


def handler(event, context):
    dist = importlib.metadata.distribution("mypkg")
    return {
        "version": importlib.metadata.version("mypkg"),
        "name": importlib.metadata.metadata("mypkg")["Name"],
        "files": sorted(str(f) for f in dist.files),
        "init_path": str(dist.locate_file("mypkg/__init__.py")),
        "module_file": mypkg.__file__,
        "value": mypkg.VALUE,
    }
"""


def _record_line(path: str, body: str) -> str:
    """A RECORD row: path, urlsafe-base64 sha256 without padding, size."""
    data = body.encode()
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{path},sha256={digest},{len(data)}"


def _package() -> dict:
    """mypkg/ and its mypkg-1.2.3.dist-info/ at the zip root, beside the handler."""
    dist = "mypkg-1.2.3.dist-info"
    files = {"mypkg/__init__.py": _PKG_INIT, f"{dist}/METADATA": _METADATA}
    record = [_record_line(p, b) for p, b in files.items()] + [f"{dist}/RECORD,,"]
    files[f"{dist}/RECORD"] = "\n".join(record) + "\n"
    return files


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A distribution's .dist-info vendored at the root of a Python deployment package is found by
    importlib.metadata through /var/task on sys.path: version, Name and RECORD files read back.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/python-package.html
    """
    role = _execution_role(ctx)
    fn = _function(ctx, role["arn"], _HANDLER, extra=_package())
    out = _invoke_ok(ctx, fn["name"])
    assert out["version"] == "1.2.3", (
        f"importlib.metadata.version('mypkg') must be '1.2.3', got {out['version']!r}")
    assert out["name"] == "mypkg", f"METADATA Name must read back 'mypkg', got {out['name']!r}"
    want_files = ["mypkg-1.2.3.dist-info/METADATA", "mypkg-1.2.3.dist-info/RECORD",
                  "mypkg/__init__.py"]
    assert out["files"] == want_files, f"RECORD files must be {want_files!r}, got {out['files']!r}"
    assert out["init_path"] == "/var/task/mypkg/__init__.py", (
        f"the distribution must resolve inside /var/task, got {out['init_path']!r}")
    assert out["module_file"] == out["init_path"], (
        f"the imported module {out['module_file']!r} must be the file the distribution names "
        f"{out['init_path']!r}")
    assert out["value"] == "vendored", f"mypkg.VALUE read back {out['value']!r}"


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


def _zip(code: str, extra=None) -> bytes:
    """The deployment package: the handler module plus ``extra`` files keyed by archive path."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(_SOURCE_FILE, textwrap.dedent(code))
        for path, body in (extra or {}).items():
            zf.writestr(path, body)
    return buf.getvalue()


def _execution_role(ctx) -> dict:
    """A Lambda execution role with no permissions: the handler calls no AWS API, and without a
    logs: grant the function never creates a log group that could outlive the check."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"], "id": role["RoleId"]}


def _function(ctx, role_arn, code, *, timeout=60, memory=256, extra=None, environment=None) -> dict:
    """A function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    kwargs = {"FunctionName": name, "Runtime": _RUNTIME, "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code, extra)}, "Timeout": timeout,
              "MemorySize": memory, "Tags": {"sim2real": CHECK}}
    if environment:
        kwargs["Environment"] = {"Variables": environment}

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


def _invoke(ctx, fn, event=None, lam=None) -> tuple:
    """(FunctionError or None, decoded payload) of one RequestResponse invoke of ``event``."""
    lam = lam or ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse",
                      Payload=json.dumps(event or {}).encode())
    raw = resp["Payload"].read()
    return resp.get("FunctionError"), (json.loads(raw) if raw else None)


def _invoke_ok(ctx, fn, event=None) -> dict:
    """The payload of one invoke that must succeed; a FunctionError raises with the payload."""
    err, out = _invoke(ctx, fn, event)
    assert err is None, f"the function failed: {err!r} {out!r}"
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
