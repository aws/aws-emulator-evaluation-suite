"""python-requirements-txt-pydantic-validates."""
from __future__ import annotations

import hashlib
import io
import json
import re
import textwrap
import time
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "python-requirements-txt-pydantic-validates"
GROUP = "packaging"
SERVICES = ["lambda"]

_RUNTIME = "python3.12"
# side-channel: the pinned wheels come from the public package index at run time, as a
# `pip install -r requirements.txt -t` build fetches them; each is checked against its pin.
_INDEX = "https://pypi.org/pypi"
# requirements.txt, its whole transitive closure pinned: (distribution, version, wheel sha256).
_REQUIREMENTS = (
    ("pydantic", "2.10.6", "427d664bf0b8a2b34ff5dd0f5a18df00591adcee7198fbd71981054cef37b584"),
    ("pydantic-core", "2.27.2", "6fb4aadc0b9a0c063206846d603b92030eb6f03069151a625667f982887153e2"),
    ("typing-extensions", "4.12.2",
     "04e5ca0351e0f3f85c6853954072df659d0d13fac324d0072316b67d7794700d"),
    ("annotated-types", "0.7.0",
     "1f02e8b43a8fbbc3f3e0d4f0f4bfc8131bcb4eebe8849b8e5c773f3a1c582a53"),
)
_HANDLER = """\
def handler(event, context):
    try:
        import pydantic
        import pydantic_core
        from pydantic import BaseModel, ValidationError

        class Order(BaseModel):
            id: int
            sku: str
            qty: int = 1

        valid = Order.model_validate({"id": "42", "sku": "A-1"}).model_dump()
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    try:
        Order.model_validate({"id": "x", "sku": "A-1"})
        rejected = None
    except ValidationError as exc:
        rejected = {"count": exc.error_count(),
                    "errors": [{"type": e["type"], "loc": list(e["loc"])} for e in exc.errors()]}
    except Exception as exc:
        rejected = {"raised": f"{type(exc).__name__}: {exc}"}
    return {"valid": valid, "rejected": rejected, "pydantic": pydantic.VERSION,
            "core": pydantic_core.__version__, "core_file": pydantic_core._pydantic_core.__file__}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A python3.12 x86_64 package built from pinned pydantic v2 requirements, its native
    pydantic-core among them, validates a model: lax input coerces to the dumped model, and an
    unparseable integer raises ValidationError with exactly one int_parsing error.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/python-package.html
    """
    package = _package(_HANDLER, _REQUIREMENTS)
    role = _execution_role(ctx)
    fn = _function(ctx, role["arn"], package)

    out = _invoke(ctx, fn["name"])
    assert out["pydantic"] == "2.10.6", f"pydantic.VERSION is {out['pydantic']!r}, not 2.10.6"
    assert out["core"] == "2.27.2", f"pydantic_core.__version__ is {out['core']!r}, not 2.27.2"
    core = out["core_file"]
    assert core.startswith("/var/task/pydantic_core/") and core.endswith(".so"), (
        f"pydantic-core's extension module loaded from {core!r}, not a .so under /var/task/")
    assert out["valid"] == {"id": 42, "sku": "A-1", "qty": 1}, (
        f"model_dump() of the validated model is {out['valid']!r}")
    expected = {"count": 1, "errors": [{"type": "int_parsing", "loc": ["id"]}]}
    assert out["rejected"] == expected, (
        f"validating id='x' should raise ValidationError {expected!r}; got {out['rejected']!r}")


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


def _http_get(url: str) -> bytes:
    # side-channel: the check fetches its pinned wheels from the public PyPI index at run time,
    # exactly as `pip install -r requirements.txt` on the customer's machine would.
    with urllib.request.urlopen(urllib.request.Request(url), timeout=120) as resp:
        return resp.read()


def _manylinux2014_x86_64(tag: str) -> bool:
    """Whether pip's ``--platform manylinux2014_x86_64`` (glibc 2.17) accepts platform ``tag``."""
    if tag in ("manylinux1_x86_64", "manylinux2010_x86_64", "manylinux2014_x86_64"):
        return True
    m = re.fullmatch(r"manylinux_2_(\d+)_x86_64", tag)
    return m is not None and int(m.group(1)) <= 17


def _wheel_rank(filename: str):
    """0 for a py3-none-any wheel, 1 for a cp312-cp312 manylinux2014 x86_64 one, None for a wheel
    ``--implementation cp --python-version 3.12 --platform manylinux2014_x86_64`` refuses."""
    py, abi, plat = (set(t.split(".")) for t in filename[:-len(".whl")].split("-")[-3:])
    if "py3" in py and "none" in abi and "any" in plat:
        return 0
    if "cp312" in py and "cp312" in abi and any(_manylinux2014_x86_64(t) for t in plat):
        return 1
    return None


def _fetch_wheel(name: str, version: str, sha256: str) -> tuple:
    """(file name, bytes) of the wheel a pin installs, checked against the sha256 the index
    publishes for it, which must be the pinned one."""
    meta = json.loads(_http_get(f"{_INDEX}/{name}/{version}/json"))
    ranked = sorted(
        ((rank, u["filename"]), u) for u in meta["urls"]
        if u["packagetype"] == "bdist_wheel" and (rank := _wheel_rank(u["filename"])) is not None)
    if not ranked:
        raise RuntimeError(f"{name}=={version} publishes no cp312 manylinux2014_x86_64 wheel: "
                           f"{[u['filename'] for u in meta['urls']]!r}")
    wheel = ranked[0][1]
    published = wheel["digests"]["sha256"]
    if published != sha256:
        raise RuntimeError(
            f"{wheel['filename']}: the index publishes sha256 {published}, the pin is {sha256}")
    body = _http_get(wheel["url"])
    got = hashlib.sha256(body).hexdigest()
    if got != published:
        raise RuntimeError(f"{wheel['filename']} downloaded with sha256 {got}, not {published}")
    return wheel["filename"], body


def _install(zf: zipfile.ZipFile, requirements) -> None:
    """``pip install -t``: every pinned wheel's files, ``.dist-info`` included, written at the
    root of ``zf``."""
    for name, version, sha256 in requirements:
        filename, body = _fetch_wheel(name, version, sha256)
        with zipfile.ZipFile(io.BytesIO(body)) as wheel:
            for info in wheel.infolist():
                if info.is_dir():
                    continue
                if ".data/" in info.filename:
                    raise RuntimeError(
                        f"{filename} ships a .data entry {info.filename!r} this install does not map")
                entry = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                entry.external_attr = info.external_attr
                entry.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(entry, wheel.read(info))


def _package(handler: str, requirements) -> bytes:
    """A deployment package: ``index.py`` at the root beside the installed requirements."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(handler))
        _install(zf, requirements)
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
