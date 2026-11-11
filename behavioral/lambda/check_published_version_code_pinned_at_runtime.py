"""published-version-code-pinned-at-runtime."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "published-version-code-pinned-at-runtime"
GROUP = 'versions_aliases'
SERVICES = ['lambda']

CODE = """\
def handler(event, context):
    return {"marker": "%s"}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll(probe, timeout_s, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = probe()
        if got:
            return got
        time.sleep(interval_s)
    return None


def _wait_active(lam, fn, timeout_s=120):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')}")
        return cfg if cfg["State"] == "Active" else None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _wait_updated(lam, fn, timeout_s=120):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        status = cfg.get("LastUpdateStatus")
        if status == "Failed":
            raise AssertionError(f"{fn} update failed: {cfg.get('LastUpdateStatusReason')}")
        return cfg if status in (None, "Successful") else None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not settle LastUpdateStatus within {timeout_s}s"
    return cfg


def _invoke_marker(lam, target, **kwargs):
    resp = lam.invoke(FunctionName=target, Payload=b"{}", **kwargs)
    assert resp["StatusCode"] == 200, resp["StatusCode"]
    payload = resp["Payload"].read()
    assert "FunctionError" not in resp, (
        f"invoking {target} reported {resp.get('FunctionError')}: {payload!r}"
    )
    return resp.get("ExecutedVersion"), json.loads(payload)["marker"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """After the code is replaced, invoking published version v1 (by qualifier or ARN) still runs the v1
    code and reports ExecutedVersion v1, while $LATEST runs v2, and the version's CodeSha256 differs
    from $LATEST's."""
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam, 
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_role_arn(ctx), Code={"ZipFile": _make_zip(CODE % "v1")},
        MemorySize=128, Timeout=30,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_active(lam, fn)

    published = lam.publish_version(FunctionName=fn)
    v1 = published["Version"]
    v1_sha = published["CodeSha256"]

    executed, marker = _invoke_marker(lam, fn, Qualifier=v1)
    assert (executed, marker) == (v1, "v1"), (
        f"the freshly published version must run the published code, got "
        f"ExecutedVersion={executed!r} marker={marker!r}"
    )

    # Replace $LATEST's code. The published version must not follow it.
    lam.update_function_code(FunctionName=fn, ZipFile=_make_zip(CODE % "v2"))
    _wait_updated(lam, fn)

    latest_executed, latest_marker = _invoke_marker(lam, fn)
    assert latest_marker == "v2", (
        f"$LATEST must run the new code after UpdateFunctionCode, got marker={latest_marker!r}"
    )
    assert latest_executed == "$LATEST", (
        f"an unqualified invoke must report ExecutedVersion=$LATEST, got {latest_executed!r}"
    )

    pinned_executed, pinned_marker = _invoke_marker(lam, fn, Qualifier=v1)
    assert pinned_marker == "v1", (
        f"version {v1} must keep running the code it was published from; it returned "
        f"{pinned_marker!r}, i.e. the qualifier is a label over a single mutable code blob"
    )
    assert pinned_executed == v1, (
        f"a qualified invoke must report ExecutedVersion={v1}, got {pinned_executed!r}"
    )

    # Same invariant via the ARN-with-qualifier form customers actually deploy.
    arn_executed, arn_marker = _invoke_marker(
        lam, lam.get_function_configuration(FunctionName=fn, Qualifier=v1)["FunctionArn"]
    )
    assert (arn_executed, arn_marker) == (v1, "v1"), (
        f"invoking the version ARN must be identical to Qualifier={v1}, got "
        f"ExecutedVersion={arn_executed!r} marker={arn_marker!r}"
    )

    # The stored code identity must differ too, not only the runtime behaviour.
    latest_sha = lam.get_function_configuration(FunctionName=fn)["CodeSha256"]
    version_sha = lam.get_function_configuration(FunctionName=fn, Qualifier=v1)["CodeSha256"]
    assert version_sha == v1_sha, (
        f"the version's CodeSha256 changed after $LATEST was updated: {v1_sha} -> {version_sha}"
    )
    assert latest_sha != version_sha, (
        f"$LATEST and version {v1} hold different code but report the same CodeSha256 "
        f"{latest_sha}"
    )

    # $LATEST is still the mutable head after all of the above.
    _, still_v2 = _invoke_marker(lam, fn)
    assert still_v2 == "v2", still_v2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
