"""deep-lambda-1-fn-state-padded-code-update-in-progress-serves-previous-code."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-1-fn-state-padded-code-update-in-progress-serves-previous-code"
GROUP = "state-machine"
SERVICES = ["lambda"]

#: A ~10MB package of incompressible, STORED padding widens the real window during which a
#: just-issued UpdateFunctionCode stays LastUpdateStatus=InProgress.
_PAD_MB = 10
_ACTIVE_CEILING_S = 60
#: A CEILING for the padded update to settle; the poll returns as soon as it does.
_UPDATE_CEILING_S = 300
_ATTEMPTS = 3

_IN_PROGRESS_MSG = (
    "The operation cannot be performed at this time. An update is in progress for resource: "
)


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """While UpdateFunctionCode is InProgress, Invoke serves the PREVIOUS code and a second update
    is refused with ResourceConflictException without effect; once Successful the NEW code serves.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/functions-states.html
    """
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    fn = ctx.unique_name("sim2real-fnstate-pad-")
    _register_log_reap(ctx, [fn])
    fn_arn = _create_function(ctx, lam, fn, role_arn, _zip_bytes("old-v1"))["FunctionArn"]
    _wait_state(lam, fn, "Active", ceiling_s=_budget_s(ctx, _ACTIVE_CEILING_S), ctx=ctx)
    # Positive control: the deployed code serves its own marker.
    assert _invoke_marker(lam, fn) == "old-v1", "positive control: function did not serve 'old-v1'"

    # The InProgress window ends on the service's own clock, so an attempt whose window closes
    # before both mid-flight probes land is discarded and a fresh padded update is issued; every
    # probe that does land inside the window is graded.
    previous = "old-v1"
    for attempt in range(1, _ATTEMPTS + 1):
        new_marker = "new-v2" if attempt == 1 else f"new-v2-{attempt}"
        padded = _padded_zip(new_marker, _PAD_MB)
        want_sha = base64.b64encode(hashlib.sha256(padded).digest()).decode()
        outcome = _mid_flight_graded(lam, fn, fn_arn, padded, previous)
        if outcome == "graded":
            break
        _wait_update_settled(lam, fn, ceiling_s=_budget_s(ctx, _UPDATE_CEILING_S), ctx=ctx)
        previous = "rogue-v3" if outcome == "rogue-accepted" else new_marker
    else:
        raise AssertionError(
            f"in {_ATTEMPTS} padded updates, no InProgress window stayed open across the "
            f"mid-flight Invoke and the competing UpdateFunctionCode"
        )

    settled = _wait_update_settled(lam, fn, ceiling_s=_budget_s(ctx, _UPDATE_CEILING_S), ctx=ctx)
    assert settled.get("LastUpdateStatus") == "Successful", (
        f"the padded update should settle Successful, got {settled.get('LastUpdateStatus')!r} "
        f"({settled.get('LastUpdateStatusReason')!r})"
    )
    assert settled["CodeSha256"] == want_sha, (
        f"settled CodeSha256 {settled['CodeSha256']!r} is not the padded package's {want_sha!r} — "
        f"the refused 'rogue-v3' update must have had no effect"
    )
    served_new = _invoke_marker(lam, fn)
    assert served_new == new_marker, (
        f"after LastUpdateStatus=Successful, Invoke must serve the NEW code ({new_marker!r}), got "
        f"{served_new!r}"
    )


def _mid_flight_graded(lam, fn, fn_arn, padded, previous) -> str:
    """Issue the padded update and grade the probes made while it is InProgress.

    Returns "graded", or why the window closed before the probes landed.
    """
    resp = lam.update_function_code(FunctionName=fn, ZipFile=padded)
    # The start operation may report the transient or the terminal value; the poll after the
    # mid-flight leg grades the terminal one.
    assert resp.get("LastUpdateStatus") in ("InProgress", "Successful"), (
        f"UpdateFunctionCode should start an update, response said "
        f"{resp.get('LastUpdateStatus')!r}"
    )
    opened = lam.get_function_configuration(FunctionName=fn)
    if opened.get("LastUpdateStatus") != "InProgress":
        return "closed"

    # Mid-flight: a competing code update is refused, naming the update in progress.
    try:
        lam.update_function_code(FunctionName=fn, ZipFile=_zip_bytes("rogue-v3"))
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code, msg = err.get("Code"), err.get("Message", "")
        assert code == "ResourceConflictException", (
            f"a second UpdateFunctionCode during an InProgress update must raise "
            f"ResourceConflictException, got {code!r} ({msg!r})"
        )
        assert msg == _IN_PROGRESS_MSG + fn_arn, (
            f"the refusal should say an update is in progress for {fn_arn!r}; got {msg!r}"
        )
    else:
        # Accepted: the window had closed before the call arrived. The rogue code is
        # deploying, so the attempt is discarded and a fresh padded update issued.
        return "rogue-accepted"

    # Mid-flight: the previous code is what runs, graded only when the window is still open
    # after the Invoke returns.
    served = _invoke_marker(lam, fn)
    if lam.get_function_configuration(FunctionName=fn).get("LastUpdateStatus") != "InProgress":
        return "closed"
    assert served == previous, (
        f"Invoke while the padded update is InProgress must be served by the PREVIOUS code "
        f"({previous!r}), got {served!r}"
    )
    return "graded"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _handler(marker: str) -> str:
    return f"def handler(event, context):\n    return {{'marker': {marker!r}}}\n"


def _zip_bytes(marker: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _handler(marker))
    return buf.getvalue()


def _padded_zip(marker: str, pad_mb: int) -> bytes:
    """ZIP_STORED + incompressible bytes, so the package really is ~pad_mb on the wire."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("index.py", _handler(marker))
        zf.writestr("padding.bin", os.urandom(pad_mb * 1024 * 1024))
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fnstate-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy))
    return role["Role"]["Arn"]


def _create_function(ctx, lam, name, role_arn, zip_bytes):
    deadline = time.monotonic() + _budget_s(ctx, 120)
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                Code={"ZipFile": zip_bytes}, MemorySize=128, Timeout=10,
                Tags={"sim2real": CHECK})
            break
        except ClientError as exc:
            # IAM propagation of a just-created role.
            if (exc.response["Error"]["Code"] == "InvalidParameterValueException"
                    and time.monotonic() < deadline):
                time.sleep(2)
                continue
            if exc.response["Error"]["Code"] == "InvalidParameterValueException" and _budget_spent(ctx):
                raise TimeoutError(f"CreateFunction {name} to be accepted: the run budget ended first; not graded") from exc
            raise
    ctx.on_cleanup(lambda: _delete_function(lam, name))
    return resp


def _delete_function(lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _register_log_reap(ctx, names):
    """Registered BEFORE the function exists so LIFO runs it after the delete; repeated because a
    buffered log stream can recreate the group after one delete."""
    logs = ctx.client("logs")

    def _reap():
        for _ in range(3):
            for n in names:
                try:
                    logs.delete_log_group(logGroupName=f"/aws/lambda/{n}")
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            time.sleep(4)

    ctx.on_cleanup(_reap)


def _wait_state(lam, name, want, *, ceiling_s, ctx=None):
    deadline = time.monotonic() + ceiling_s
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == want:
            return cfg
        if cfg["State"] == "Failed":
            raise AssertionError(f"{name} entered Failed: {cfg.get('StateReason')!r}")
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{name} to reach State {want!r}: the run budget ended first; not graded")
    raise AssertionError(f"{name} did not reach State {want!r} within {ceiling_s}s; last {cfg!r}")


def _wait_update_settled(lam, name, *, ceiling_s, ctx=None):
    deadline = time.monotonic() + ceiling_s
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("LastUpdateStatus") != "InProgress":
            return cfg
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{name} update to leave InProgress: the run budget ended first; not graded")
    raise AssertionError(f"{name} update still InProgress after {ceiling_s}s; last {cfg!r}")


def _invoke_marker(lam, name):
    resp = lam.invoke(FunctionName=name, Payload=b"{}")
    body = json.loads(resp["Payload"].read())
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"invoke of {name} failed: StatusCode={resp['StatusCode']!r} body={body!r}"
    )
    return body.get("marker")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
