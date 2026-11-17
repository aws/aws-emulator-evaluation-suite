"""add-permission-statement-id-over-length-limit-rejected."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "add-permission-statement-id-over-length-limit-rejected"
GROUP = "permissions"
SERVICES = ["iam", "lambda", "logs"]

_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
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


def _wait_active(lam, fn: str, timeout_s: float = 60) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')!r}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} did not reach Active within {timeout_s}s. Last: {last!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddPermission accepts a 100-character StatementId and rejects a 101-character one with
    ValidationException naming the value and the 100-character limit; the policy stays unchanged.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC), "NoSuchEntity"))

    fn = ctx.unique_name("sim2real-behav-sidlim-fn-")
    _create_function(
        lam, FunctionName=fn, Runtime="python3.12", Handler="index.handler", Role=role_arn,
        Code={"ZipFile": _make_zip("def handler(event, context):\n    return event\n")},
    )
    ctx.on_cleanup(_teardown(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn}"),
        "ResourceNotFoundException"))
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function(FunctionName=fn), "ResourceNotFoundException"))
    _wait_active(lam, fn)

    boundary_sid = "sim2real-sid-" + "b" * (100 - len("sim2real-sid-"))
    assert len(boundary_sid) == 100, f"boundary fixture is {len(boundary_sid)} chars, expected 100"
    lam.add_permission(
        FunctionName=fn, StatementId=boundary_sid, Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
    )
    policy = json.loads(lam.get_policy(FunctionName=fn)["Policy"])
    sids = {s["Sid"] for s in policy["Statement"]}
    assert sids == {boundary_sid}, f"expected only {boundary_sid!r} present, found {sorted(sids)!r}"

    over_sid = boundary_sid + "x"
    assert len(over_sid) == 101, f"over-limit fixture is {len(over_sid)} chars, expected 101"
    code, message = _error(lambda: lam.add_permission(
        FunctionName=fn, StatementId=over_sid, Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
    ))
    want_message = (
        f"1 validation error detected: Value '{over_sid}' at 'statementId' failed to satisfy "
        "constraint: Member must have length less than or equal to 100"
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == want_message, f"unexpected message {message!r}, wanted {want_message!r}"

    policy_after = json.loads(lam.get_policy(FunctionName=fn)["Policy"])
    sids_after = {s["Sid"] for s in policy_after["Statement"]}
    assert sids_after == {boundary_sid}, (
        f"the refused AddPermission left the policy at {sorted(sids_after)!r}, "
        f"expected only the boundary statement {boundary_sid!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
