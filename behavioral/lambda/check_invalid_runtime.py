"""invalid-runtime."""

from __future__ import annotations

import json as _json
import time

import io
import textwrap
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "invalid-runtime"
GROUP = 'errors'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLES: dict = {}


def _role_arn(ctx):
    """Create this check's own Lambda execution role once per run and register its cleanup."""
    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY))
    _ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only while a freshly created role is not yet assumable."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = err.get("Code") == "InvalidParameterValueException" and "cannot be assumed" in err.get("Message", "")
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _cleanup_fn(lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because a
    target that accepts a call real AWS refuses must surface its actual response."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction with an invalid runtime → ValidationException (400), and nothing is created.

    A positive control creates a real function first, so the rejection cannot be confused with a
    target that denies every CreateFunction call regardless of the runtime value.
    """
    lam = ctx.client("lambda")
    role = _role_arn(ctx)

    good_name = ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam,
        FunctionName=good_name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role,
        Code={"ZipFile": _make_zip("def handler(event, context): return event\n")},
        Tags={"sim2real": "invalid-runtime"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(lam, good_name))
    lam.get_function(FunctionName=good_name)

    bad_name = ctx.unique_name("sim2real-behav-fn-bad-")
    code, _message = _error(
        lambda: _create_function(lam,
            FunctionName=bad_name,
            Runtime="python2.5",
            Handler="x.x",
            Role=role,
            Code={"ZipFile": _make_zip("def handler(event, context): return event\n")},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    # message varies: it lists every runtime Lambda currently accepts, in no stable order, and
    # the list changes as runtimes are added and retired.

    absent_code, absent_message = _error(lambda: lam.get_function(FunctionName=bad_name))
    assert absent_code == "ResourceNotFoundException", (
        f"CreateFunction with an invalid runtime was rejected but {bad_name} is visible via "
        f"GetFunction (code={absent_code!r})"
    )
    bad_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_name}"
    assert absent_message == f"Function not found: {bad_arn}", absent_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
