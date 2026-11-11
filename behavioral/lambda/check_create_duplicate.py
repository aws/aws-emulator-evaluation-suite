"""create-duplicate."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-duplicate"
GROUP = 'errors'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_ASSUMABLE = "The role defined for the function cannot be assumed by Lambda."
_ROLES = []


def _delete_role(iam, name):
    for call in (
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY),
        lambda: iam.delete_role(RoleName=name),
    ):
        try:
            call()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise


def _execution_role(ctx):
    """The execution role this check creates for its functions, one per run."""
    for owner, arn in _ROLES:
        if owner is ctx:
            return arn
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lam-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY)
    _ROLES.append((ctx, arn))
    return arn


def _call_create_function(lam, **kwargs):
    """CreateFunction, retried while IAM propagates the execution role this check created."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") != "InvalidParameterValueException"
                or err.get("Message") != _ROLE_NOT_ASSUMABLE
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(3)


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function_url_config(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
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


def _wait_active(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _create_function(ctx, lam, code_src, name=None, **kwargs):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    resp = _call_create_function(lam, 
        FunctionName=name, Runtime="python3.12", Handler="index.handler",
        Role=_execution_role(ctx),
        Code={"ZipFile": _make_zip(code_src)},
        **kwargs,
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    return name, resp


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised.

    An unexpected SUCCESS raises.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("CreateFunction unexpectedly succeeded on a name that already exists")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction on an existing name fails with ResourceConflictException and leaves the original
    CodeSha256 unchanged; after DeleteFunction the name is not found, and the same create succeeds.
    """
    lam = ctx.client("lambda")
    original_code = "def handler(event, context): return {'gen': 1}\n"
    conflicting_code = "def handler(event, context): return {'gen': 2}\n"

    fn, created = _create_function(ctx, lam, original_code)
    _wait_active(lam, fn)
    original_sha = created["CodeSha256"]

    def _conflicting_create():
        _call_create_function(lam, 
            FunctionName=fn,
            Runtime="python3.12",
            Handler="index.handler",
            Role=_execution_role(ctx),
            Code={"ZipFile": _make_zip(conflicting_code)},
        )

    code, message = _error_code(_conflicting_create)
    assert code == "ResourceConflictException", (
        f"CreateFunction on the existing name {fn!r} returned {code!r}, expected "
        f"ResourceConflictException"
    )
    expected = f"Function already exist: {fn}"
    assert message == expected, (
        f"CreateFunction on the existing name {fn!r} returned message {message!r}, "
        f"expected {expected!r}"
    )

    after = lam.get_function_configuration(FunctionName=fn)
    assert after["CodeSha256"] == original_sha, (
        f"a rejected CreateFunction on {fn!r} changed the stored code: expected CodeSha256 "
        f"{original_sha!r}, observed {after['CodeSha256']!r}"
    )

    lam.delete_function(FunctionName=fn)
    not_found = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    gone_code, gone_message = _error_code(lambda: lam.get_function_configuration(FunctionName=fn))
    assert gone_code == "ResourceNotFoundException", (
        f"GetFunctionConfiguration({fn!r}) after DeleteFunction returned {gone_code!r}, expected "
        f"ResourceNotFoundException"
    )
    assert gone_message == not_found, (
        f"GetFunctionConfiguration({fn!r}) after DeleteFunction returned message "
        f"{gone_message!r}, expected {not_found!r}"
    )
    dead_mutation_code, dead_mutation_message = _error_code(
        lambda: lam.update_function_configuration(FunctionName=fn, Timeout=10)
    )
    assert dead_mutation_code == "ResourceNotFoundException", (
        f"UpdateFunctionConfiguration on the deleted name {fn!r} returned "
        f"{dead_mutation_code!r}, expected ResourceNotFoundException"
    )
    assert dead_mutation_message == not_found, (
        f"UpdateFunctionConfiguration on the deleted name {fn!r} returned message "
        f"{dead_mutation_message!r}, expected {not_found!r}"
    )

    restored_name, restored = _create_function(ctx, lam, conflicting_code, name=fn)
    _wait_active(lam, restored_name)
    assert restored_name == fn, f"restore recreated a different name: {restored_name!r} != {fn!r}"
    assert restored["CodeSha256"] != original_sha, (
        f"the restored function at {fn!r} unexpectedly reports the deleted original's CodeSha256 "
        f"{original_sha!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
