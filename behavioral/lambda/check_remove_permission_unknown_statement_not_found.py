"""remove-permission-unknown-statement-not-found."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-permission-unknown-statement-not-found"
GROUP = "permissions"
SERVICES = ["lambda"]

# The only statement was removed above, so the function has no resource policy left.
_EMPTY_POLICY_MESSAGE = "The resource you requested does not exist."
_NO_POLICY_MESSAGE = "No policy is associated with the given resource."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemovePermission with a never-added StatementId is ResourceNotFoundException; removing a
    just-added statement succeeds and is confirmed gone, so the refusal is specific to the unknown
    statement.
    """
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-lambda-perm-nf-")
    _create_function(ctx, lam, name=name)
    _wait_active(lam, name)

    lam.add_permission(
        FunctionName=name,
        StatementId="known-statement",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
    )
    lam.remove_permission(FunctionName=name, StatementId="known-statement")
    try:
        sids = [
            s["Sid"]
            for s in json.loads(lam.get_policy(FunctionName=name)["Policy"])["Statement"]
        ]
        assert "known-statement" not in sids, (
            f"RemovePermission reported success but 'known-statement' is still in the policy: {sids!r}"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ResourceNotFoundException", (
            f"expected GetPolicy on an empty policy to fail with ResourceNotFoundException, got {code!r}"
        )
        assert message == _EMPTY_POLICY_MESSAGE, (
            f"GetPolicy on an empty policy: expected message {_EMPTY_POLICY_MESSAGE!r}, got {message!r}"
        )

    code, message = _error(
        lambda: lam.remove_permission(FunctionName=name, StatementId="never-existed")
    )
    assert code == "ResourceNotFoundException", (
        f"RemovePermission on a StatementId that was never added: expected "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert message == _NO_POLICY_MESSAGE, (
        f"RemovePermission on a StatementId that was never added: expected message "
        f"{_NO_POLICY_MESSAGE!r}, got {message!r}"
    )



_DEFAULT_HANDLER_SRC = """
import json

def handler(event, context):
    if isinstance(event, dict) and event.get("fail"):
        raise Exception("intentional-failure: " + str(event.get("fail")))
    return {"echo": event}
"""


def _make_zip(src: str = _DEFAULT_HANDLER_SRC, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, src)
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _exec_role_arn(ctx):
    """An execution role this check creates (once per run) and deletes in cleanup."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn



def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=1.5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _cleanup_fn(ctx, lam, name: str) -> None:
    """Delete the function and the log group Lambda implicitly creates for it."""
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


def _wait_active(lam, name: str, timeout_s: float = 90, interval_s: float = 1.5):
    """Poll until State settles at Active or Failed.

    Does not raise on Failed: a Failed function surfaces as a real service error on the next call.
    """
    return _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"function {name} to leave Pending",
    )


def _create_function(
    ctx,
    lam,
    name=None,
    src: str = _DEFAULT_HANDLER_SRC,
    handler: str = "index.handler",
    runtime: str = "python3.12",
    timeout: int = 15,
    memory: int = 128,
    role_arn: str | None = None,
    env: dict | None = None,
    **kwargs,
):
    """CreateFunction with teardown registered first and bounded retry on IAM role propagation."""
    name = name or ctx.unique_name("sim2real-behav-lambda-fn-")
    params = dict(
        FunctionName=name,
        Runtime=runtime,
        Role=role_arn or _exec_role_arn(ctx),
        Handler=handler,
        Code={"ZipFile": _make_zip(src)},
        Timeout=timeout,
        MemorySize=memory,
        Publish=False,
        Tags={"sim2real": "remove-permission-unknown-statement-not-found"},
    )
    if env is not None:
        params["Environment"] = {"Variables": env}
    params.update(kwargs)

    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    last_exc = None
    for _ in range(8):
        try:
            return lam.create_function(**params)
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or (
                "InvalidParameterValueException" in msg and "role" in msg.lower()
            ):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
