"""tags-lifecycle."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "tags-lifecycle"
GROUP = 'tags'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}


def _exec_role_arn(ctx) -> str:
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
    policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function_when_role_ready(lam, **kwargs):
    """CreateFunction, retried while the role this check just created propagates in IAM."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


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


def _deploy_function(ctx, lam, code, *, name=None, handler="index.handler",
                     runtime="python3.12", memory=128, timeout=30, environment=None,
                     layers=None, ephemeral_storage=None, role=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role or _exec_role_arn(ctx),
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": memory,
        "Timeout": timeout,
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    _create_function_when_role_ready(lam, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(fn):
    """The (code, message) of a call that must fail; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags applied and removed from a function are reflected consistently in ListTags.

    Overly-permissive boundary: a reserved "aws:" tag-key prefix must be rejected outright,
    not silently accepted/persisted.
    """
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return e")
    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]

    before = lam.list_tags(Resource=fn_arn)["Tags"]
    assert "sim2real-behav-owner" not in before, before

    lam.tag_resource(
        Resource=fn_arn, Tags={"sim2real-behav-owner": "team-a", "sim2real-behav-env": "test"}
    )
    listed = lam.list_tags(Resource=fn_arn)["Tags"]
    assert listed.get("sim2real-behav-owner") == "team-a", listed
    assert listed.get("sim2real-behav-env") == "test", listed

    got = lam.get_function(FunctionName=fn)
    assert got.get("Tags", {}).get("sim2real-behav-owner") == "team-a", got.get("Tags")

    reserved_code, reserved_message = _error(
        lambda: lam.tag_resource(Resource=fn_arn, Tags={"aws:reserved-prefix": "x"})
    )
    assert reserved_code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a reserved tag key, got {reserved_code}"
    )
    assert reserved_message == (
        'One or more of your tags had a problem, please ensure none of your tag names start with '
        '"aws:", none are empty, and there are no duplicate tags'
    ), f"unexpected reserved-tag-key message, got {reserved_message!r}"
    after_reject = lam.list_tags(Resource=fn_arn)["Tags"]
    assert "aws:reserved-prefix" not in after_reject, "rejected tag must not have been persisted"

    lam.untag_resource(Resource=fn_arn, TagKeys=["sim2real-behav-env"])
    after = lam.list_tags(Resource=fn_arn)["Tags"]
    assert "sim2real-behav-env" not in after, after
    assert after.get("sim2real-behav-owner") == "team-a", "untagging one key must not remove the other"

    lam.untag_resource(Resource=fn_arn, TagKeys=["sim2real-behav-owner"])
    final = lam.list_tags(Resource=fn_arn)["Tags"]
    assert "sim2real-behav-owner" not in final, final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
