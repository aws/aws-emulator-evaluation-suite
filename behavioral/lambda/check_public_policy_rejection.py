"""public-policy-rejection."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "public-policy-rejection"
GROUP = 'permissions'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _role_arn(ctx):
    """An execution role this check creates once per run and deletes in its teardown."""
    import json as _json

    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY))
    _ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, **kwargs):
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


def _deploy_function(ctx, lam, code, *, name=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam,
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddPermission accepts an unscoped Principal="*" InvokeFunction grant; a wildcard-Action grant
    is either refused with PublicPolicyException, leaving the policy unchanged, or added. Removing the
    last statement leaves GetPolicy answering ResourceNotFoundException with AWS's exact message.
    """
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, HANDLER_V1)

    narrow_sid = "sim2real-behav-public-invoke"
    lam.add_permission(
        FunctionName=fn, StatementId=narrow_sid,
        Action="lambda:InvokeFunction", Principal="*",
    )
    policy = json.loads(lam.get_policy(FunctionName=fn)["Policy"])
    assert any(s.get("Sid") == narrow_sid for s in policy["Statement"]), policy

    wild_sid = "sim2real-behav-public-wild"
    try:
        lam.add_permission(
            FunctionName=fn, StatementId=wild_sid, Action="lambda:*", Principal="*",
        )
        wild_code = None
    except ClientError as exc:
        wild_code = exc.response["Error"]["Code"]
        assert wild_code == "PublicPolicyException", f"unexpected error adding the wildcard-Action grant: {exc}"
    if wild_code == "PublicPolicyException":
        after_reject_policy = json.loads(lam.get_policy(FunctionName=fn)["Policy"])
        assert not any(s.get("Sid") == wild_sid for s in after_reject_policy["Statement"]), after_reject_policy
        assert len(after_reject_policy["Statement"]) == 1, after_reject_policy
    else:
        wild_policy = json.loads(lam.get_policy(FunctionName=fn)["Policy"])
        assert any(s.get("Sid") == wild_sid for s in wild_policy["Statement"]), wild_policy
        lam.remove_permission(FunctionName=fn, StatementId=wild_sid)

    lam.remove_permission(FunctionName=fn, StatementId=narrow_sid)
    try:
        lam.get_policy(FunctionName=fn)
    except ClientError as exc:
        after_remove_code = exc.response["Error"]["Code"]
        after_remove_message = exc.response["Error"]["Message"]
    else:
        raise AssertionError("expected GetPolicy to be refused once the last statement is removed, it succeeded")
    assert after_remove_code == "ResourceNotFoundException", (
        f"expected policy gone after removing the only remaining statement, got {after_remove_code}"
    )
    assert after_remove_message == "The resource you requested does not exist.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {after_remove_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
