"""put-resource-policy-public-document-round-trips."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-public-document-round-trips"
GROUP = "error-semantics"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy accepts an unconditioned Principal "*" lambda:InvokeFunction grant, GetPolicy
    returns it, and a later scoped PutResourcePolicy replaces the whole document.
    """
    fn = _create_function(ctx)
    lam = ctx.client("lambda")

    public_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "default",
            "Statement": [
                {
                    "Sid": "PublicInvoke",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "lambda:InvokeFunction",
                    "Resource": fn["arn"],
                }
            ],
        }
    )

    error_code = None
    try:
        lam.put_resource_policy(ResourceArn=fn["arn"], Policy=public_policy)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]

    assert error_code is None, (
        f"expected PutResourcePolicy to accept an unconditioned public invoke grant "
        f"(Lambda has no public-policy guard for this API), got {error_code!r}"
    )

    # the public statement must actually be persisted and reflected back via GetPolicy
    persisted = json.loads(lam.get_policy(FunctionName=fn["name"])["Policy"])
    persisted_sids = {s["Sid"] for s in persisted["Statement"]}
    assert "PublicInvoke" in persisted_sids, (
        f"accepted public statement missing from GetPolicy, got sids {persisted_sids!r}"
    )
    public_statement = next(s for s in persisted["Statement"] if s["Sid"] == "PublicInvoke")
    assert public_statement["Principal"] == "*", (
        f"expected the persisted principal to remain the public wildcard, "
        f"got {public_statement['Principal']!r}"
    )

    # a properly scoped (non-public) statement on the same function also succeeds via the same
    # API, and PutResourcePolicy replaces the whole document, so the public statement is gone
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    scoped_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "default",
            "Statement": [
                {
                    "Sid": "ScopedInvoke",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "lambda:InvokeFunction",
                    "Resource": fn["arn"],
                }
            ],
        }
    )
    lam.put_resource_policy(ResourceArn=fn["arn"], Policy=scoped_policy)

    replaced = json.loads(lam.get_policy(FunctionName=fn["name"])["Policy"])
    replaced_sids = {s["Sid"] for s in replaced["Statement"]}
    assert replaced_sids == {"ScopedInvoke"}, (
        f"expected PutResourcePolicy to fully replace the document, got sids {replaced_sids!r}"
    )


def _minimal_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_active(lam, name):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError("function did not become Active in time")


def _create_function(ctx, **overrides):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    role_arn = _create_lambda_role(ctx)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _minimal_zip_bytes()},
        Timeout=10,
    )
    kwargs.update(overrides)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and "cannot be assumed" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(lam, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
