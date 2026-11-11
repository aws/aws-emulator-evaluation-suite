"""put-resource-policy-length-exceeded."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-length-exceeded"
GROUP = "error-semantics"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with a policy over 20480 characters is ValidationException with the exact
    length-constraint message, and leaves the in-bounds policy written first and its RevisionId
    unchanged."""
    fn = _create_function(ctx)
    lam = ctx.client("lambda")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # positive control: an in-bounds policy on the same wiring is accepted and persisted, so a
    # rejection below cannot be confused with "this account can't call PutResourcePolicy at all"
    baseline_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "default",
            "Statement": [
                {
                    "Sid": "AllowRootInvoke",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "lambda:InvokeFunction",
                    "Resource": fn["arn"],
                }
            ],
        }
    )
    put = lam.put_resource_policy(ResourceArn=fn["arn"], Policy=baseline_policy)
    baseline_revision = put["RevisionId"]
    baseline_persisted = json.loads(lam.get_policy(FunctionName=fn["name"])["Policy"])
    assert {s["Sid"] for s in baseline_persisted["Statement"]} == {"AllowRootInvoke"}, (
        f"positive control: expected the in-bounds policy to be persisted, got {baseline_persisted!r}"
    )

    statements = []
    for i in range(400):
        statements.append(
            {
                "Sid": f"Statement{i}",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{100000000000 + i:012d}:root"},
                "Action": "lambda:InvokeFunction",
                "Resource": fn["arn"],
            }
        )
    policy = json.dumps({"Version": "2012-10-17", "Id": "default", "Statement": statements})
    assert len(policy) > 20480, "constructed policy is not actually oversized"

    error_code, error_msg = _error(lambda: lam.put_resource_policy(ResourceArn=fn["arn"], Policy=policy))
    assert error_code == "ValidationException", (
        f"expected ValidationException, got {error_code!r}"
    )
    assert error_msg == (
        f"1 validation error detected: Value '{policy}' at 'policy' failed to satisfy constraint: "
        "Member must have length less than or equal to 20480"
    ), f"expected the exact policy-length message, got {error_msg!r}"

    # the rejected write must not have replaced or partially applied over the existing policy
    after = lam.get_policy(FunctionName=fn["name"])
    after_policy = json.loads(after["Policy"])
    assert {s["Sid"] for s in after_policy["Statement"]} == {"AllowRootInvoke"}, (
        f"rejected oversized policy leaked into the stored document, got {after_policy!r}"
    )
    assert after["RevisionId"] == baseline_revision, (
        f"expected RevisionId to stay at {baseline_revision!r} after a rejected write, "
        f"got {after['RevisionId']!r}"
    )


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
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
        Tags={"sim2real:managed": "true"},
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
