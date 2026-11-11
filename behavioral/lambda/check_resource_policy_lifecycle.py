"""resource-policy-lifecycle."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Resource-based policy document set/get/remove roundtrip ends in ResourceNotFoundException."""
    lam = ctx.client("lambda")
    fn = _create_basic_function(ctx)

    policy_doc = _policy_document(fn["arn"], sid="AllowEventsInvoke")
    put = lam.put_resource_policy(ResourceArn=fn["arn"], Policy=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _delete_resource_policy_ignore(lam, fn["arn"]))
    put_policy = json.loads(put["Policy"])
    assert put_policy["Statement"][0]["Sid"] == "AllowEventsInvoke", (
        f"expected PutResourcePolicy to echo back Sid 'AllowEventsInvoke', got {put_policy['Statement'][0]!r}"
    )

    got = lam.get_resource_policy(ResourceArn=fn["arn"])
    got_policy = json.loads(got["Policy"])
    assert got_policy["Statement"][0]["Sid"] == "AllowEventsInvoke", (
        f"expected GetResourcePolicy to reflect Sid 'AllowEventsInvoke', got {got_policy['Statement'][0]!r}"
    )
    assert got["RevisionId"] == put["RevisionId"], (
        f"expected GetResourcePolicy RevisionId to match the RevisionId PutResourcePolicy just returned, "
        f"got {got['RevisionId']!r} vs {put['RevisionId']!r}"
    )

    lam.delete_resource_policy(ResourceArn=fn["arn"])

    code, message = _error(lambda: lam.get_resource_policy(ResourceArn=fn["arn"]))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "The resource you requested does not exist."
    assert message == expected, f"GetResourcePolicy after delete: expected message {expected!r}, got {message!r}"

    # DeleteResourcePolicy on an already-gone policy is idempotent: it does not raise
    # ResourceNotFoundException.
    redelete = lam.delete_resource_policy(ResourceArn=fn["arn"])
    assert redelete["ResponseMetadata"]["HTTPStatusCode"] == 204, (
        f"expected a second DeleteResourcePolicy on an already-gone policy to succeed idempotently, "
        f"got HTTP {redelete['ResponseMetadata'].get('HTTPStatusCode')}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _policy_document(resource_arn: str, sid: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Id": "default",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "lambda:InvokeFunction",
                "Resource": resource_arn,
            }
        ],
    }


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_basic_function(ctx) -> dict:
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 90
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _lambda_zip_bytes()},
                Timeout=10,
                MemorySize=128,
                Publish=False,
                Tags={"sim2real:managed": "true"},
            )
            break
        except Exception as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValueException" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError("create_function never succeeded (role propagation timeout)")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


def _wait_function_active(ctx, name: str) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return cfg
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function did not become Active in time (last={cfg!r})")


def _delete_resource_policy_ignore(lam, resource_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        lam.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
