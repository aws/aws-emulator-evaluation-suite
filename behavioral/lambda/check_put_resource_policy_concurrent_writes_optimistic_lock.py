"""put-resource-policy-concurrent-writes-optimistic-lock."""
from __future__ import annotations

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-resource-policy-concurrent-writes-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["lambda"]

_RACER_COUNT = 4


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutResourcePolicy calls that all supply the same (soon-stale)
    RevisionId enforce optimistic locking: exactly one racer wins and durably
    replaces the policy, the rest are rejected with PreconditionFailedException."""
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    fn = _create_function(ctx, role_arn)
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(lam, fn["arn"]))

    initial_policy = json.dumps(_policy_doc(fn["arn"], "seed"))
    revision0 = lam.put_resource_policy(ResourceArn=fn["arn"], Policy=initial_policy)["RevisionId"]

    def _racer(i):
        policy = json.dumps(_policy_doc(fn["arn"], f"racer-{i}"))
        try:
            resp = lam.put_resource_policy(ResourceArn=fn["arn"], Policy=policy, RevisionId=revision0)
            return ("ok", i, resp["RevisionId"], None)
        except ClientError as e:
            return ("err", i, e.response["Error"]["Code"], e.response["Error"].get("Message", ""))

    with ThreadPoolExecutor(max_workers=_RACER_COUNT) as pool:
        results = [f.result() for f in [pool.submit(_racer, i) for i in range(_RACER_COUNT)]]

    oks = [r for r in results if r[0] == "ok"]
    errs = [r for r in results if r[0] == "err"]
    assert len(oks) == 1, f"expected exactly one winner among {_RACER_COUNT} racers, got {len(oks)}: {results}"
    assert len(errs) == _RACER_COUNT - 1, f"expected {_RACER_COUNT - 1} losers, got {len(errs)}: {results}"
    assert all(code == "PreconditionFailedException" for (_, _, code, _) in errs), (
        f"a loser got an unexpected error code: {errs}"
    )
    lost = (
        "The value of RevisionId provided doesn't match the policy's latest revision ID. Use the "
        "GetResourcePolicy API action to retrieve the current revision ID and try again."
    )
    messages = {message for (_, _, _, message) in errs}
    assert messages == {lost}, f"a loser got an unexpected error message: {errs}"

    winner_index = oks[0][1]
    after = lam.get_resource_policy(ResourceArn=fn["arn"])
    sids = {s["Sid"] for s in json.loads(after["Policy"])["Statement"]}
    assert sids == {f"stmt-racer-{winner_index}"}, (
        f"final policy does not reflect the sole winner (PutResourcePolicy replaces, never merges): {sids}"
    )
    assert after["RevisionId"] == oks[0][2], "final policy revision does not match the recorded winner"


def _policy_doc(function_arn, tag):
    return {
        "Version": "2012-10-17",
        "Id": "default",
        "Statement": [
            {
                "Sid": f"stmt-{tag}",
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "lambda:InvokeFunction",
                "Resource": function_arn,
            }
        ],
    }


def _safe_delete_resource_policy(lam, resource_arn):
    try:
        lam.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _lambda_zip(handler_body: str = "def handler(event, context):\n    return {'ok': True}\n") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_body)
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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
    return role["Arn"]


def _create_function(ctx, role_arn: str, name: str | None = None) -> dict:
    lam = ctx.client("lambda")
    fn_name = name or ctx.unique_name("sim2real-behav-fn-")
    code = _lambda_zip()
    deadline = time.monotonic() + 60.0
    resp = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code},
                Timeout=10,
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(2.0)
                continue
            raise
    if resp is None:
        raise AssertionError(f"function creation never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_state_active(ctx, fn_name)
    return {"name": fn_name, "arn": resp["FunctionArn"], "revision_id": resp["RevisionId"]}


def _wait_state_active(ctx, function_name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        if cfg["State"] == "Active":
            return cfg
        time.sleep(1.0)
    raise AssertionError(f"function {function_name} never became Active")


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
