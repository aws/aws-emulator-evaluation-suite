"""update-alias-concurrent-conflicting-writes."""
from __future__ import annotations

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-alias-concurrent-conflicting-writes"
GROUP = "concurrency"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateAlias calls racing on the same stale RevisionId
    resolve to exactly one winner and one PreconditionFailedException loser;
    no update is silently lost or double-applied."""
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    fn = _create_function(ctx, role_arn)
    v1 = lam.publish_version(FunctionName=fn["name"])["Version"]

    alias_name = ctx.unique_name("sim2real-behav-alias-")
    create_resp = lam.create_alias(FunctionName=fn["name"], Name=alias_name, FunctionVersion=v1)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=fn["name"], Name=alias_name))
    revision0 = create_resp["RevisionId"]

    def _racer(description):
        try:
            resp = lam.update_alias(
                FunctionName=fn["name"],
                Name=alias_name,
                Description=description,
                RevisionId=revision0,
            )
            return ("ok", resp["RevisionId"], None)
        except ClientError as e:
            return ("err", e.response["Error"]["Code"], e.response["Error"].get("Message", ""))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_racer, "racer-A"), pool.submit(_racer, "racer-B")]
        results = [f.result() for f in futures]

    oks = [r for r in results if r[0] == "ok"]
    errs = [r for r in results if r[0] == "err"]
    assert len(oks) == 1, f"expected exactly one winner among racers, got {len(oks)}: {results}"
    assert len(errs) == 1, f"expected exactly one loser among racers, got {len(errs)}: {results}"
    assert errs[0][1] == "PreconditionFailedException", f"expected PreconditionFailedException, got {errs[0][1]!r}"
    loser_message = errs[0][2]
    assert loser_message == (
        "The Revision Id provided does not match the latest Revision Id. Call the "
        "GetFunction/GetAlias API to retrieve the latest Revision Id"
    ), loser_message

    final = lam.get_alias(FunctionName=fn["name"], Name=alias_name)
    assert final["Description"] in ("racer-A", "racer-B"), f"unexpected final description: {final['Description']!r}"
    assert final["RevisionId"] == oks[0][1], "final alias revision does not match the recorded winner"


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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]
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
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code},
                Timeout=10,
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
