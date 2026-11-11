"""concurrent-tag-resource-merge."""
from __future__ import annotations

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-merge"
GROUP = "concurrency"
SERVICES = ["lambda"]

_RACER_COUNT = 8


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource calls adding disjoint tag keys to the same
    function are all durably merged - no writer's tag is lost to a
    last-writer-wins race on the whole tag set."""
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    fn = _create_function(ctx, role_arn)

    expected = {f"sim2real-tag-{i}": f"value-{i}" for i in range(_RACER_COUNT)}

    def _racer(key, value):
        lam.tag_resource(Resource=fn["arn"], Tags={key: value})
        return key

    with ThreadPoolExecutor(max_workers=_RACER_COUNT) as pool:
        futures = [pool.submit(_racer, k, v) for k, v in expected.items()]
        completed = [f.result() for f in futures]

    assert set(completed) == set(expected.keys()), "not every concurrent TagResource call completed"

    tags_after = lam.list_tags(Resource=fn["arn"])["Tags"]
    for key, value in expected.items():
        assert key in tags_after, f"tag {key!r} was lost under concurrent writes: {tags_after}"
        assert tags_after[key] == value, f"tag {key!r} has wrong value {tags_after[key]!r}, expected {value!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
