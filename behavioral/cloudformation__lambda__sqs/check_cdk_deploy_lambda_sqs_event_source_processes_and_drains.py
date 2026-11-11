"""cdk-deploy-lambda-sqs-event-source-processes-and-drains."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-deploy-lambda-sqs-event-source-processes-and-drains"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "sqs"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0
_ESM_ENABLED_TIMEOUT_S = 90.0
_PROCESS_TIMEOUT_S = 120.0

_APP = "cdk_lambda_sqs_processor"
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:eventing", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A plain `cdk deploy` of a Function with an SqsEventSource: a message sent to the queue
    is actually delivered to the handler (observed on a marker it writes), and the source queue
    drains -- the message is not left or redelivered once the handler has processed it.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.account
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")

    marker_name = ctx.unique_name("sim2real-sqsesm-marker-")
    marker_url = sqs.create_queue(QueueName=marker_name,
                                  Attributes={"MessageRetentionPeriod": "3600"})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(sqs, marker_url))
    marker_arn = sqs.get_queue_attributes(
        QueueUrl=marker_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    staging = f"cdk-{qualifier}-assets-{account}-{ctx.region}"
    stack_name = ctx.unique_name("sim2real-cdksqs-")
    marker = ctx.unique_name("marker-")

    work = _stage_app(ctx, _APP)
    fn_names: list[str] = []

    try:
        _bootstrap(ctx, account, qualifier, toolkit)

        base_env = {"CDK_DEFAULT_ACCOUNT": account, "CDK_DEFAULT_REGION": ctx.region,
                    "QUALIFIER": qualifier, "STACK_NAME": stack_name, "MARKER": marker,
                    "MARKER_QUEUE_URL": marker_url, "MARKER_QUEUE_ARN": marker_arn}
        _cdk(ctx, work, ["deploy", stack_name, "--require-approval", "never"], base_env,
             timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        fn_names = _lambda_function_names(ctx, stack_name)
        role_names = [r["PhysicalResourceId"] for r in ctx.client("cloudformation").describe_stack_resources(
            StackName=stack_name)["StackResources"] if r["ResourceType"] == "AWS::IAM::Role"]
        assert role_names, f"stack {stack_name} declares no execution role"

        source_queue_url, function_name = _stack_outputs(
            ctx, stack_name, "SourceQueueUrl", "FunctionName")

        esm_uuid = _wait_esm_enabled(lam, function_name, timeout_s=_ESM_ENABLED_TIMEOUT_S)

        order_id = ctx.unique_name("order-")
        sqs.send_message(QueueUrl=source_queue_url, MessageBody=json.dumps({"orderId": order_id}))

        record = _wait_for_marker(sqs, marker_url, order_id, timeout_s=_PROCESS_TIMEOUT_S)
        assert record == {"marker": marker, "echo": {"orderId": order_id}}, (
            f"the marker the handler wrote was {record!r}, expected the echoed payload "
            f"stamped with this run's marker {marker!r}"
        )

        _wait_queue_drained(sqs, source_queue_url, timeout_s=_PROCESS_TIMEOUT_S)

        _destroy_stack(ctx, work, stack_name, base_env)

        esm_gone = _error(lambda: lam.get_event_source_mapping(UUID=esm_uuid))
        assert esm_gone == ("ResourceNotFoundException", "The resource you requested does not exist."), (
            f"GetEventSourceMapping after `cdk destroy` returned {esm_gone!r}, expected it gone"
        )
        fn_gone = _error(lambda: lam.get_function(FunctionName=function_name))
        want_fn = ("ResourceNotFoundException",
                   f"Function not found: arn:aws:lambda:{ctx.region}:{account}:function:{function_name}")
        assert fn_gone == want_fn, f"GetFunction after `cdk destroy` returned {fn_gone!r}"
        queue_gone = _error(lambda: sqs.get_queue_attributes(QueueUrl=source_queue_url))
        assert queue_gone == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
            f"GetQueueAttributes on the destroyed source queue returned {queue_gone!r}"
        )
        iam = ctx.client("iam")
        for role_name in role_names:
            role_gone = _error(lambda role_name=role_name: iam.get_role(RoleName=role_name))
            assert role_gone == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
                f"GetRole on the execution role {role_name!r} after `cdk destroy` returned {role_gone!r}"
            )
    finally:
        _teardown(ctx, stack_name, staging, toolkit, qualifier, account, fn_names)


# ===== helpers =====

def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError("call succeeded but was expected to be refused")


def _stack_missing(exc: ClientError) -> bool:
    error = exc.response["Error"]
    return error["Code"] == "ValidationError" and "does not exist" in str(error.get("Message", ""))


def _stack_outputs(ctx, stack_name: str, *keys: str) -> tuple[str, ...]:
    cfn = ctx.client("cloudformation")
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return tuple(outputs[k] for k in keys)


def _lambda_function_names(ctx, stack: str) -> list[str]:
    cfn = ctx.client("cloudformation")
    try:
        resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    except ClientError as exc:
        if _stack_missing(exc):
            return []
        raise
    return [r["PhysicalResourceId"] for r in resources
            if r["ResourceType"] == "AWS::Lambda::Function" and r.get("PhysicalResourceId")]


def _wait_esm_enabled(lam, function_name: str, *, timeout_s: float) -> str:
    """Poll to the ESM's Enabled state; returns its UUID. A message sent before the mapping is
    Enabled is not waited for by the poller, so the first send follows this."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        mappings = lam.list_event_source_mappings(FunctionName=function_name)["EventSourceMappings"]
        assert len(mappings) == 1, f"expected exactly one ESM for {function_name!r}, got {mappings!r}"
        last = mappings[0]
        if last["State"] == "Enabled":
            return last["UUID"]
        time.sleep(2.0)
    raise AssertionError(f"ESM for {function_name!r} did not reach Enabled within {timeout_s}s: "
                         f"last state {last!r}")


def _wait_for_marker(sqs, marker_url: str, order_id: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    seen: list[dict] = []
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(QueueUrl=marker_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=min(5, remaining))
        for msg in resp.get("Messages", []):
            record = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=marker_url, ReceiptHandle=msg["ReceiptHandle"])
            if record.get("echo", {}).get("orderId") == order_id:
                return record
            seen.append(record)
    raise AssertionError(f"no marker for order {order_id!r} within {timeout_s}s (saw {seen!r})")


def _wait_queue_drained(sqs, queue_url: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        last = attrs
        if attrs["ApproximateNumberOfMessages"] == "0" and attrs["ApproximateNumberOfMessagesNotVisible"] == "0":
            return
        time.sleep(2.0)
    raise AssertionError(f"source queue did not drain within {timeout_s}s: last attributes {last!r}")


def _delete_queue(sqs, url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
            raise


def _stage_app(ctx, name: str) -> Path:
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir() and (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app this check references is missing or incomplete at {source}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _bootstrap(ctx, account: str, qualifier: str, toolkit: str) -> None:
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdksqs-boot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit,
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        "--tags", f"sim2real={CHECK}",
        *_CDK_FLAGS,
    ]
    result = subprocess.run(command, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0. "
        f"Output tail: {(result.stdout + result.stderr)[-1000:]!r}"
    )


def _cdk(ctx, work: Path, args: list[str], extra_env: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env.update(extra_env)
    cmd = ["cdk", *args, *_CDK_FLAGS, "--no-color"]
    result = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True,
                            timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output "
            f"tail: {output[-1200:]!r}"
        )
    return result.returncode, output


def _destroy_stack(ctx, work: Path, stack_name: str, base_env: dict[str, str]) -> None:
    """The graded in-band `cdk destroy`; raises (never swallows) on a non-zero exit or a timeout."""
    _cdk(ctx, work, ["destroy", stack_name, "--force"], base_env,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if _stack_missing(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _stack_missing(exc):
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(2.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                      for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 2.0,
                    budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes; {absent} "
                    f"clean reads"
                )
            time.sleep(interval_s)


def _bootstrap_remnants(ctx, staging: str, toolkit: str, qualifier: str, account: str) -> list[str]:
    remaining: list[str] = []
    try:
        status = ctx.client("cloudformation").describe_stacks(StackName=toolkit)["Stacks"][0][
            "StackStatus"]
        if status != "DELETE_COMPLETE":
            remaining.append(f"toolkit stack {toolkit} in {status}")
    except ClientError as exc:
        if not _stack_missing(exc):
            raise
    try:
        ctx.client("s3").head_bucket(Bucket=staging)
        remaining.append(f"staging bucket {staging}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise
    try:
        ctx.client("ssm").get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
        remaining.append("bootstrap version parameter")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise
    iam = ctx.client("iam")
    roles = [role["RoleName"] for page in iam.get_paginator("list_roles").paginate()
             for role in page["Roles"] if role["RoleName"].startswith(f"cdk-{qualifier}-")]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


def _teardown(ctx, stack: str, staging: str, toolkit: str, qualifier: str, account: str,
             fn_names: list[str]) -> None:
    """Delete the app stack (idempotent: the in-band destroy likely already did), its functions'
    log groups, then the bootstrap toolkit and staging bucket. Collects, then raises at the end.
    """
    logs = ctx.client("logs")
    steps: list[tuple[str, object]] = [
        (f"app stack {stack}", lambda: _delete_stack_and_wait(ctx, stack)),
    ]
    steps += [(f"log group of {fn}", lambda fn=fn: _reap_log_group(logs, f"/aws/lambda/{fn}"))
              for fn in fn_names]
    steps += [(f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
              (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit))]
    errors: list[str] = []
    for label, step in steps:
        if label == f"staging bucket {staging}" and any(e.startswith("app stack ") for e in errors):
            raise AssertionError(f"toolkit stack {toolkit} and staging bucket kept: "
                                 + "; ".join(errors))
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown must report, never mask the verdict
            errors.append(f"{label}: {exc!r}")
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    remaining = _bootstrap_remnants(ctx, staging, toolkit, qualifier, account)
    while remaining and time.monotonic() < deadline:
        time.sleep(2.0)
        remaining = _bootstrap_remnants(ctx, staging, toolkit, qualifier, account)
    if remaining:
        errors.append(f"bootstrap remnants still present after {_TEARDOWN_DEADLINE_S}s: "
                      f"{remaining!r}")
    if errors:
        raise AssertionError("teardown left residue: " + "; ".join(errors))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
