"""cdk-default-deploy-scoped-grants-deny-unauthorized-queue-receive-and-destroy-removes-all."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-default-deploy-scoped-grants-deny-unauthorized-queue-receive-and-destroy-removes-all"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "lambda", "sqs"]

_APP = "cdk_trio_scoped_grants"
_CLI_TIMEOUT_S = 900.0
_INVOKE_BUDGET_S = 60.0
_ANALYTICS = re.compile(r"v2:deflate64:[A-Za-z0-9+/]+={0,2}")


@tags(
    "axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
    "dp:api", "plane:control", "plane:data",
)
def run(ctx) -> None:
    """A default `cdk deploy` creates a table, a queue and a function granted write-only on the
    table and send-only on the queue; the function's own ReceiveMessage is denied with SQS's exact
    error, writing and sending still succeed, and `cdk destroy` removes every resource it created.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    logs = ctx.client("logs")
    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdktrio-")
    function = ctx.unique_name("sim2real-cdktrio-")
    context = {
        "stack_name": stack,
        "account": ctx.account,
        "region": ctx.region,
        "qualifier": qualifier,
        "function_name": function,
    }
    work = _stage_app(ctx)
    _bootstrap(ctx, qualifier, toolkit_stack)
    # Registered before the deploy, so the log-group reap runs after the stack delete removes the
    # function, and the stack delete is a safety net behind the in-band `cdk destroy` below.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{function}"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never",
                               "--toolkit-stack-name", toolkit_stack], context)
    assert rc == 0, f"`cdk deploy` exited {rc}; output tail {out[-800:]!r}"
    deployed = _deployed(cfn, stack)
    _assert_metadata(cfn, deployed["StackId"])
    outputs = _outputs(deployed)
    table = outputs["TableName"]
    queue_url = outputs["QueueUrl"]
    queue_arn = outputs["QueueArn"]
    role_arn = outputs["RoleArn"]
    assert outputs["FunctionName"] == function, f"the stack outputs {outputs!r}"

    # 1. Every resource is readable through its own API and carries the shape the app declared.
    described = ddb.describe_table(TableName=table)["Table"]
    shape = (
        described["TableStatus"],
        described["KeySchema"],
        described["BillingModeSummary"]["BillingMode"],
    )
    assert shape == ("ACTIVE", [{"AttributeName": "pk", "KeyType": "HASH"}], "PAY_PER_REQUEST"), (
        f"DescribeTable on {table} gives {shape!r}"
    )
    config = lam.get_function(FunctionName=function)["Configuration"]
    got = (config["Runtime"], config["Handler"], config["State"])
    assert got == ("python3.12", "index.handler", "Active"), (
        f"GetFunction on {function} gives {got!r}"
    )
    attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]
    assert attrs["QueueArn"] == queue_arn, (
        f"GetQueueAttributes on {queue_url} gives ARN {attrs['QueueArn']!r}, stack output "
        f"recorded {queue_arn!r}"
    )

    # 2. The positive controls: the granted actions actually work.
    key, marker = ctx.unique_name("pk-"), ctx.unique_name("marker-")
    result = _invoke_until_granted(lam, function, {"action": "write", "pk": key, "marker": marker})
    assert result == {"written": key}, f"the function answered {result!r}"
    item = ddb.get_item(TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")
    assert item == {"pk": {"S": key}, "marker": {"S": marker}}, (
        f"GetItem after the function's write returns {item!r}"
    )

    body = ctx.unique_name("body-")
    result = _invoke_until_granted(lam, function, {"action": "send", "body": body})
    assert sorted(result) == ["sent"], f"the function answered {result!r}"
    messages = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda msgs: bool(msgs),
        timeout_s=90.0,
        description=f"message sent by {function} on {queue_url}",
    )
    assert messages[0]["Body"] == body, messages
    assert messages[0]["MessageId"] == result["sent"], (
        f"the function reported MessageId {result['sent']!r}, the queue delivered {messages[0]['MessageId']!r}"
    )

    # 3. The negative: grantSendMessages never grants ReceiveMessage, so the function's own
    #    receive attempt is denied with SQS's exact identity-based-policy error.
    role_name = role_arn.split("/")[-1]
    want_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{function} is not "
        f"authorized to perform: sqs:receivemessage on resource: {queue_arn} because no "
        f"identity-based policy allows the sqs:receivemessage action"
    )
    outcome = _invoke_until_granted(lam, function, {"action": "receive"})
    assert outcome == {"error": "AccessDenied", "message": want_message}, (
        f"the function's own ReceiveMessage answered {outcome!r}, expected a denial carrying "
        f"{want_message!r}"
    )

    # 4. `cdk destroy` is the graded teardown step; every resource it created must be gone.
    rc, out = _cdk(ctx, work, ["destroy", stack, "--force",
                               "--toolkit-stack-name", toolkit_stack], context)
    assert rc == 0, f"`cdk destroy` exited {rc}; output tail {out[-800:]!r}"

    final = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert final == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"DescribeStacks on {stack!r} after destroy raised {final!r}"
    )
    code, message = _error(lambda: ddb.describe_table(TableName=table))
    assert (code, message) == (
        "ResourceNotFoundException", f"Requested resource not found: Table: {table} not found",
    ), f"DescribeTable on destroyed {table!r} raised ({code!r}, {message!r})"
    code, message = _error(lambda: lam.get_function(FunctionName=function))
    assert (code, message) == (
        "ResourceNotFoundException",
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function}",
    ), f"GetFunction on destroyed {function!r} raised ({code!r}, {message!r})"
    got = _error(lambda: sqs.get_queue_url(QueueName=queue_url.rsplit("/", 1)[-1]))
    assert got == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"GetQueueUrl on destroyed queue raised {got!r}"
    )
    got = _error(lambda: ctx.client("iam").get_role(RoleName=role_name))
    assert got == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"GetRole on the destroyed execution role raised {got!r}"
    )


def _invoke_until_granted(lam, function: str, event: dict) -> dict:
    """Invoke the function; retry while a just-granted permission has not yet propagated."""
    deadline = time.monotonic() + _INVOKE_BUDGET_S
    while True:
        response = lam.invoke(FunctionName=function, Payload=json.dumps(event).encode())
        payload = json.loads(response["Payload"].read())
        assert "FunctionError" not in response, f"{function} raised: {payload!r}"
        # DynamoDB reports AccessDeniedException and SQS AccessDenied while a new grant propagates.
        if payload.get("error") not in ("AccessDenied", "AccessDeniedException") or event["action"] == "receive":
            return payload
        if time.monotonic() > deadline:
            return payload
        time.sleep(2.0)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _reap_log_group(
    logs, name: str, *, reads: int = 3, interval_s: float = 2.0, budget_s: float = 180.0
) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
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
                raise AssertionError(f"log group {name} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


def _stage_app(ctx) -> Path:
    """Copy the CDK app into a temp dir so cdk.out stays out of the app directory."""
    source = Path(__file__).parent / "deployments" / _APP
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is missing app.py or cdk.json"
    )
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdk-app-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(source, work / _APP, ignore=shutil.ignore_patterns("cdk.out", "__pycache__"))
    return work / _APP


def _cli_env(ctx) -> dict[str, str]:
    """The target's subprocess env with CDK CLI telemetry off.

    CLI telemetry is separate from version reporting: turning it off keeps the CLI from
    contacting any host but the target, while the app still synthesizes `AWS::CDK::Metadata`.
    """
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    return env


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str]) -> tuple[int, str]:
    """Run the CDK CLI with its default version reporting; returns (exit code, stdout + stderr)."""
    cmd = ["cdk", *args, "--app", f"{sys.executable} app.py", "--ci", "--no-color", "--no-notices"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    done = subprocess.run(
        cmd, cwd=work, env=_cli_env(ctx), capture_output=True, text=True, timeout=_CLI_TIMEOUT_S
    )
    return done.returncode, done.stdout + done.stderr


def _deployed(cfn, name: str) -> dict:
    """The stack's description, which must be CREATE_COMPLETE."""
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {name} is {stack['StackStatus']!r} after `cdk deploy`: "
        f"{stack.get('StackStatusReason')!r}"
    )
    return stack


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _assert_metadata(cfn, stack_id: str) -> None:
    """The stack holds a created `CDKMetadata` resource whose template carries `Analytics`."""
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    found = [
        (r["ResourceType"], r["ResourceStatus"])
        for r in resources
        if r["LogicalResourceId"] == "CDKMetadata"
    ]
    assert found == [("AWS::CDK::Metadata", "CREATE_COMPLETE")], (
        f"DescribeStackResources on {stack_id} lists CDKMetadata as {found!r}"
    )
    body = cfn.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"]
    template = json.loads(body) if isinstance(body, str) else body
    metadata = template["Resources"].get("CDKMetadata", {})
    shape = (metadata.get("Type"), sorted(metadata.get("Properties", {})))
    assert shape == ("AWS::CDK::Metadata", ["Analytics"]), (
        f"GetTemplate on {stack_id} carries CDKMetadata as {metadata!r}"
    )
    analytics = metadata["Properties"]["Analytics"]
    assert _ANALYTICS.fullmatch(analytics), f"CDKMetadata Analytics is {analytics!r}"


def _delete_stack(cfn, name: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by id and wait for DELETE_COMPLETE; a stack never created is a no-op."""
    try:
        stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    stack_id = stack["StackId"]
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {name} teardown ended {status!r}")
        time.sleep(2.0)


def _bootstrap(ctx, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for a per-run qualifier; what it creates is torn down by this run."""
    s3 = ctx.client("s3")
    bucket = f"cdk-{qualifier}-assets-{ctx.account}-{ctx.region}"
    # The staging bucket has DeletionPolicy: Retain, so it is emptied and deleted after the stack;
    # the container-assets ECR repo has no DeletionPolicy and goes with the stack.
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    ctx.on_cleanup(lambda: _delete_stack(ctx.client("cloudformation"), toolkit_stack))
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdk-boot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    cmd = [
        "cdk", "bootstrap", f"aws://{ctx.account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        "--ci", "--no-color", "--no-notices",
    ]
    done = subprocess.run(
        cmd, cwd=scratch, env=_cli_env(ctx), capture_output=True, text=True, timeout=_CLI_TIMEOUT_S
    )
    assert done.returncode == 0, (
        f"`cdk bootstrap` exited {done.returncode}; output tail "
        f"{(done.stdout + done.stderr)[-800:]!r}"
    )


def _delete_bucket(s3, bucket: str) -> None:
    """Purge every object version and delete marker, then delete the bucket."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get(
                    "Errors", []
                )
                assert not failed, f"DeleteObjects in {bucket} left {failed!r}"
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _error(fn) -> tuple[str, str]:
    """The AWS (error code, message) a call raises; raises AssertionError if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return str(err["Code"]), str(err["Message"])
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
