"""sam-s3-event-prefix-filter-invokes-and-filters."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "sam-s3-event-prefix-filter-invokes-and-filters"
GROUP = "deploy-sam"
SERVICES = ["cloudformation", "lambda", "s3"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_PROJECT = "sam_s3_event"
_TEMPLATE_FILE = "template.yaml"
_DEADLINE_S = 600.0


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e",
      "concern:eventing", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A SAM Function's S3 event becomes the bucket's prefix-filtered notification: a PutObject under
    the prefix invokes it (it writes a marker the check reads) and a key outside never does.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-filtering.html
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    stack = ctx.unique_name("sim2real-s3event-")
    bucket = ctx.unique_name("sim2real-s3event-")
    deploy_bucket = ctx.unique_name("sim2real-s3event-deploy-")
    fn = ctx.unique_name("sim2real-s3event-")
    work = _workdir(ctx, _PROJECT)

    _make_bucket(ctx, s3, deploy_bucket)
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    ctx.on_cleanup(lambda: _delete_stack_named(cfn, stack))
    _ok(_sam(ctx, work, _deploy_args(
        ctx, stack, deploy_bucket, "--no-fail-on-empty-changeset",
        "--parameter-overrides", f"FunctionName={fn}", f"BucketName={bucket}",
    )), "deploy")

    described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", f"stack is {described['StackStatus']!r}"
    assert _physical_id(cfn, stack, "Bucket") == bucket, "the bucket must be named as requested"
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))
    good_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"

    # The S3 event SAM expanded into the bucket's own NotificationConfiguration.
    config = s3.get_bucket_notification_configuration(Bucket=bucket)
    lambda_configs = config.get("LambdaFunctionConfigurations", [])
    assert len(lambda_configs) == 1, f"expected one Lambda notification, got {config!r}"
    rules = lambda_configs[0]["Filter"]["Key"]["FilterRules"]
    got = (lambda_configs[0]["LambdaFunctionArn"], lambda_configs[0]["Events"],
           [(r["Name"].lower(), r["Value"]) for r in rules])
    assert got == (good_arn, ["s3:ObjectCreated:*"], [("prefix", "trigger/")]), (
        f"the bucket's NotificationConfiguration reads back {got!r}"
    )

    start = time.monotonic()
    s3.put_object(Bucket=bucket, Key="trigger/good.txt", Body=b"hello")
    _poll(lambda: _exists(s3, bucket, "marker/good.txt"), lambda ok: ok, timeout_s=120.0,
          interval_s=2.0, what="marker written for the matching key")
    good_body = s3.get_object(Bucket=bucket, Key="marker/good.txt")["Body"].read()
    assert good_body == b"trigger/good.txt", f"unexpected marker content {good_body!r}"
    latency = time.monotonic() - start

    s3.put_object(Bucket=bucket, Key="ignore/bad.txt", Body=b"hello")
    deadline = time.monotonic() + max(30.0, 5 * latency)
    while time.monotonic() < deadline:
        assert not _exists(s3, bucket, "marker/bad.txt"), (
            "a key outside the prefix filter must never invoke the function")
        time.sleep(2.0)

    roles = _stack_roles(cfn, described["StackId"])
    assert len(roles) == 1, f"expected the function's execution role, got {roles!r}"
    _empty_bucket(s3, bucket)
    _delete_stack(cfn, described["StackId"])
    code, message = _error(lambda: s3.head_bucket(Bucket=bucket))
    assert code == "404", f"bucket survived delete: {code!r}"
    code, message = _error(lambda: lam.get_function(FunctionName=fn))
    assert code == "ResourceNotFoundException", f"function survived delete: {code!r}"
    assert message == f"Function not found: {good_arn}", f"unexpected message {message!r}"
    _assert_roles_gone(ctx.client("iam"), roles)


def _exists(s3, bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return False
        raise


def _empty_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _error(fn):
    """(Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


def _physical_id(cfn, stack: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _sam(ctx, cwd: Path, args: list, *, timeout_s: float = 600.0):
    """Run the SAM CLI in ``cwd`` against the target, with telemetry off."""
    sam = shutil.which("sam")
    if sam is None:
        raise RequiredToolMissing(["sam"])
    ctx.verify_account_safety()
    return subprocess.run([sam, *args], cwd=cwd,
                          env={**ctx.subprocess_env(), "SAM_CLI_TELEMETRY": "0"},
                          capture_output=True, text=True, timeout=timeout_s)


def _ok(result, what: str) -> str:
    """stdout of a SAM CLI run that must exit 0."""
    assert result.returncode == 0, (
        f"`sam {what}` exited {result.returncode}: {(result.stdout + result.stderr)[-1500:]!r}")
    return result.stdout


def _deploy_args(ctx, stack: str, bucket: str, *extra: str) -> list:
    """``sam deploy`` of the template into the check's own bucket, never prompting."""
    return ["deploy", "--template-file", _TEMPLATE_FILE, "--stack-name", stack,
            "--s3-bucket", bucket, "--s3-prefix", stack, "--capabilities", "CAPABILITY_IAM",
            "--region", ctx.region, "--no-confirm-changeset", "--no-progressbar",
            "--tags", f"sim2real={CHECK}", *extra]


def _workdir(ctx, project: str) -> Path:
    """A scratch copy of the SAM project, so a build never writes into the source tree."""
    root = Path(tempfile.mkdtemp(prefix="sim2real-sam-"))
    ctx.on_cleanup(lambda: shutil.rmtree(root))
    work = root / "app"
    shutil.copytree(DEPLOYMENTS / project, work)
    return work


def _make_bucket(ctx, s3, name: str) -> None:
    """Create the deploy-artifact bucket with a teardown that empties and deletes it."""
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def empty_and_delete() -> None:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=name, Key=obj["Key"])
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(empty_and_delete)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})


def _poll(probe, done, *, timeout_s: float, interval_s: float = 2.0, what: str = "condition"):
    """``probe()`` until ``done(result)``; returns the result and raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete by ``StackId`` and wait for ``DELETE_COMPLETE``; any other end raises."""
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _delete_stack_named(cfn, name: str) -> None:
    """Delete the stack a CLI created under ``name``, if it exists, and wait for ``DELETE_COMPLETE``."""
    try:
        stack_id = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    _delete_stack(cfn, stack_id)


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 2.0,
                    budget_s: float = 60.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads, ``interval_s`` apart, find it
    absent; a late log flush that re-creates the group is deleted again."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while True:
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
            if absent >= reads:
                return
        if time.monotonic() > deadline:
            raise AssertionError(f"log group {name} still re-appears after {budget_s}s")
        time.sleep(interval_s)


def _stack_roles(cfn, stack: str) -> list[str]:
    """Names of every AWS::IAM::Role the stack created, read before its delete."""
    resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    return sorted(r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::IAM::Role")


def _assert_roles_gone(iam, roles: list[str]) -> None:
    """Each role answers NoSuchEntity with IAM's exact message."""
    for role in roles:
        try:
            iam.get_role(RoleName=role)
        except ClientError as exc:
            got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            assert got == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
                f"GetRole({role!r}) after the stack delete: {got!r}"
            )
            continue
        raise AssertionError(f"role {role!r} survived the stack delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
