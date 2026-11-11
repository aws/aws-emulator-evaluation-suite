"""deploy-cdk-table-stream-consumer-copies-inserts-into-a-second-table."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "deploy-cdk-table-stream-consumer-copies-inserts-into-a-second-table"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "lambda"]

_APP = Path(__file__).parent / "deployments" / "cdk_stream_consumer"
_CLI_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 600.0
_PROPAGATION_S = 180.0


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:eventing", "concern:data-plane",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A `cdk deploy`ed table stream feeding a function that copies each insert into a second table
    delivers every put item to the sink unchanged; `cdk destroy` removes the tables, function,
    mapping and role.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkstream-")
    work = _stage(ctx, _APP)

    ctx.on_cleanup(lambda: _final_sweep(ctx, qualifier, toolkit, stack))
    _bootstrap(ctx, qualifier, toolkit)
    # The function L2s mint their own log groups, which outlive the stack delete: reap them once
    # the stack, and with it every stream mapping that could invoke them, is gone.
    log_groups: list[str] = []
    ctx.on_cleanup(lambda: _delete_stack_then_reap(cfn, logs, stack, log_groups))

    rc, out = _cdk(ctx, work, ["deploy", "--require-approval", "never",
                               "--toolkit-stack-name", toolkit], qualifier, stack)
    assert rc == 0, f"`cdk deploy` exited {rc}; output tail {out[-1200:]!r}"

    stack_desc = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert stack_desc["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {stack_desc['StackStatus']!r} after `cdk deploy`: "
        f"{stack_desc.get('StackStatusReason')!r}")
    outputs = _outputs(stack_desc)
    source, sink, function = outputs["SourceTableName"], outputs["SinkTableName"], outputs["FunctionName"]
    log_groups.append(f"/aws/lambda/{function}")
    roles = sorted(r["PhysicalResourceId"]
                   for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
                   if r["ResourceType"] == "AWS::IAM::Role")
    assert roles, f"stack {stack!r} declares no execution role"
    mappings = lam.list_event_source_mappings(FunctionName=function)["EventSourceMappings"]
    assert len(mappings) == 1, f"expected one stream mapping on {function!r}, got {mappings!r}"
    mapping_uuid = mappings[0]["UUID"]

    described_source = ddb.describe_table(TableName=source)["Table"]
    assert described_source.get("StreamSpecification", {}).get("StreamViewType") == "NEW_IMAGE", (
        f"DescribeTable on {source!r} reports StreamSpecification "
        f"{described_source.get('StreamSpecification')!r}, expected NEW_IMAGE")

    k1, k2 = ctx.unique_name("item-1-"), ctx.unique_name("item-2-")
    items = {
        k1: {"pk": {"S": k1}, "n": {"N": "1"}, "note": {"S": "first"}},
        k2: {"pk": {"S": k2}, "n": {"N": "2"}, "note": {"S": "second"}},
    }
    for item in items.values():
        ddb.put_item(TableName=source, Item=item)

    copied = _poll(
        lambda: {k: ddb.get_item(TableName=sink, Key={"pk": {"S": k}}, ConsistentRead=True).get("Item")
                 for k in items},
        lambda got: all(v is not None for v in got.values()),
        timeout_s=_PROPAGATION_S, interval_s=2.0,
        what="both inserted items reach the sink table through the stream consumer")
    assert copied == items, (
        f"the sink table's copies are {copied!r}, expected exactly the items put into the source "
        f"table: {items!r}")

    _cdk(ctx, work, ["destroy", "--force", "--toolkit-stack-name", toolkit], qualifier, stack,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)

    final = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert final == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"DescribeStacks on {stack!r} after `cdk destroy --force` raised {final!r}")

    _reap_log_group(logs, f"/aws/lambda/{function}")
    for name, table in (("source", source), ("sink", sink)):
        gone = _error(lambda t=table: ddb.describe_table(TableName=t))
        assert gone == ("ResourceNotFoundException",
                        f"Requested resource not found: Table: {table} not found"), (
            f"DescribeTable on the destroyed {name} table {table!r} raised {gone!r}")
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function}"
    gone = _error(lambda: lam.get_function(FunctionName=function))
    assert gone == ("ResourceNotFoundException", f"Function not found: {fn_arn}"), (
        f"GetFunction on the destroyed function {function!r} raised {gone!r}")
    gone = _error(lambda: lam.get_event_source_mapping(UUID=mapping_uuid))
    assert gone == ("ResourceNotFoundException", "The resource you requested does not exist."), (
        f"GetEventSourceMapping on the destroyed stream mapping raised {gone!r}")
    iam = ctx.client("iam")
    for role in roles:
        gone = _error(lambda r=role: iam.get_role(RoleName=r))
        assert gone == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
            f"GetRole on the destroyed execution role {role!r} raised {gone!r}")


def _poll(probe, done, *, timeout_s: float, interval_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return str(err["Code"]), str(err["Message"])
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _stage(ctx, app_dir: Path) -> Path:
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkstream-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _cli_env(ctx) -> dict[str, str]:
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    return env


def _cdk(ctx, work: Path, args: list[str], qualifier: str, stack: str, *,
         timeout_s: float = _CLI_TIMEOUT_S, expect_rc: int | None = None) -> tuple[int, str]:
    env = _cli_env(ctx)
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    cmd = ["cdk", *args, "--ci", "--no-color", "--no-notices",
           "--app", f"{sys.executable} app.py",
           "--context", f"stack_name={stack}", "--context", f"account={ctx.account}",
           "--context", f"region={ctx.region}", "--context", f"qualifier={qualifier}"]
    r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    rc, out = r.returncode, r.stdout + r.stderr
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk {args[0]}` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


def _bootstrap(ctx, qualifier: str, toolkit: str) -> None:
    boot = Path(tempfile.mkdtemp(prefix="sim2real-cdkstream-boot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(boot, ignore_errors=True))
    cmd = ["cdk", "bootstrap", f"aws://{ctx.account}/{ctx.region}", "--qualifier", qualifier,
           "--toolkit-stack-name", toolkit, "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
           "--ci", "--no-color", "--no-notices"]
    r = subprocess.run(cmd, cwd=boot, env=_cli_env(ctx), capture_output=True, text=True,
                        timeout=_CLI_TIMEOUT_S)
    assert r.returncode == 0, (
        f"`cdk bootstrap` exited {r.returncode}; output tail {(r.stdout + r.stderr)[-1200:]!r}")



def _delete_stack_then_reap(cfn, logs, stack: str, log_groups: list[str]) -> None:
    _delete_stack_and_wait(cfn, stack)
    for name in log_groups:
        _reap_log_group(logs, name)

def _delete_stack_and_wait(cfn, stack: str, *, timeout_s: float = 540.0) -> None:
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist":
            return
        raise
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    status = "never read"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            break
        time.sleep(2.0)
    raise AssertionError(f"stack {stack!r} is {status!r} after DeleteStack, expected DELETE_COMPLETE")


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 2.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group `name` until `reads` consecutive reads find it absent."""
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


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _final_sweep(ctx, qualifier: str, toolkit: str, stack: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] != f"Stack with id {stack} does not exist":
            raise
        status = "DELETE_COMPLETE"
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"app stack {stack} is {status!r}: toolkit stack {toolkit} kept so "
                             f"the app stack can still be deleted")
    staging = f"cdk-{qualifier}-assets-{ctx.account}-{ctx.region}"
    errors: list[str] = []
    for label, fn in (
        (f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
        (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(cfn, toolkit)),
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — collected and raised below, every step still runs
            errors.append(f"{label}: {exc!r}")
    if errors:
        raise AssertionError(f"teardown left resources behind: {errors!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
