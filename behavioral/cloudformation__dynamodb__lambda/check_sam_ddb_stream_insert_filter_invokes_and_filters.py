"""sam-ddb-stream-insert-filter-invokes-and-filters."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "sam-ddb-stream-insert-filter-invokes-and-filters"
GROUP = "deploy-sam"
SERVICES = ["cloudformation", "dynamodb", "lambda"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_PROJECT = "sam_ddb_stream"
_TEMPLATE_FILE = "template.yaml"
_DEADLINE_S = 600.0


@tags("axis:negative-delivery", "cap:c3", "cap:c6", "concern:data-plane", "concern:deploy",
      "concern:e2e", "concern:eventing", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A SAM Function's DynamoDB stream event invokes on an item insert, and the mapping's
    FilterCriteria keeps a later modification of that same item from ever reaching it.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-ddb.html
    """
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    lam = ctx.client("lambda")
    ssm = ctx.client("ssm")
    logs = ctx.client("logs")
    stack = ctx.unique_name("sim2real-ddbstream-")
    bucket = ctx.unique_name("sim2real-ddbstream-")
    fn = ctx.unique_name("sim2real-ddbstream-")
    marker_prefix = ctx.unique_name("sim2real-ddbstream-")
    work = _workdir(ctx, _PROJECT)
    log_group = f"/aws/lambda/{fn}"

    _make_bucket(ctx, ctx.client("s3"), bucket)
    ctx.on_cleanup(lambda: _reap_log_group(logs, log_group))
    for item in ("insert-item", "barrier-item"):
        ctx.on_cleanup(lambda item=item: _ignore_not_found(
            lambda: ssm.delete_parameter(Name=f"{marker_prefix}{item}"), "ParameterNotFound"))
    ctx.on_cleanup(lambda: _delete_stack_named(cfn, stack))
    _ok(_sam(ctx, work, _deploy_args(
        ctx, stack, bucket, "--no-fail-on-empty-changeset",
        "--parameter-overrides", f"FunctionName={fn}", f"MarkerPrefix={marker_prefix}",
    )), "deploy")

    described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", f"stack is {described['StackStatus']!r}"
    table = _physical_id(cfn, stack, "Table")
    stream_arn = ddb.describe_table(TableName=table)["Table"]["LatestStreamArn"]

    _wait_for_mapping_enabled(lam, fn, stream_arn)
    (mapping,) = lam.list_event_source_mappings(FunctionName=fn, EventSourceArn=stream_arn)[
        "EventSourceMappings"]
    assert mapping["FilterCriteria"] == {"Filters": [{"Pattern": '{"eventName": ["INSERT"]}'}]}, (
        f"the mapping SAM created reads back FilterCriteria {mapping.get('FilterCriteria')!r}"
    )

    start = time.monotonic()
    ddb.put_item(TableName=table, Item={"pk": {"S": "insert-item"}, "v": {"S": "1"}})
    value = _poll(lambda: _get_parameter(ssm, f"{marker_prefix}insert-item"), lambda v: v is not None,
                  timeout_s=120.0, interval_s=2.0, what="marker written for the inserted item")
    assert value == "inserted", f"unexpected marker value {value!r}"
    latency = time.monotonic() - start

    modify_at = time.time()
    ddb.update_item(TableName=table, Key={"pk": {"S": "insert-item"}},
                     UpdateExpression="SET v = :v", ExpressionAttributeValues={":v": {"S": "2"}})
    deadline = time.monotonic() + max(30.0, 5 * latency)
    while time.monotonic() < deadline:
        seen = _log_lines_mentioning(logs, log_group, modify_at, "MODIFY")
        assert seen == [], (
            f"the FilterCriteria must keep a MODIFY record out of the function; saw {seen!r}")
        time.sleep(2.0)

    # Barrier: a later insert still reaches the function, and the MODIFY still never did.
    ddb.put_item(TableName=table, Item={"pk": {"S": "barrier-item"}, "v": {"S": "1"}})
    value = _poll(lambda: _get_parameter(ssm, f"{marker_prefix}barrier-item"), lambda v: v is not None,
                  timeout_s=120.0, interval_s=2.0, what="marker written for the barrier item")
    assert value == "inserted", f"unexpected barrier marker value {value!r}"
    seen = _log_lines_mentioning(logs, log_group, modify_at, "MODIFY")
    assert seen == [], f"a MODIFY record reached the function after all: {seen!r}"

    roles = _stack_roles(cfn, described["StackId"])
    assert len(roles) == 1, f"expected the function's execution role, got {roles!r}"
    _delete_stack(cfn, described["StackId"])
    code, message = _error(lambda: ddb.describe_table(TableName=table))
    assert code == "ResourceNotFoundException", f"table survived delete: {code!r}"
    assert message == f"Requested resource not found: Table: {table} not found", (
        f"unexpected message {message!r}")
    good_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    code, message = _error(lambda: lam.get_function(FunctionName=fn))
    assert code == "ResourceNotFoundException", f"function survived delete: {code!r}"
    assert message == f"Function not found: {good_arn}", f"unexpected message {message!r}"
    code, message = _error(lambda: lam.get_event_source_mapping(UUID=mapping["UUID"]))
    assert (code, message) == ("ResourceNotFoundException", "The resource you requested does not exist."), (
        f"the stream mapping after the delete: {(code, message)!r}")
    _assert_roles_gone(ctx.client("iam"), roles)


def _log_lines_mentioning(logs, log_group: str, after: float, needle: str) -> list:
    """Every log event in ``log_group`` after ``after`` whose message contains ``needle``."""
    try:
        pages = logs.get_paginator("filter_log_events").paginate(
            logGroupName=log_group, startTime=int(after * 1000), filterPattern=f'"{needle}"')
        return [e["message"] for page in pages for e in page["events"]]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise


def _get_parameter(ssm, name: str) -> str | None:
    try:
        return ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ParameterNotFound":
            return None
        raise


def _wait_for_mapping_enabled(lam, fn: str, stream_arn: str) -> None:
    def state():
        mappings = lam.list_event_source_mappings(FunctionName=fn, EventSourceArn=stream_arn)[
            "EventSourceMappings"]
        return mappings[0]["State"] if mappings else None

    _poll(state, lambda s: s == "Enabled", timeout_s=90.0, interval_s=2.0,
          what="event source mapping enabled")


def _ignore_not_found(fn, *codes: str) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
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
