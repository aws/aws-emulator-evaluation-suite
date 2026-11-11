"""deploy-cdk-table-stream-consumer-missing-sink-grant-blocks-propagation."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "deploy-cdk-table-stream-consumer-missing-sink-grant-blocks-propagation"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "lambda"]

_APP = Path(__file__).parent / "deployments" / "cdk_stream_consumer_missing_grant"
_CLI_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 600.0
_REPAIR_POLICY_NAME = "sim2real-sinkbad-repair"
# IAM propagation into a Lambda execution environment can take minutes.
_REPAIR_DEADLINE_S = 600.0


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:deploy", "concern:negative-classes",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of two `cdk deploy`ed consumers of one table stream, the one never granted PutItem on its
    sink is refused with DynamoDB's exact AccessDeniedException and lands nothing while its sibling
    delivers; granting the permission lets its next insert through.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    logs = ctx.client("logs")
    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkmissgrant-")
    work = _stage(ctx, _APP)

    ctx.on_cleanup(lambda: _final_sweep(ctx, qualifier, toolkit, stack))
    _bootstrap(ctx, qualifier, toolkit)
    # The functions' L2s mint their own log groups, which outlive the stack delete: reap them once
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
    source = outputs["SourceTableName"]
    sink_good, sink_bad = outputs["SinkGoodTableName"], outputs["SinkBadTableName"]
    sink_bad_arn = outputs["SinkBadTableArn"]
    good_fn, bad_fn = outputs["GoodFunctionName"], outputs["BadFunctionName"]
    bad_role = outputs["BadRoleName"]
    log_groups += [f"/aws/lambda/{good_fn}", f"/aws/lambda/{bad_fn}"]
    lam = ctx.client("lambda")
    roles = sorted(r["PhysicalResourceId"]
                   for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
                   if r["ResourceType"] == "AWS::IAM::Role")
    assert bad_role in roles, f"the BadConsumer role {bad_role!r} is not among the stack's {roles!r}"
    mapping_uuids = []
    for fn in (good_fn, bad_fn):
        mappings = lam.list_event_source_mappings(FunctionName=fn)["EventSourceMappings"]
        assert len(mappings) == 1, f"expected one stream mapping on {fn!r}, got {mappings!r}"
        mapping_uuids.append(mappings[0]["UUID"])

    batch1 = [ctx.unique_name(f"item-1-{i}-") for i in range(3)]
    for key in batch1:
        ddb.put_item(TableName=source, Item={"pk": {"S": key}})
    latency_s, _ = _latency(lambda: _all_present(ddb, sink_good, batch1), budget_s=180.0)

    # A second, independent good-side delivery: a sustained good side, not a single lucky one.
    batch2 = [ctx.unique_name(f"item-2-{i}-") for i in range(2)]
    for key in batch2:
        ddb.put_item(TableName=source, Item={"pk": {"S": key}})
    _latency(lambda: _all_present(ddb, sink_good, batch2), budget_s=180.0)

    leaked = _absent_for(
        lambda: [k for k in batch1 + batch2
                if ddb.get_item(TableName=sink_bad, Key={"pk": {"S": k}},
                                ConsistentRead=True).get("Item") is not None],
        latency_s)
    assert leaked == [], (
        f"items {leaked!r} appeared in the never-granted sink table {sink_bad!r}; the missing "
        f"PutItem grant must block delivery there while the sibling consumer keeps delivering "
        f"to {sink_good!r}")

    code, message = _wait_denied_log(logs, bad_fn, budget_s=180.0)
    assert code == "AccessDeniedException", (
        f"the BadConsumer function's log carries denied_code {code!r}, expected "
        f"'AccessDeniedException'")
    # Lambda assumes the execution role under a session named after the function.
    want = (f"User: arn:aws:sts::{ctx.account}:assumed-role/{bad_role}/{bad_fn} is not authorized "
            f"to perform: dynamodb:PutItem on resource: {sink_bad_arn} because no identity-based "
            f"policy allows the dynamodb:PutItem action")
    assert message == want, (
        f"the denied PutItem message is {message!r}, expected {want!r}")

    iam.put_role_policy(
        RoleName=bad_role, PolicyName=_REPAIR_POLICY_NAME,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "dynamodb:PutItem",
                           "Resource": sink_bad_arn}]}))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=bad_role, PolicyName=_REPAIR_POLICY_NAME),
        "NoSuchEntity"))

    repaired_key, repaired_item = _wait_repaired(ctx, ddb, source, sink_bad)
    assert repaired_item == {"pk": {"S": repaired_key}}, (
        f"after granting the missing PutItem permission, the sink table's row for "
        f"{repaired_key!r} is {repaired_item!r}, expected just its key")

    _cdk(ctx, work, ["destroy", "--force", "--toolkit-stack-name", toolkit], qualifier, stack,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)

    final = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert final == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"DescribeStacks on {stack!r} after `cdk destroy --force` raised {final!r}")
    for name, table in (("source", source), ("sink_good", sink_good), ("sink_bad", sink_bad)):
        gone = _error(lambda t=table: ddb.describe_table(TableName=t))
        assert gone == ("ResourceNotFoundException",
                        f"Requested resource not found: Table: {table} not found"), (
            f"DescribeTable on the destroyed {name} table {table!r} raised {gone!r}")
    for fn in (good_fn, bad_fn):
        _reap_log_group(logs, f"/aws/lambda/{fn}")
        fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
        gone = _error(lambda f=fn: lam.get_function(FunctionName=f))
        assert gone == ("ResourceNotFoundException", f"Function not found: {fn_arn}"), (
            f"GetFunction on the destroyed function {fn!r} raised {gone!r}")
    for uuid in mapping_uuids:
        gone = _error(lambda u=uuid: lam.get_event_source_mapping(UUID=u))
        assert gone == ("ResourceNotFoundException", "The resource you requested does not exist."), (
            f"GetEventSourceMapping on a destroyed stream mapping raised {gone!r}")
    for role in roles:
        gone = _error(lambda r=role: iam.get_role(RoleName=r))
        assert gone == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
            f"GetRole on the destroyed execution role {role!r} raised {gone!r}")


def _all_present(ddb, table: str, keys: list[str]) -> bool:
    return all(ddb.get_item(TableName=table, Key={"pk": {"S": k}}, ConsistentRead=True).get("Item")
              is not None for k in keys)


def _latency(observe, *, budget_s: float = 120.0, poll_s: float = 2.0) -> tuple[float, bool]:
    """Seconds until `observe()` first returns truthy; raises if it never does within budget_s."""
    start = time.monotonic()
    while True:
        result = observe()
        if result:
            return time.monotonic() - start, result
        if time.monotonic() - start > budget_s:
            raise AssertionError(f"the positive control saw nothing in {budget_s}s")
        time.sleep(poll_s)


def _absent_for(observe, latency_s: float, *, factor: float = 3.0, floor_s: float = 10.0,
                poll_s: float = 2.0) -> list:
    """Everything `observe()` returned over `max(floor_s, factor * latency_s)` seconds."""
    window = max(floor_s, factor * latency_s)
    deadline = time.monotonic() + window
    seen: list = []
    while True:
        seen.extend(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


def _wait_denied_log(logs, function: str, *, budget_s: float) -> tuple[str, str]:
    """(code, message) from the first `denied_code` line the function's log group carries."""
    group = f"/aws/lambda/{function}"
    deadline = time.monotonic() + budget_s
    while True:
        try:
            events = [e for page in logs.get_paginator("filter_log_events").paginate(
                logGroupName=group) for e in page["events"]]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            events = []
        for e in events:
            start = e["message"].find('{"denied_code"')
            if start >= 0:
                end = e["message"].rfind("}") + 1
                payload = json.loads(e["message"][start:end])
                return payload["denied_code"], payload["denied_message"]
        if time.monotonic() > deadline:
            raise AssertionError(
                f"log group {group} carries no 'denied_code' line within {budget_s}s; events "
                f"seen: {[e['message'] for e in events]!r}")
        time.sleep(2.0)


def _wait_repaired(ctx, ddb, source: str, sink_bad: str, *,
                   deadline_s: float = _REPAIR_DEADLINE_S) -> tuple[str, dict]:
    """Insert a fresh key into `source` until it appears in `sink_bad`: IAM propagation is
    asynchronous, and the stream delivers each key once, so a retry needs a new key."""
    deadline = time.monotonic() + deadline_s
    while True:
        key = ctx.unique_name("repaired-")
        ddb.put_item(TableName=source, Item={"pk": {"S": key}})
        probe_deadline = time.monotonic() + 15.0
        while time.monotonic() < probe_deadline:
            item = ddb.get_item(TableName=sink_bad, Key={"pk": {"S": key}},
                                ConsistentRead=True).get("Item")
            if item is not None:
                return key, item
            time.sleep(2.0)
        if time.monotonic() > deadline:
            raise AssertionError(
                f"no insert into {source!r} reached {sink_bad!r} within {deadline_s}s of "
                f"granting the missing permission")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


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
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkmissgrant-"))
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
    boot = Path(tempfile.mkdtemp(prefix="sim2real-cdkmissgrant-boot-"))
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
