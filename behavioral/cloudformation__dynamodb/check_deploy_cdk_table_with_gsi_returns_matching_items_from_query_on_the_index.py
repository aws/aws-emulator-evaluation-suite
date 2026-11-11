"""deploy-cdk-table-with-gsi-returns-matching-items-from-query-on-the-index."""
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

CHECK = "deploy-cdk-table-with-gsi-returns-matching-items-from-query-on-the-index"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

_APP = Path(__file__).parent / "deployments" / "cdk_gsi_query"
_CLI_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 600.0
_INDEX_BUDGET_S = 60.0


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:data-plane", "concern:representation",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A `cdk deploy`ed table's global secondary index answers `Query` by its own key with exactly
    the items put under that key; `cdk destroy` removes the table.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkgsi-")
    work = _stage(ctx, _APP)

    # The bootstrap staging bucket and toolkit stack outlive `cdk destroy` of the app stack, so
    # this net is registered first (LIFO: runs last) and reads the app stack's own final state.
    ctx.on_cleanup(lambda: _final_sweep(ctx, qualifier, toolkit, stack))
    _bootstrap(ctx, qualifier, toolkit)
    # Safety net only: the graded teardown is the in-band `cdk destroy` below.
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))

    rc, out = _cdk(ctx, work, ["deploy", "--require-approval", "never",
                               "--toolkit-stack-name", toolkit], qualifier, stack)
    assert rc == 0, f"`cdk deploy` exited {rc}; output tail {out[-1200:]!r}"

    stack_desc = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert stack_desc["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {stack_desc['StackStatus']!r} after `cdk deploy`: "
        f"{stack_desc.get('StackStatusReason')!r}")
    table = _outputs(stack_desc)["TableName"]

    described = ddb.describe_table(TableName=table)["Table"]
    gsis = [(g["IndexName"], g["KeySchema"], g["Projection"]["ProjectionType"])
            for g in described.get("GlobalSecondaryIndexes", [])]
    assert gsis == [("ByGk", [{"AttributeName": "gk", "KeyType": "HASH"}], "ALL")], (
        f"DescribeTable on {table!r} reports GSIs {gsis!r}, expected the one declared GSI")

    group_a = {ctx.unique_name(f"pk-a{i}-"): str(i) for i in range(3)}
    group_b = {ctx.unique_name(f"pk-b{i}-"): str(i) for i in range(2)}
    for pk, v in {**group_a, **group_b}.items():
        gk = "group-a" if pk in group_a else "group-b"
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "gk": {"S": gk}, "v": {"N": v}})

    # A GSI is eventually consistent with its table: poll until it converges, bounded.
    found = _poll(lambda: _query_index(ddb, table, "group-a"), lambda got: got == group_a,
                  timeout_s=_INDEX_BUDGET_S)
    assert found == group_a, (
        f"Query on ByGk for gk='group-a' returned items {found!r}; expected exactly {group_a!r} "
        f"(the items put with gk='group-b' must not appear)")

    _cdk(ctx, work, ["destroy", "--force", "--toolkit-stack-name", toolkit], qualifier, stack,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)

    final = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert final == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"DescribeStacks on {stack!r} after `cdk destroy --force` raised {final!r}")

    gone = _error(lambda: ddb.describe_table(TableName=table))
    assert gone == ("ResourceNotFoundException",
                    f"Requested resource not found: Table: {table} not found"), (
        f"DescribeTable on the destroyed table {table!r} raised {gone!r}")


def _poll(probe, done, *, timeout_s: float, interval_s: float = 2.0):
    """The first probe() result done() accepts, or the last one once timeout_s has passed."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last) or time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)


def _query_index(ddb, table: str, gk: str) -> dict[str, str]:
    """Every {pk: v} the index returns for one gk value, paginated."""
    found: dict[str, str] = {}
    for page in ddb.get_paginator("query").paginate(
            TableName=table, IndexName="ByGk", KeyConditionExpression="gk = :g",
            ExpressionAttributeValues={":g": {"S": gk}}):
        for item in page["Items"]:
            found[item["pk"]["S"]] = item["v"]["N"]
    return found


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
    """Copy the CDK app to a temp workdir so cdk.out is not written beside the source."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkgsi-"))
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
    """`cdk bootstrap` under a per-run qualifier; what it creates is torn down by `_final_sweep`."""
    boot = Path(tempfile.mkdtemp(prefix="sim2real-cdkgsi-boot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(boot, ignore_errors=True))
    cmd = ["cdk", "bootstrap", f"aws://{ctx.account}/{ctx.region}", "--qualifier", qualifier,
           "--toolkit-stack-name", toolkit, "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
           "--ci", "--no-color", "--no-notices"]
    r = subprocess.run(cmd, cwd=boot, env=_cli_env(ctx), capture_output=True, text=True,
                        timeout=_CLI_TIMEOUT_S)
    assert r.returncode == 0, (
        f"`cdk bootstrap` exited {r.returncode}; output tail {(r.stdout + r.stderr)[-1200:]!r}")


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
    """Delete the bootstrap staging bucket and toolkit stack once the app stack is gone."""
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
