"""cdk-import-mapping-file-adopts-a-table-with-its-item-and-refuses-a-missing-one."""

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

CHECK = "cdk-import-mapping-file-adopts-a-table-with-its-item-and-refuses-a-missing-one"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

_APP = "cdk_import_table"
_TAG_KEY = "sim2real-stage"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """`cdk import` from a mapping file adopts a table made out of band, its id and item intact.

    A mapping naming a missing table is refused and leaves the stack unchanged; a later
    `cdk deploy` that adds a tag updates the adopted table in place.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/ref-cli-cmd-import.html
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    stack = ctx.unique_name("sim2real-cdk-imptbl-")
    table = ctx.unique_name("sim2real-cdk-imptbl-")
    missing = ctx.unique_name("sim2real-cdk-imptbl-missing-")
    tag_value = ctx.unique_name("v-")
    base = {"stack_name": stack, "account": ctx.account, "region": ctx.region}
    work = _stage_app(ctx)

    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        _teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException")
    )
    born = _poll_until(
        lambda: ddb.describe_table(TableName=table)["Table"],
        lambda t: t["TableStatus"] == "ACTIVE",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"table {table} ACTIVE",
    )
    key = {"pk": {"S": "seed"}}
    marker = ctx.unique_name("marker-")
    ddb.put_item(TableName=table, Item={**key, "marker": {"S": marker}})
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(
        ctx,
        work,
        ["deploy", stack, "--require-approval", "never"],
        {**base, "table_name": table, "with_table": "0"},
    )
    assert rc == 0, f"the first deploy exited {rc}; output tail {out[-800:]!r}"
    stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]

    rc, out = _cdk(
        ctx,
        work,
        ["import", stack, "--resource-mapping", str(_mapping_file(work, "missing", missing))],
        {**base, "table_name": missing, "with_table": "1"},
    )
    assert rc == 1, f"`cdk import` of a missing table exited {rc}; output tail {out[-800:]!r}"
    failed_cs = [
        c for c in cfn.list_change_sets(StackName=stack_id)["Summaries"] if c["Status"] == "FAILED"
    ]
    assert len(failed_cs) == 1, f"expected one FAILED change set, got {failed_cs!r}"
    described_cs = cfn.describe_change_set(
        StackName=stack_id, ChangeSetName=failed_cs[0]["ChangeSetId"]
    )
    reason = f"Table: {missing} does not exist."
    assert (described_cs["Status"], described_cs["StatusReason"]) == ("FAILED", reason), (
        f"the missing table's change set is {described_cs!r}"
    )
    # cdk prints the DeploymentError's message twice: once in its own ❌ summary, once more
    # when node dumps the uncaught error object; both carry this line verbatim.
    cli_lines = [line.strip() for line in out.splitlines() if reason in line]
    assert cli_lines == [reason, reason], (
        f"`cdk import` reported the refusal as {cli_lines!r}; output tail {out[-800:]!r}"
    )
    after = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert (after, _resources(cfn, stack_id)) == (
        "CREATE_COMPLETE",
        {"Handle": ("CREATE_COMPLETE", _handle_id(cfn, stack_id))},
    ), f"the refused import left the stack {after!r} with {_resources(cfn, stack_id)!r}"
    absent = _client_error(lambda: ddb.describe_table(TableName=missing))
    assert (absent["Code"], absent["Message"]) == (
        "ResourceNotFoundException",
        f"Requested resource not found: Table: {missing} not found",
    ), f"DescribeTable on the missing table answered {absent!r}"

    rc, out = _cdk(
        ctx,
        work,
        ["import", stack, "--resource-mapping", str(_mapping_file(work, "existing", table))],
        {**base, "table_name": table, "with_table": "1"},
    )
    assert rc == 0, f"`cdk import` of the existing table exited {rc}; output tail {out[-800:]!r}"
    after = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert after == "IMPORT_COMPLETE", f"the import left the stack {after!r}"
    # The import applies stack-level tags to the imported resource as an update of its own.
    adopted = _poll_until(
        lambda: cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Table")[
            "StackResourceDetail"
        ],
        lambda r: _past_import(r["ResourceStatus"]),
        timeout_s=180.0,
        interval_s=5.0,
        description=f"the imported table's stack-level tag update on {stack}",
    )
    assert adopted["ResourceStatus"] == "UPDATE_COMPLETE", (
        f"the imported table's stack resource is {adopted!r}"
    )
    mapped = _resources(cfn, stack_id)
    assert (sorted(mapped), mapped["Table"][1]) == (["Handle", "Table"], table), (
        f"DescribeStackResources after the import maps {mapped!r}"
    )
    _assert_same_table(ddb, table, born["TableId"], key, marker, "after the import")

    rc, out = _cdk(
        ctx,
        work,
        ["deploy", stack, "--require-approval", "never"],
        {**base, "table_name": table, "with_table": "1", "tag_value": tag_value},
    )
    assert rc == 0, f"the tagging deploy exited {rc}; output tail {out[-800:]!r}"
    after = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert after == "UPDATE_COMPLETE", f"the tagging deploy left the stack {after!r}"
    tags_now = _poll_until(
        lambda: {
            t["Key"]: t["Value"]
            for t in ddb.list_tags_of_resource(ResourceArn=born["TableArn"]).get("Tags", [])
        },
        lambda t: _TAG_KEY in t,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"tag {_TAG_KEY} on {table}",
    )
    assert tags_now[_TAG_KEY] == tag_value, (
        f"ListTagsOfResource shows {_TAG_KEY}={tags_now[_TAG_KEY]!r}, expected {tag_value!r}"
    )
    _assert_same_table(ddb, table, born["TableId"], key, marker, "after the tagging deploy")


def _assert_same_table(ddb, table: str, table_id: str, key: dict, marker: str, when: str) -> None:
    """The table keeps its TableId and its pre-existing item: adopted, never re-created."""
    now = ddb.describe_table(TableName=table)["Table"]["TableId"]
    assert now == table_id, f"{when}: TableId moved {table_id!r} -> {now!r}, so it was re-created"
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert item == {**key, "marker": {"S": marker}}, f"{when}: the seeded item reads {item!r}"


def _mapping_file(work: Path, label: str, table: str) -> Path:
    """A `--resource-mapping` file mapping the Table logical id to ``table``."""
    path = work / f"mapping-{label}.json"
    path.write_text(json.dumps({"Table": {"TableName": table}}))
    return path


def _handle_id(cfn, stack_id: str) -> str:
    """The wait-condition handle's physical id, which the refused import must leave alone."""
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Handle")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _past_import(status: str) -> bool:
    """True once the resource has left its import states for a terminal status."""
    return not status.endswith("_IN_PROGRESS") and status != "IMPORT_COMPLETE"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy and return it; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _resources(cfn, stack_id: str) -> dict[str, tuple[str, str]]:
    """{logical id: (status, physical id)} of the stack's resources."""
    return {
        r["LogicalResourceId"]: (r["ResourceStatus"], r["PhysicalResourceId"])
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _client_error(fn) -> dict:
    """The error a call raises, as its response Error dict; raises if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("the call succeeded but was expected to be refused")


def _stage_app(ctx) -> Path:
    """Copy the CDK app into a temp dir so cdk.out and the mapping files stay out of the repo."""
    source = Path(__file__).parent / "deployments" / _APP
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is missing app.py or cdk.json"
    )
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdk-app-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(source, work / _APP, ignore=shutil.ignore_patterns("cdk.out", "__pycache__"))
    return work / _APP


def _cdk(
    ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float = 600.0
) -> tuple[int, str]:
    """Run the CDK CLI against the target; returns (exit code, stdout + stderr)."""
    cmd = [
        "cdk",
        *args,
        "--app",
        f"{sys.executable} app.py",
        "--ci",
        "--no-color",
        "--no-notices",
        "--no-version-reporting",
    ]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    done = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    return done.returncode, done.stdout + done.stderr


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
        time.sleep(5.0)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
