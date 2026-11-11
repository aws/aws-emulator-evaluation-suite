"""cfn-rds-instance-invalid-engine-version-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-rds-instance-invalid-engine-version-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "rds"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    rows = []
    kwargs = {"StackName": stack_id}
    while True:
        page = cf.describe_stack_events(**kwargs)
        rows.extend(page["StackEvents"])
        token = page.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return rows[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----


def _poll_status(describe, extract_status, *, ok: set, bad: set, timeout_s: float,
                  interval_s: float = 5.0, description: str):
    """Poll ``describe()`` until ``extract_status`` is in ``ok``; raise on ``bad`` or timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        result = describe()
        status = extract_status(result)
        if status in ok:
            return result
        if status in bad:
            raise AssertionError(f"{description} reached {status!r}, expected one of {sorted(ok)}")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} still {status!r} after {timeout_s}s, expected one of {sorted(ok)}"
            )
        time.sleep(interval_s)


_BAD_VERSION = "0.0.1"
_REJECTED = (
    f"Cannot find version {_BAD_VERSION} for mysql (Service: Rds, Status Code: 400, "
    "Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(instance_id: str, subnet_group: str, engine_version: str | None) -> str:
    """A standalone DB instance, with ``DeletionPolicy: Delete`` so the control costs no snapshot."""
    props = {
        "DBInstanceIdentifier": instance_id,
        "Engine": "mysql",
        "DBInstanceClass": "db.t4g.micro",
        "AllocatedStorage": "20",
        "MasterUsername": "sim2realadmin",
        "ManageMasterUserPassword": True,
        "DBSubnetGroupName": subnet_group,
        "BackupRetentionPeriod": 0,
        "DeletionProtection": False,
        "PubliclyAccessible": False,
    }
    if engine_version is not None:
        props["EngineVersion"] = engine_version
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "DBInstance": {
                "Type": "AWS::RDS::DBInstance",
                "DeletionPolicy": "Delete",
                "Properties": props,
            },
        },
    })


def _delete_subnet_group(rds, name):
    """Delete the subnet group; only its own not-found fault means it never existed."""
    try:
        rds.delete_db_subnet_group(DBSubnetGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBSubnetGroupNotFoundFault":
            raise


def _create_subnet_group(ctx, rds) -> str:
    """An RDS DB subnet group over the run's own shared network, covering >=2 AZs."""
    subnet_ids = ctx.network().subnet_ids
    assert len(subnet_ids) >= 2, f"the run's network has subnets in only {len(subnet_ids)} AZ(s)"
    name = ctx.unique_name("sim2real-rds-dbsg-")
    ctx.on_cleanup(lambda: _delete_subnet_group(rds, name))
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real cfn provisioning check",
        SubnetIds=subnet_ids[:2],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    return name


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::RDS::DBInstance naming an EngineVersion RDS does not offer fails with RDS's exact
    message, the rollback leaves no instance, and the same template with a real version deploys.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html
    """
    cf = ctx.client("cloudformation")
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx, rds)

    # ---- Negative: an EngineVersion RDS does not offer for mysql. ----
    bad_instance_id = ctx.unique_name("sim2real-rds-badver-")
    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnrds-badverstk-"),
                          _template(bad_instance_id, subnet_group, _BAD_VERSION))
    bad_status = wait_stack(cf, bad_id)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"invalid-version stack settled at {bad_status!r}: "
        f"{decisive_rows(stack_events(cf, bad_id))!r}"
    )
    got = handler_reason(failed_reason(stack_events(cf, bad_id), "DBInstance"),
                         ctx.account, bad_instance_id)
    assert got == _REJECTED, f"the DBInstance CREATE_FAILED reason was {got!r}, expected {_REJECTED!r}"
    # The rollback itself left no instance, before this check deletes the stack.
    bad_not_found = ("DBInstanceNotFound", f"DBInstance {bad_instance_id} not found.")
    expect_error(lambda: rds.describe_db_instances(DBInstanceIdentifier=bad_instance_id),
                 *bad_not_found)
    delete_stack(cf, bad_id)

    # ---- Positive control: the same template, same subnet group, no EngineVersion override. ----
    good_instance_id = ctx.unique_name("sim2real-rds-goodver-")
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnrds-goodverstk-"),
                           _template(good_instance_id, subnet_group, None))
    good_status = wait_stack(cf, good_id, timeout_s=1500.0)
    assert good_status == "CREATE_COMPLETE", (
        f"control stack settled at {good_status!r}: {decisive_rows(stack_events(cf, good_id))!r}"
    )
    instance = _poll_status(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=good_instance_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"],
        ok={"available"},
        bad={"failed", "incompatible-parameters", "incompatible-network"},
        timeout_s=900.0,
        description=f"DB instance {good_instance_id}",
    )
    assert instance["Engine"] == "mysql", f"RDS reports engine {instance['Engine']!r}, expected 'mysql'"

    delete_stack(cf, good_id)
    good_not_found = ("DBInstanceNotFound", f"DBInstance {good_instance_id} not found.")
    expect_error(lambda: rds.describe_db_instances(DBInstanceIdentifier=good_instance_id),
                 *good_not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
