"""deploy-dynamodb-1-cfn-global-table-bidirectional-then-replica-removal-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-dynamodb-1-cfn-global-table-bidirectional-then-replica-removal-rejected"
GROUP = "deploy-global-table"
SERVICES = ["dynamodb"]

_GT_VERSION = "2019.11.21"


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation AWS::DynamoDB::GlobalTable replicates items both ways between two regions.

    Dropping the replica via UpdateStack makes that region answer ResourceNotFoundException while
    the primary keeps every item, including those written in the removed region.
    """
    primary = ctx.region
    other = _second_region(ctx)
    ddb = ctx.client("dynamodb")
    away = ctx.client("dynamodb", region=other)
    cfn = ctx.client("cloudformation")

    table = ctx.unique_name("sim2real-ddbgt-")
    stack = ctx.unique_name("sim2real-ddbgt-stack-")

    # -- 1. deploy: one GlobalTable resource, the stack's own region plus ONE replica region.
    #    _deploy_cfn registers the DeleteStack teardown immediately after CreateStack returns,
    #    before any wait or assertion.
    _deploy_cfn(ctx, cfn, stack, _template(table, [primary, other]), table, [primary, other])
    _wait_stack(cfn, stack, "stack_create_complete", "CREATE")

    # -- 3. real traffic: write in the primary, read it eventually-consistently in the replica.
    token = ctx.unique_name("")
    item_p = {
        "pk": {"S": f"from-primary-{token}"},
        "origin": {"S": primary},
        "n": {"N": "7"},
        "tags": {"SS": ["a", "b"]},
    }
    ddb.put_item(TableName=table, Item=item_p)
    seen = _poll_get(away, table, item_p["pk"], consistent=False, budget_s=_budget_s(ctx, 300.0))
    if seen is None and _budget_spent(ctx):
        raise TimeoutError(f"the item replicating to {other!r}: the run budget ended first; not graded")
    assert seen == item_p, (
        f"item written in {primary!r} never replicated intact to {other!r} within 300 s: "
        f"last read there was {seen!r}, expected {item_p!r}"
    )

    # -- 4. both regions name each other as an ACTIVE replica of a 2019.11.21 global table.
    desc_p = _wait_replica_active(ddb, table, other, budget_s=_budget_s(ctx, 300.0))
    desc_o = _wait_replica_active(away, table, primary, budget_s=_budget_s(ctx, 300.0))
    for d, peer in ((desc_p, other), (desc_o, primary)):
        active = {r.get("RegionName"): r.get("ReplicaStatus") for r in d.get("Replicas", [])}.get(peer) == "ACTIVE"
        if not active and _budget_spent(ctx):
            raise TimeoutError(f"replica {peer!r} ACTIVE: the run budget ended first; not graded")
    for region, d, peer in ((primary, desc_p, other), (other, desc_o, primary)):
        assert d.get("GlobalTableVersion") == _GT_VERSION, (
            f"DescribeTable in {region!r} reports GlobalTableVersion "
            f"{d.get('GlobalTableVersion')!r}, expected {_GT_VERSION!r}"
        )
        statuses = {r.get("RegionName"): r.get("ReplicaStatus") for r in d.get("Replicas", [])}
        assert statuses.get(peer) == "ACTIVE", (
            f"DescribeTable in {region!r} lists replicas {statuses!r}; expected {peer!r} ACTIVE"
        )
        assert d.get("StreamSpecification", {}).get("StreamViewType") == "NEW_AND_OLD_IMAGES", (
            f"{region!r} StreamSpecification is {d.get('StreamSpecification')!r}"
        )
        billing = d.get("BillingModeSummary", {}).get("BillingMode")
        assert billing == "PAY_PER_REQUEST", f"{region!r} BillingMode is {billing!r}"

    # -- 5. control in the other direction: write in the replica, read it in the primary.
    item_o = {
        "pk": {"S": f"from-replica-{token}"},
        "origin": {"S": other},
        "n": {"N": "11"},
    }
    away.put_item(TableName=table, Item=item_o)
    back = _poll_get(ddb, table, item_o["pk"], consistent=False, budget_s=_budget_s(ctx, 300.0))
    if back is None and _budget_spent(ctx):
        raise TimeoutError(f"the item replicating back to {primary!r}: the run budget ended first; not graded")
    assert back == item_o, (
        f"item written in replica {other!r} never replicated intact back to {primary!r} within "
        f"300 s: last read there was {back!r}, expected {item_o!r}"
    )

    # -- 6. the one broken thing: UpdateStack drops the replica, keeping the primary table.
    cfn.update_stack(StackName=stack, TemplateBody=_template(table, [primary]))
    _wait_stack(cfn, stack, "stack_update_complete", "UPDATE")

    code, message = _poll_until_gone(away, table, budget_s=_budget_s(ctx, 600.0))
    if code.startswith("<table still present") and _budget_spent(ctx):
        raise TimeoutError(f"the {other!r} replica table leaving: the run budget ended first; not graded")
    assert code == "ResourceNotFoundException", (
        f"after UpdateStack removed the {other!r} replica, DescribeTable there returned "
        f"{code!r}, expected ResourceNotFoundException"
    )
    expected_message = f"Requested resource not found: Table: {table} not found"
    assert message == expected_message, (
        f"DescribeTable in {other!r} returned message {message!r}, expected {expected_message!r}"
    )
    get_code, get_message = _error(
        lambda: away.get_item(TableName=table, Key={"pk": item_p["pk"]}, ConsistentRead=False)
    )
    assert get_code == "ResourceNotFoundException", (
        f"GetItem against the removed replica in {other!r} returned {get_code!r}, "
        f"expected ResourceNotFoundException -- the replicated item must be gone with its table"
    )
    assert get_message == "Requested resource not found", (
        f"GetItem against the removed replica in {other!r} returned message {get_message!r}"
    )

    after = ddb.describe_table(TableName=table)["Table"]
    remaining = sorted(r.get("RegionName") for r in after.get("Replicas", []))
    assert other not in remaining, (
        f"primary still lists {other!r} among its replicas {remaining!r} after the update"
    )
    assert after.get("TableStatus") == "ACTIVE", (
        f"primary table status after replica removal is {after.get('TableStatus')!r}"
    )
    for want in (item_p, item_o):
        got = ddb.get_item(TableName=table, Key={"pk": want["pk"]}, ConsistentRead=True).get("Item")
        assert got == want, (
            f"primary {primary!r} lost data when the replica was removed: GetItem "
            f"{want['pk']!r} returned {got!r}, expected {want!r}"
        )

    # -- 8. tear the stack down now (the registered net stays as a backstop and is a no-op on
    #    a deleted stack), then prove neither region kept a table.
    _delete_stack(cfn, stack)
    for region, client in ((primary, ddb), (other, away)):
        gone, gone_message = _poll_until_gone(client, table, budget_s=_budget_s(ctx, 600.0))
        if gone.startswith("<table still present") and _budget_spent(ctx):
            raise TimeoutError(f"table {table!r} in {region!r} leaving: the run budget ended first; not graded")
        assert gone == "ResourceNotFoundException", (
            f"after DeleteStack, DescribeTable for {table!r} in {region!r} returned {gone!r}, "
            f"expected ResourceNotFoundException"
        )
        assert gone_message == expected_message, (
            f"after DeleteStack, DescribeTable in {region!r} returned message {gone_message!r}, "
            f"expected {expected_message!r}"
        )


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _template(table: str, regions: list) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "GlobalTable": {
                "Type": "AWS::DynamoDB::GlobalTable",
                "Properties": {
                    "TableName": table,
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    "StreamSpecification": {"StreamViewType": "NEW_AND_OLD_IMAGES"},
                    "Replicas": [
                        {"Region": r, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
                        for r in regions
                    ],
                },
            }
        },
    })


def _second_region(ctx) -> str:
    """The partner region: us-east-1, or us-west-2 when ctx.region is us-east-1. Both are
    enabled in every account, so choosing one needs no EC2 call and reads no account state."""
    return "us-east-1" if ctx.region != "us-east-1" else "us-west-2"


def _error(fn) -> tuple:
    """(code, message) of the AWS error fn raised. A call that SUCCEEDS returns a sentinel code no
    AWS code can equal."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 -- botocore ClientError carries the code
        resp = getattr(exc, "response", None)
        if isinstance(resp, dict):
            err = resp.get("Error", {})
            return err.get("Code") or f"<no code: {exc!r}>", err.get("Message")
        return f"<non-AWS exception: {exc!r}>", None
    return "<call unexpectedly succeeded>", None


def _poll_get(client, table: str, key_attr: dict, *, consistent: bool, budget_s: float):
    """GetItem until the item appears or the budget runs out; returns the last read (or None)."""
    deadline = time.monotonic() + budget_s
    delay = 1.0
    last = None
    while True:
        last = client.get_item(
            TableName=table, Key={"pk": key_attr}, ConsistentRead=consistent
        ).get("Item")
        if last is not None or time.monotonic() >= deadline:
            return last
        time.sleep(delay)
        delay = min(delay * 1.5, 2.0)


def _wait_replica_active(client, table: str, peer: str, *, budget_s: float) -> dict:
    """DescribeTable until the peer replica reads ACTIVE; returns the last description."""
    deadline = time.monotonic() + budget_s
    while True:
        d = client.describe_table(TableName=table)["Table"]
        st = {r.get("RegionName"): r.get("ReplicaStatus") for r in d.get("Replicas", [])}
        if st.get(peer) == "ACTIVE" or time.monotonic() >= deadline:
            return d
        time.sleep(2.0)


def _poll_until_gone(client, table: str, *, budget_s: float) -> tuple:
    """DescribeTable until it raises; returns that (code, message), or a sentinel code on timeout.

    A table mid-deletion still describes (TableStatus DELETING), so the poll waits it out rather
    than asserting on the first read.
    """
    deadline = time.monotonic() + budget_s
    while True:
        code, message = _error(lambda: client.describe_table(TableName=table))
        if code != "<call unexpectedly succeeded>":
            return code, message
        if time.monotonic() >= deadline:
            status = client.describe_table(TableName=table)["Table"].get("TableStatus")
            return f"<table still present after {budget_s:.0f}s, TableStatus={status!r}>", None
        time.sleep(2.0)


def _deploy_cfn(ctx, cfn, stack: str, body: str, table: str, regions: list) -> None:
    cfn.create_stack(
        StackName=stack, TemplateBody=body, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _cleanup_stack(ctx, stack, table, regions))


def _stack_failure_reasons(cfn, stack: str) -> list:
    try:
        events = cfn.describe_stack_events(StackName=stack)["StackEvents"]
    except Exception as exc:  # noqa: BLE001
        return [f"<describe_stack_events failed: {exc!r}>"]
    return [
        f"{e.get('LogicalResourceId')} {e.get('ResourceStatus')}: {e.get('ResourceStatusReason')}"
        for e in events
        if "FAILED" in (e.get("ResourceStatus") or "")
    ][:6]


def _wait_stack(cfn, stack: str, waiter_name: str, phase: str) -> None:
    try:
        cfn.get_waiter(waiter_name).wait(
            StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
        )
    except Exception as exc:  # noqa: BLE001 -- WaiterError; quote the stack's own reasons
        raise AssertionError(
            f"{phase} of stack {stack!r} did not complete: {exc!r}; "
            f"failure events: {_stack_failure_reasons(cfn, stack)!r}"
        ) from exc


def _delete_stack(cfn, stack: str) -> None:
    """Delete and wait. DeleteStack on an already-deleted stack name is a no-op success."""
    cfn.delete_stack(StackName=stack)
    _wait_stack(cfn, stack, "stack_delete_complete", "DELETE")


def _cleanup_stack(ctx, stack: str, table: str, regions: list) -> None:
    """Backstop teardown: wait out any in-flight operation, delete, then raise on a leftover.

    DeleteStack is refused while an UPDATE is in progress, so the stack is first allowed to
    settle (bounded). A failure raises so the leftover is reported.
    """
    _leaks: list = []
    cfn = ctx.client("cloudformation")
    try:
        deadline = time.monotonic() + 840
        while time.monotonic() < deadline:
            try:
                st = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
            except ClientError as err:
                # A stack that no longer exists is refused ValidationException "... does not exist".
                if err.response["Error"]["Code"] != "ValidationException" or "does not exist" not in str(err):
                    raise
                st = "GONE"
            if not st.endswith("_IN_PROGRESS") or st == "DELETE_IN_PROGRESS":
                break
            time.sleep(2)
        _delete_stack(cfn, stack)
    except Exception as exc:  # noqa: BLE001
        _leaks.append(
            (f"cloudformation stack {stack!r} (table {table!r} in {regions!r}): {exc!r}", exc)
        )
        if _leaks:
            raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
                (e for _, e in _leaks if e is not None), None
            )
        return
    for region in regions:
        try:
            ctx.client("dynamodb", region=region).describe_table(TableName=table)
            _leaks.append(
                (f"dynamodb table {table!r} still present in {region!r} after DeleteStack", None)
            )
        except ClientError as err:
            if err.response["Error"]["Code"] not in (
                "ResourceNotFoundException",
                "TableNotFoundException",
            ):
                raise
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
