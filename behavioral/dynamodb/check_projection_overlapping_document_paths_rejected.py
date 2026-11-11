"""projection-overlapping-document-paths-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "projection-overlapping-document-paths-rejected"
GROUP = "item_crud"
SERVICES = ["dynamodb"]

ERR_VALIDATION = "ValidationException"
_OVERLAP_PREFIX = (
    "Invalid ProjectionExpression: Two document paths overlap with each other; "
    "must remove or rewrite one of these paths; "
)


def _error(fn) -> tuple[str | None, str | None]:
    """Return (code, message) for a rejected call; fail loudly if it SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Overlapping ProjectionExpression paths (same path twice, or parent plus descendant, also via
    aliases) are rejected with ValidationException naming both resolved paths; siblings are served.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)

    ddb.put_item(
        TableName=table,
        Item={
            "pk": {"S": "overlap"},
            "doc": {"M": {"keep": {"S": "k"}, "zeta": {"S": "z"}}},
        },
    )

    def _reject(expr: str, names: dict | None = None):
        kwargs = dict(
            TableName=table,
            Key={"pk": {"S": "overlap"}},
            ConsistentRead=True,
            ProjectionExpression=expr,
        )
        if names:
            kwargs["ExpressionAttributeNames"] = names
        return _error(lambda: ddb.get_item(**kwargs))

    # --- the same raw path twice ---
    code, msg = _reject("doc, doc")
    assert code == ERR_VALIDATION, f"'doc, doc' must be rejected with {ERR_VALIDATION}; got {code}"
    assert msg == _OVERLAP_PREFIX + "path one: [doc], path two: [doc]", (
        "the overlap message must name both paths in resolved bracketed form; "
        f"got {msg!r}"
    )

    # --- a parent alongside its own child ---
    code, msg = _reject("doc, doc.keep")
    assert code == ERR_VALIDATION, (
        f"'doc, doc.keep' must be rejected with {ERR_VALIDATION}; got {code}"
    )
    assert msg == _OVERLAP_PREFIX + "path one: [doc], path two: [doc, keep]", (
        "a parent/descendant overlap must render the child path with every segment; "
        f"got {msg!r}"
    )

    # --- the same attribute reached via an alias on one side only ---
    code, msg = _reject("doc, #d", {"#d": "doc"})
    assert code == ERR_VALIDATION, (
        f"a raw path and an alias for the same attribute must overlap; got {code}"
    )
    assert msg == _OVERLAP_PREFIX + "path one: [doc], path two: [doc]", (
        "overlap is decided on the RESOLVED name and the message must render the resolved "
        f"name, not the alias; got {msg!r}"
    )

    # --- the same alias twice ---
    code, msg = _reject("#d, #d", {"#d": "doc"})
    assert code == ERR_VALIDATION, f"the same alias twice must overlap; got {code}"
    assert msg == _OVERLAP_PREFIX + "path one: [doc], path two: [doc]", (
        f"got {msg!r}"
    )

    # --- the rejection precedes the read: it fires on a key that does not exist ---
    absent_code, absent_msg = _error(
        lambda: ddb.get_item(
            TableName=table,
            Key={"pk": {"S": "no-such-item"}},
            ConsistentRead=True,
            ProjectionExpression="doc, doc.keep",
        )
    )
    assert absent_code == ERR_VALIDATION, (
        "projection overlap must be validated BEFORE the item lookup, so it rejects even "
        f"for a key that does not exist; got {absent_code}"
    )
    assert absent_msg == _OVERLAP_PREFIX + "path one: [doc], path two: [doc, keep]", (
        f"got {absent_msg!r}"
    )

    # --- control: two siblings under one parent do not overlap and are served ---
    # A refusal here is a divergence, so report it as an assertion failure.
    try:
        ok = ddb.get_item(
            TableName=table,
            Key={"pk": {"S": "overlap"}},
            ConsistentRead=True,
            ProjectionExpression="doc.keep, doc.zeta",
        )["Item"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            "'doc.keep, doc.zeta' are non-overlapping siblings and must be SERVED, but the "
            f"target refused them with {err.get('Code')}: {err.get('Message')}"
        ) from None
    assert ok == {"doc": {"M": {"keep": {"S": "k"}, "zeta": {"S": "z"}}}}, (
        "two non-overlapping sibling paths under one parent must be ACCEPTED and both "
        f"returned -- the rule is prefix overlap, not a shared first segment; got {ok!r}"
    )

    # --- control: an ordinary read still works after the rejections ---
    full = ddb.get_item(
        TableName=table, Key={"pk": {"S": "overlap"}}, ConsistentRead=True
    )["Item"]
    assert set(full) == {"pk", "doc"}, (
        f"an unprojected read must still carry every attribute; got {sorted(full)}"
    )


def _create_table(ctx, ddb) -> str:
    name = ctx.unique_name("sim2real-behav-projovl-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _wait_table_active(ddb, name)
    return name


def _wait_table_active(ddb, name: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {name} never became ACTIVE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
