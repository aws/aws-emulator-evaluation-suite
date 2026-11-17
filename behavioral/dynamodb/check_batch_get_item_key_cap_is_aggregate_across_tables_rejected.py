"""batch-get-item-key-cap-is-aggregate-across-tables-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-item-key-cap-is-aggregate-across-tables-rejected"
GROUP = "batch"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises.

    An unexpected success raises too, naming what came back.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetItem's 100-key cap is a sum across every table in the request: 60 keys on one
    table plus 41 on another (101 total, neither table alone over 100) is refused, and the
    identical shape at exactly 100 combined keys succeeds.
    """
    ddb = ctx.client("dynamodb")
    table_a = ctx.unique_name("sim2real-behav-bgicapa-")
    table_b = ctx.unique_name("sim2real-behav-bgicapb-")
    for table in (table_a, table_b):
        ddb.create_table(
            TableName=table,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(
            _teardown(lambda t=table: ddb.delete_table(TableName=t), "ResourceNotFoundException")
        )
    for table in (table_a, table_b):
        ddb.get_waiter("table_exists").wait(
            TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250}
        )

    ddb.put_item(TableName=table_a, Item={"pk": {"S": "a0"}, "val": {"S": "canary-a"}})
    ddb.put_item(TableName=table_b, Item={"pk": {"S": "b0"}, "val": {"S": "canary-b"}})

    keys_a_60 = [{"pk": {"S": f"a{i}"}} for i in range(60)]
    keys_b_41 = [{"pk": {"S": f"b{i}"}} for i in range(41)]
    keys_b_40 = keys_b_41[:40]

    code, message = _error(lambda: ddb.batch_get_item(
        RequestItems={table_a: {"Keys": keys_a_60}, table_b: {"Keys": keys_b_41}}
    ))
    assert code == "ValidationException", (
        f"60 keys on {table_a!r} plus 41 on {table_b!r} (101 combined, neither table over 100) "
        f"got {code!r}, expected ValidationException"
    )
    expected_message = "Too many items requested for the BatchGetItem call"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    resp = ddb.batch_get_item(
        RequestItems={table_a: {"Keys": keys_a_60}, table_b: {"Keys": keys_b_40}}
    )
    unprocessed = resp.get("UnprocessedKeys", {})
    assert unprocessed == {}, (
        f"the identical shape at exactly 100 combined keys must not be refused or partial, got "
        f"UnprocessedKeys {unprocessed!r}"
    )
    canary_a = {item["pk"]["S"]: item["val"]["S"] for item in resp["Responses"][table_a]}.get("a0")
    canary_b = {item["pk"]["S"]: item["val"]["S"] for item in resp["Responses"][table_b]}.get("b0")
    assert (canary_a, canary_b) == ("canary-a", "canary-b"), (
        f"the 100-combined-key call succeeded but did not return the stored canaries: "
        f"{(canary_a, canary_b)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
