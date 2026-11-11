"""scan-all-projected-attributes-rejects-attributes-to-get."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-all-projected-attributes-rejects-attributes-to-get"
GROUP = "validation"
SERVICES = ["dynamodb"]

_GSI = "include-gsi"
ERR_VALIDATION = "ValidationException"
_MESSAGE = (
    "1 validation error detected: Cannot specify the AttributesToGet when choosing to get "
    "ALL_PROJECTED_ATTRIBUTES"
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_count(fn, want, *, timeout_s=120.0, interval_s=2.0):
    """*fn*'s result once its Count reaches *want*; a GSI write is eventually consistent."""
    deadline = time.monotonic() + timeout_s
    result = fn()
    while result.get("Count", 0) != want:
        if time.monotonic() >= deadline:
            raise AssertionError(f"Count never reached {want} within {timeout_s}s: {result!r}")
        time.sleep(interval_s)
        result = fn()
    return result


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scan with Select=ALL_PROJECTED_ATTRIBUTES on a global secondary index rejects a paired
    AttributesToGet, while the same Select alone still serves the index's projected attributes.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbscansel-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("pk", "sk", "gi")],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[{
            "IndexName": _GSI,
            "KeySchema": [{"AttributeName": "gi", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["kept"]},
        }],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={
        "pk": {"S": "p"}, "sk": {"S": "s"}, "gi": {"S": "g"}, "kept": {"S": "K"}, "excluded": {"S": "X"},
    })

    # Positive control: Select=ALL_PROJECTED_ATTRIBUTES alone succeeds and serves exactly the
    # index's projection, so the rejection below is attributable to AttributesToGet.
    control = _poll_count(
        lambda: ddb.scan(TableName=table, IndexName=_GSI, Select="ALL_PROJECTED_ATTRIBUTES"), 1,
    )["Items"][0]
    assert sorted(control) == ["gi", "kept", "pk", "sk"], (
        f"the control Scan must serve exactly the table key, the index key and 'kept', got "
        f"{sorted(control)!r}"
    )
    assert "excluded" not in control, f"the control leaked a non-projected attribute: {control!r}"

    # Break exactly one thing: the same request, with AttributesToGet added.
    code, message = _error(lambda: ddb.scan(
        TableName=table, IndexName=_GSI, Select="ALL_PROJECTED_ATTRIBUTES", AttributesToGet=["kept"],
    ))
    assert code == ERR_VALIDATION, (
        f"Scan Select=ALL_PROJECTED_ATTRIBUTES with AttributesToGet must be refused with "
        f"{ERR_VALIDATION}, got {code!r} ({message!r})"
    )
    assert message == _MESSAGE, f"expected AWS's exact ValidationException message, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
