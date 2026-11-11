"""transact-write-items-put-string-set-with-zero-members-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-put-string-set-with-zero-members-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error_code(fn, what: str) -> tuple[str, str, dict]:
    """The AWS error code, message and response `fn` raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response
    raise AssertionError(f"{what}: the call was ACCEPTED with {result!r}; real AWS rejects it")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems Put whose string set has zero members is a top-level
    ValidationException with no CancellationReasons, and a sibling Put in the same
    call does not land either."""
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddbtxss0-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- positive control: a sibling Put with a legal single-empty-string-member SS commits
    # on its own, so the rejection below is about the empty set, not about TransactWriteItems
    # refusing every SS it sees ---
    ddb.transact_write_items(TransactItems=[
        {"Put": {"TableName": t, "Item": {"pk": {"S": "control"}, "tags": {"SS": [""]}}}},
    ])
    control = ddb.get_item(TableName=t, Key={"pk": {"S": "control"}}, ConsistentRead=True).get("Item", {})
    assert control.get("tags") == {"SS": [""]}, (
        f"positive control: a single-empty-string-member SS must commit and read back unchanged, "
        f"got {control.get('tags')!r}"
    )

    # --- the probe: a zero-member SS beside a legal sibling Put, in one TransactWriteItems call ---
    expected_message = "One or more parameter values were invalid: An string set  may not be empty"
    code, message, resp = _error_code(lambda: ddb.transact_write_items(TransactItems=[
        {"Put": {"TableName": t, "Item": {"pk": {"S": "sibling"}, "v": {"S": "x"}}}},
        {"Put": {"TableName": t, "Item": {"pk": {"S": "bad"}, "tags": {"SS": []}}}},
    ]), "TransactWriteItems with a zero-member SS in one Put.Item beside a valid Put")
    assert code == ERR_VALIDATION, (
        f"a zero-member SS inside a TransactWriteItems Put must be {ERR_VALIDATION}, got {code!r}"
    )
    assert message == expected_message, (
        f"expected AWS's exact message {expected_message!r}, got {message!r}"
    )
    assert "CancellationReasons" not in resp, (
        f"a zero-member SS must be a top-level ValidationException with no CancellationReasons, "
        f"got {resp!r}"
    )

    sibling = ddb.get_item(TableName=t, Key={"pk": {"S": "sibling"}}, ConsistentRead=True)
    assert "Item" not in sibling, (
        f"the valid sibling Put must not land when the transaction is rejected top-level, "
        f"found {sibling.get('Item')!r}"
    )
    bad = ddb.get_item(TableName=t, Key={"pk": {"S": "bad"}}, ConsistentRead=True)
    assert "Item" not in bad, (
        f"the rejected zero-member SS Put must not land, found {bad.get('Item')!r}"
    )

    scanned = ddb.scan(TableName=t, ConsistentRead=True, Select="COUNT")
    assert scanned["Count"] == 1, (
        f"only the control item may exist after the rejected transaction, got "
        f"{scanned['Count']!r} items"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
