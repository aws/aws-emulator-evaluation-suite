"""create-table-with-six-local-secondary-indexes-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-with-six-local-secondary-indexes-rejected"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS raises rather than returning a
    falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_table_if_exists(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _lsi_set(n, prefix):
    key_schema = [{"AttributeName": "pk", "KeyType": "HASH"}]
    attribute_definitions = [{"AttributeName": "pk", "AttributeType": "S"}]
    indexes = []
    for i in range(n):
        sort_attr = f"{prefix}{i}"
        attribute_definitions.append({"AttributeName": sort_attr, "AttributeType": "S"})
        indexes.append(
            {
                "IndexName": f"{prefix}idx{i}",
                "KeySchema": [
                    {"AttributeName": "pk", "KeyType": "HASH"},
                    {"AttributeName": sort_attr, "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "KEYS_ONLY"},
            }
        )
    return key_schema, attribute_definitions, indexes


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable with 6 LocalSecondaryIndexes is rejected with its exact message; the same
    table with 5 is accepted -- the per-table LSI limit sits between those two counts.
    """
    ddb = ctx.client("dynamodb")
    ok_name = ctx.unique_name("sim2real-behav-lsi5-")
    bad_name = ctx.unique_name("sim2real-behav-lsi6-")
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, ok_name))
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, bad_name))

    # Positive control: 5 LSIs on a fresh base table (HASH+RANGE primary key, one range per
    # index) must be ACCEPTED -- the row's own evidence that 5 is inside the limit.
    ok_sk, ok_ad, ok_lsi = _lsi_set(5, "ok")
    ok_ad_full = ok_ad + [{"AttributeName": "sk", "AttributeType": "S"}]
    ok_ks_full = ok_sk + [{"AttributeName": "sk", "KeyType": "RANGE"}]
    ddb.create_table(
        TableName=ok_name,
        KeySchema=ok_ks_full,
        AttributeDefinitions=ok_ad_full,
        LocalSecondaryIndexes=ok_lsi,
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ddb.get_waiter("table_exists").wait(TableName=ok_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ok_desc = ddb.describe_table(TableName=ok_name)["Table"]
    ok_lsi_names = {idx["IndexName"] for idx in ok_desc.get("LocalSecondaryIndexes", [])}
    assert ok_lsi_names == {i["IndexName"] for i in ok_lsi}, (
        f"positive control did not create all 5 LSIs: {ok_lsi_names!r}"
    )

    bad_sk, bad_ad, bad_lsi = _lsi_set(6, "bad")
    bad_ad_full = bad_ad + [{"AttributeName": "sk", "AttributeType": "S"}]
    bad_ks_full = bad_sk + [{"AttributeName": "sk", "KeyType": "RANGE"}]
    code, message = _error(
        lambda: ddb.create_table(
            TableName=bad_name,
            KeySchema=bad_ks_full,
            AttributeDefinitions=bad_ad_full,
            LocalSecondaryIndexes=bad_lsi,
            BillingMode="PAY_PER_REQUEST",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    assert code == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code!r}"
    expected_msg = (
        "One or more parameter values were invalid: Number of LocalSecondaryIndexes exceeds "
        "per-table limit of 5"
    )
    assert message == expected_msg, f"expected message {expected_msg!r}, got {message!r}"

    # The rejected CreateTable must not have left a stray table behind.
    exists_code, exists_msg = _error(lambda: ddb.describe_table(TableName=bad_name))
    assert exists_code == "ResourceNotFoundException", (
        f"the refused CreateTable left {bad_name!r} behind: DescribeTable gave {exists_code!r}"
    )
    expected_nf = f"Requested resource not found: Table: {bad_name} not found"
    assert exists_msg == expected_nf, f"expected message {expected_nf!r}, got {exists_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
