"""execute-transaction-exists-condition-statement-commits-or-cancels."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-transaction-exists-condition-statement-commits-or-cancels"
GROUP = "partiql"
SERVICES = ["dynamodb"]
ERR_TRANSACTION_CANCELED = "TransactionCanceledException"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteTransaction treats a standalone EXISTS(SELECT ...) statement as a condition check,
    like TransactWriteItems' ConditionCheck: true lets a sibling write statement commit, false
    cancels the whole transaction with a ConditionalCheckFailed cancellation reason.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.multiplestatements.transactions.html
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    sentinel_key = {"pk": {"S": "sentinel"}, "sk": {"S": "s1"}}
    ddb.put_item(TableName=t, Item={**sentinel_key, "flag": {"S": "yes"}})
    target_key = {"pk": {"S": "target"}, "sk": {"S": "s1"}}
    ddb.put_item(TableName=t, Item={**target_key, "v": {"N": "0"}})

    # EXISTS must read a single item by its full key plus an additional attribute condition.
    exists_stmt = f'EXISTS(SELECT * FROM "{t}" WHERE pk = ? AND sk = ? AND flag = ?)'
    update_stmt = f'UPDATE "{t}" SET v = ? WHERE pk = ? AND sk = ?'

    # Positive control: the sentinel's flag matches, so the EXISTS condition is true and the
    # sibling UPDATE commits.
    ddb.execute_transaction(TransactStatements=[
        {"Statement": exists_stmt, "Parameters": [{"S": "sentinel"}, {"S": "s1"}, {"S": "yes"}]},
        {"Statement": update_stmt, "Parameters": [{"N": "1"}, {"S": "target"}, {"S": "s1"}]},
    ])
    after_commit = ddb.get_item(TableName=t, Key=target_key, ConsistentRead=True)["Item"]
    assert after_commit["v"] == {"N": "1"}, (
        f"a true EXISTS condition statement must let the sibling UPDATE commit, got {after_commit!r}"
    )

    # Break exactly one thing: the sentinel item exists, but its flag no longer matches.
    try:
        ddb.execute_transaction(TransactStatements=[
            {"Statement": exists_stmt, "Parameters": [{"S": "sentinel"}, {"S": "s1"}, {"S": "no"}]},
            {"Statement": update_stmt, "Parameters": [{"N": "2"}, {"S": "target"}, {"S": "s1"}]},
        ])
        err = None
    except ClientError as exc:
        err = exc.response

    assert err is not None, "a false EXISTS condition statement must cancel the transaction"
    assert err["Error"]["Code"] == ERR_TRANSACTION_CANCELED, (
        f"expected {ERR_TRANSACTION_CANCELED}, got {err['Error'].get('Code')!r}"
    )
    expected_message = (
        "Transaction cancelled, please refer cancellation reasons for specific reasons "
        "[ConditionalCheckFailed, None]"
    )
    assert err["Error"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err['Error'].get('Message')!r}"
    )

    reasons = err.get("CancellationReasons")
    assert reasons is not None and len(reasons) == 2, (
        f"CancellationReasons must be positionally aligned with the 2 statements, got {reasons}"
    )
    exists_reason, update_reason = reasons
    assert exists_reason["Code"] == "ConditionalCheckFailed", (
        f"the EXISTS statement must report ConditionalCheckFailed, got {exists_reason}"
    )
    assert update_reason["Code"] == "None", (
        f"the sibling UPDATE must report Code 'None' when the transaction is canceled by its "
        f"sibling, got {update_reason}"
    )

    # Effect absent: an independent read shows the canceled transaction's UPDATE never applied.
    unchanged = ddb.get_item(TableName=t, Key=target_key, ConsistentRead=True)["Item"]
    assert unchanged["v"] == {"N": "1"}, (
        f"a canceled transaction must not have applied its sibling UPDATE, got {unchanged!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
