"""transact-write-items-overlength-token-masks-other-violations-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-overlength-token-masks-other-violations-rejected"
GROUP = 'transactions'
SERVICES = ['dynamodb']


def _error(call, what):
    try:
        result = call()
    except ClientError as exc:
        return exc.response['Error']
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it: {result!r}')


def _wait_table_active(ctx, ddb, table):
    """Poll DescribeTable to ACTIVE, bounded by the run's remaining time."""
    deadline = time.monotonic() + max(1.0, min(60.0, (ctx.time_left() or 60.0) - 10.0))
    status = ddb.describe_table(TableName=table)['Table']['TableStatus']
    while status != 'ACTIVE' and time.monotonic() < deadline:
        time.sleep(2)
        status = ddb.describe_table(TableName=table)['Table']['TableStatus']
    assert status == 'ACTIVE', f"table did not reach ACTIVE in time, last status {status!r}"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """A ClientRequestToken over 36 characters is the only violation TransactWriteItems reports
    even beside an action naming no operation and an invalid ReturnConsumedCapacity; drop the
    token defect and the other two are reported together instead."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_table_active(ctx, ddb, table)

    # Positive control: a well-formed transaction is accepted and its write lands.
    ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': table, 'Item': {'pk': {'S': 'control'}}}}])
    assert ddb.get_item(TableName=table, Key={'pk': {'S': 'control'}}, ConsistentRead=True).get('Item'), (
        'the positive control item must exist after a well-formed TransactWriteItems'
    )

    long_token = 'x' * 37
    no_op_action = {}
    valid_but_blocked_put = {'Put': {'TableName': table, 'Item': {'pk': {'S': 'should-not-write-1'}}}}

    # All three violations present: the overlength token is the only one reported.
    err = _error(
        lambda: ddb.transact_write_items(
            TransactItems=[no_op_action, valid_but_blocked_put],
            ClientRequestToken=long_token,
            ReturnConsumedCapacity='BOGUS',
        ),
        'a TransactWriteItems with a no-op action, an overlength token and an invalid ReturnConsumedCapacity',
    )
    assert err['Code'] == 'ValidationException', f"expected ValidationException, got {err['Code']!r}"
    token_only_message = ("1 validation error detected: Value at 'ClientRequestToken' failed to "
                          "satisfy constraint: Member must have length less than or equal to 36")
    assert err['Message'] == token_only_message, f"expected {token_only_message!r}, got {err['Message']!r}"

    # Drop the token defect: the remaining two violations are now both reported, together.
    err2 = _error(
        lambda: ddb.transact_write_items(
            TransactItems=[no_op_action, valid_but_blocked_put],
            ReturnConsumedCapacity='BOGUS',
        ),
        'a TransactWriteItems with a no-op action and an invalid ReturnConsumedCapacity, valid token',
    )
    assert err2['Code'] == 'ValidationException', f"expected ValidationException, got {err2['Code']!r}"
    two_violation_message = (
        "2 validation errors detected: Value '' at 'transactItems' failed to satisfy constraint: "
        "TransactWriteRequest should contain Delete or Put or Update or ConditionCheck; "
        "Value 'BOGUS' at 'returnConsumedCapacity' failed to satisfy constraint: "
        "Member must satisfy enum value set: [INDEXES, TOTAL, NONE]"
    )
    assert err2['Message'] == two_violation_message, f"expected {two_violation_message!r}, got {err2['Message']!r}"

    items = {i['pk']['S'] for i in ddb.scan(TableName=table, ConsistentRead=True)['Items']}
    assert items == {'control'}, (
        f"neither rejected transaction may write anything; table holds {sorted(items)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
