"""transact-get-items-top-level-vs-cancellation-error-class."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-get-items-top-level-vs-cancellation-error-class"
GROUP = 'transactions'
SERVICES = ['dynamodb']


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
    """A bad table name and an unparsable projection each fail the whole TransactGetItems call
    with their own top-level error; a key missing an attribute instead cancels the transaction
    and names the broken slot; a projection matching no attribute still succeeds, Item absent."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    missing_table = ctx.unique_name('sim2real-behav-missing-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_table_active(ctx, ddb, table)
    ddb.put_item(TableName=table, Item={'pk': {'S': 'item1'}, 'sk': {'S': 'main'}, 'color': {'S': 'blue'}})

    valid_get = {'Get': {'TableName': table, 'Key': {'pk': {'S': 'item1'}, 'sk': {'S': 'main'}}}}

    # Positive control: a well-formed TransactGetItems returns the item.
    control = ddb.transact_get_items(TransactItems=[valid_get])['Responses']
    assert control[0].get('Item', {}).get('color') == {'S': 'blue'}, (
        f"the positive control must read back color=blue, got {control!r}"
    )

    # 1. An invalid TableName at position 2 fails the whole call with its OWN top-level error,
    # never cancellation: DynamoDB cannot start a transaction against a table that is not there.
    bad_table_get = {'Get': {'TableName': missing_table, 'Key': {'pk': {'S': 'item1'}, 'sk': {'S': 'main'}}}}
    try:
        ddb.transact_get_items(TransactItems=[valid_get, bad_table_get])
        raise AssertionError('a TransactGetItems naming a nonexistent table at position 2 was ACCEPTED')
    except ClientError as exc:
        resp = exc.response
    err = resp['Error']
    assert err['Code'] == 'ResourceNotFoundException', f"expected ResourceNotFoundException, got {err['Code']!r}"
    assert err['Message'] == 'Requested resource not found', f"expected exact message, got {err['Message']!r}"
    assert 'CancellationReasons' not in resp, (
        'a missing table is a top-level failure, not a per-item cancellation'
    )

    # 2. An unparsable ProjectionExpression also fails the whole call with its OWN top-level
    # error, never cancellation: the request as a whole could not even be parsed.
    bad_proj_get = {'Get': {'TableName': table, 'Key': {'pk': {'S': 'item1'}, 'sk': {'S': 'main'}},
                            'ProjectionExpression': 'color AND'}}
    try:
        ddb.transact_get_items(TransactItems=[bad_proj_get])
        raise AssertionError('a TransactGetItems with an unparsable ProjectionExpression was ACCEPTED')
    except ClientError as exc:
        resp = exc.response
    err = resp['Error']
    assert err['Code'] == 'ValidationException', f"expected ValidationException, got {err['Code']!r}"
    expected_proj_message = 'Invalid ProjectionExpression: Syntax error; token: "AND", near: "color AND"'
    assert err['Message'] == expected_proj_message, f"expected {expected_proj_message!r}, got {err['Message']!r}"
    assert 'CancellationReasons' not in resp, (
        'an unparsable projection expression is a top-level failure, not a per-item cancellation'
    )

    # 3. A Key missing an attribute (the sort key) instead CANCELS the transaction, and the
    # cancellation reason names only the broken slot.
    incomplete_key_get = {'Get': {'TableName': table, 'Key': {'pk': {'S': 'item1'}}}}
    try:
        ddb.transact_get_items(TransactItems=[valid_get, incomplete_key_get])
        raise AssertionError('a TransactGetItems with a Key missing the sort key was ACCEPTED')
    except ClientError as exc:
        resp = exc.response
    assert resp['Error']['Code'] == 'TransactionCanceledException', (
        f"expected TransactionCanceledException, got {resp['Error']['Code']!r}"
    )
    reasons = resp['CancellationReasons']
    assert reasons[0] == {'Code': 'None'}, f"the valid slot must carry no reason, got {reasons[0]!r}"
    assert reasons[1] == {'Code': 'ValidationError', 'Message': 'The provided key element does not match the schema'}, (
        f"the incomplete-key slot must carry the exact schema-mismatch reason, got {reasons[1]!r}"
    )

    # 4. A ProjectionExpression matching no attribute of an existing item still succeeds; the
    # response for that slot simply carries no Item.
    no_match_proj_get = {'Get': {'TableName': table, 'Key': {'pk': {'S': 'item1'}, 'sk': {'S': 'main'}},
                                 'ProjectionExpression': 'nonexistentattr'}}
    responses = ddb.transact_get_items(TransactItems=[no_match_proj_get])['Responses']
    assert 'Item' not in responses[0], (
        f"a projection matching nothing must omit Item entirely, got {responses[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
