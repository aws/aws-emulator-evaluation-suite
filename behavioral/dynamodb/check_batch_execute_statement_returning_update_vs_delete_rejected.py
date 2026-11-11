"""batch-execute-statement-returning-update-vs-delete-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-execute-statement-returning-update-vs-delete-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_EXPECTED_DELETE_MESSAGE = (
    'Invalid returning clause: RETURNING ALL NEW *. '
    'Only RETURNING ALL OLD * is allowed in DELETE statements.'
)


def _stored(ddb, table, pk, sk):
    return ddb.get_item(
        TableName=table, Key={'pk': {'S': pk}, 'sk': {'S': sk}}, ConsistentRead=True,
    ).get('Item')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement reports an UPDATE member's RETURNING ALL NEW * / MODIFIED NEW * as a
    per-slot Item carrying that image, and a DELETE member's unsupported RETURNING ALL NEW * as a
    per-slot Error instead of aborting the batch; only the Item-carrying slots echo TableName.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlbret-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 60})

    item1 = {'pk': {'S': 'p1'}, 'sk': {'S': 's1'}, 'name': {'S': 'Ada'}, 'qty': {'N': '3'}}
    item2 = {'pk': {'S': 'p2'}, 'sk': {'S': 's2'}, 'name': {'S': 'Bea'}, 'qty': {'N': '5'}}
    item3 = {'pk': {'S': 'p3'}, 'sk': {'S': 's3'}, 'name': {'S': 'Cid'}, 'qty': {'N': '7'}}
    for item in (item1, item2, item3):
        ddb.put_item(TableName=table, Item=item)

    resp = ddb.batch_execute_statement(Statements=[
        {'Statement': f"UPDATE \"{table}\" SET qty = 10 WHERE pk = 'p1' AND sk = 's1' RETURNING ALL NEW *"},
        {'Statement': f"UPDATE \"{table}\" SET name = 'Zed' WHERE pk = 'p2' AND sk = 's2' RETURNING MODIFIED NEW *"},
        {'Statement': f"DELETE FROM \"{table}\" WHERE pk = 'p3' AND sk = 's3' RETURNING ALL NEW *"},
    ])
    responses = resp['Responses']
    assert len(responses) == 3, f'expected 3 per-statement responses, got {len(responses)}: {responses}'

    slot1, slot2, slot3 = responses

    # Slot 1: UPDATE ... RETURNING ALL NEW * succeeds with the full post-update image, and the
    # slot echoes TableName.
    assert 'Error' not in slot1, f'expected the ALL NEW * UPDATE slot to succeed, got {slot1!r}'
    assert slot1.get('TableName') == table, (
        f'expected the successful UPDATE slot to echo TableName={table!r}, got {slot1!r}'
    )
    want1 = {**item1, 'qty': {'N': '10'}}
    assert slot1.get('Item') == want1, (
        f'expected RETURNING ALL NEW * to carry the full post-update item {want1!r}, got {slot1.get("Item")!r}'
    )

    # Slot 2: UPDATE ... RETURNING MODIFIED NEW * succeeds with only the modified attribute, and
    # the slot echoes TableName.
    assert 'Error' not in slot2, f'expected the MODIFIED NEW * UPDATE slot to succeed, got {slot2!r}'
    assert slot2.get('TableName') == table, (
        f'expected the successful UPDATE slot to echo TableName={table!r}, got {slot2!r}'
    )
    want2 = {'name': {'S': 'Zed'}}
    assert slot2.get('Item') == want2, (
        f'expected RETURNING MODIFIED NEW * to carry only the set attribute {want2!r}, got {slot2.get("Item")!r}'
    )

    # Slot 3: DELETE ... RETURNING ALL NEW * is an unsupported variant, reported as a per-slot
    # Error (not a thrown exception aborting the batch), and the slot carries no TableName.
    assert 'Item' not in slot3, f'expected the rejected DELETE slot to carry no Item, got {slot3!r}'
    assert 'TableName' not in slot3, (
        f'expected the rejected DELETE slot to carry no TableName (only a successful slot echoes '
        f'it), got {slot3!r}'
    )
    error = slot3.get('Error')
    assert error is not None, f'expected the rejected DELETE slot to carry a per-slot Error, got {slot3!r}'
    assert error.get('Code') == 'ValidationError', (
        f'expected the rejected DELETE slot Error.Code to be ValidationError, got {error.get("Code")!r}'
    )
    assert error.get('Message') == _EXPECTED_DELETE_MESSAGE, (
        f'expected message {_EXPECTED_DELETE_MESSAGE!r}, got {error.get("Message")!r}'
    )

    # The batch's mutations landed exactly where the per-slot outcomes say they did: p1 and p2
    # updated, p3 untouched by its rejected DELETE.
    assert _stored(ddb, table, 'p1', 's1') == want1, (
        f'p1 must have been updated to {want1!r}, got {_stored(ddb, table, "p1", "s1")!r}'
    )
    stored2 = _stored(ddb, table, 'p2', 's2')
    want_stored2 = {**item2, 'name': {'S': 'Zed'}}
    assert stored2 == want_stored2, f'p2 must have been updated to {want_stored2!r}, got {stored2!r}'
    assert _stored(ddb, table, 'p3', 's3') == item3, (
        f'p3 must be untouched by its rejected DELETE, got {_stored(ddb, table, "p3", "s3")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
