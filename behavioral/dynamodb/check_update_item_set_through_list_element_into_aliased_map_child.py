"""update-item-set-through-list-element-into-aliased-map-child."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = 'update-item-set-through-list-element-into-aliased-map-child'
GROUP = 'update-expression'
SERVICES = ['dynamodb']


def _s(v):
    return {'S': v}


def _elem(status, note):
    return {'M': {'status': _s(status), 'note': _s(note)}}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """SET through a list element into a map child applies with a list- or child-alias, and
    ALL_NEW/ALL_OLD/UPDATED_NEW each scope to the full item or to the touched leaf alone.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-ddb-lec-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    key = {'pk': _s('doc')}
    ddb.put_item(TableName=t, Item={
        **key,
        'l': {'L': [_elem('open', 'n0'), _elem('pending', 'n1'), _elem('closed', 'n2')]},
        'other': _s('keep'),
    })

    # 1. SET l[0].#k = :v, aliasing only the reserved-word child ("status"); unaliased the
    # literal keyword would be a parse error. ReturnValues defaults to NONE: prove the write
    # through a read, not the response.
    resp = ddb.update_item(
        TableName=t, Key=key, UpdateExpression='SET l[0].#k = :v',
        ExpressionAttributeNames={'#k': 'status'}, ExpressionAttributeValues={':v': _s('approved')},
    )
    assert 'Attributes' not in resp, f'default ReturnValues must omit Attributes, got {resp.get("Attributes")}'
    item = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert item['l'] == {'L': [_elem('approved', 'n0'), _elem('pending', 'n1'), _elem('closed', 'n2')]}, (
        f"after SET l[0].#k the list was {item['l']!r}; expected only index 0's status changed"
    )

    # 2. SET through a list element into an ordinary (non-reserved) map child via alias, on a
    # different index, proving the mechanism is general and not specific to the reserved word.
    resp = ddb.update_item(
        TableName=t, Key=key, UpdateExpression='SET #l[1].#n = :v',
        ExpressionAttributeNames={'#l': 'l', '#n': 'note'}, ExpressionAttributeValues={':v': _s('n1-updated')},
        ReturnValues='UPDATED_OLD',
    )
    assert resp['Attributes'] == {'l': {'L': [{'M': {'note': _s('n1')}}]}}, (
        f"UPDATED_OLD for #l[1].#n returned {resp['Attributes']!r}; expected a single-element list "
        f"holding only the pre-update leaf"
    )

    # 3. Aliased list AND aliased reserved-word child together, with UPDATED_NEW: the rebuild
    # composes the list-index truncation (single-element list) with the map rebuild (only the
    # touched field), not just one or the other.
    resp = ddb.update_item(
        TableName=t, Key=key, UpdateExpression='SET #l[2].#k = :v',
        ExpressionAttributeNames={'#l': 'l', '#k': 'status'}, ExpressionAttributeValues={':v': _s('reopened')},
        ReturnValues='UPDATED_NEW',
    )
    assert resp['Attributes'] == {'l': {'L': [{'M': {'status': _s('reopened')}}]}}, (
        f"UPDATED_NEW for #l[2].#k returned {resp['Attributes']!r}; expected a single-element list "
        f"holding a map with only the touched field"
    )

    # 4. ALL_NEW after a list-element-child SET returns the complete resulting item, not just the
    # touched path.
    resp = ddb.update_item(
        TableName=t, Key=key, UpdateExpression='SET l[0].#k = :v',
        ExpressionAttributeNames={'#k': 'status'}, ExpressionAttributeValues={':v': _s('closed-final')},
        ReturnValues='ALL_NEW',
    )
    want_all_new = {
        **key,
        'l': {'L': [_elem('closed-final', 'n0'),
                    {'M': {'status': _s('pending'), 'note': _s('n1-updated')}},
                    _elem('reopened', 'n2')]},
        'other': _s('keep'),
    }
    assert resp['Attributes'] == want_all_new, (
        f"ALL_NEW after SET l[0].#k returned {resp['Attributes']!r}; expected {want_all_new!r}"
    )

    # 5. ALL_OLD before a list-element-child SET returns the complete prior item.
    want_all_old = want_all_new
    resp = ddb.update_item(
        TableName=t, Key=key, UpdateExpression='SET l[1].#n = :v',
        ExpressionAttributeNames={'#n': 'note'}, ExpressionAttributeValues={':v': _s('n1-final')},
        ReturnValues='ALL_OLD',
    )
    assert resp['Attributes'] == want_all_old, (
        f"ALL_OLD before SET l[1].#n returned {resp['Attributes']!r}; expected the prior full item {want_all_old!r}"
    )

    final = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    want_final = {
        **key,
        'l': {'L': [_elem('closed-final', 'n0'), {'M': {'status': _s('pending'), 'note': _s('n1-final')}},
                    _elem('reopened', 'n2')]},
        'other': _s('keep'),
    }
    assert final == want_final, f'final item was {final!r}; expected {want_final!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
