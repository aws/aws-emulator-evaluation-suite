"""ddbgsi-query-filter-on-a-non-projected-attribute-rejected-while-scan-matches-nothing."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddbgsi-query-filter-on-a-non-projected-attribute-rejected-while-scan-matches-nothing"
GROUP = 'gsi'
SERVICES = ['dynamodb']

ERR_VALIDATION = 'ValidationException'
_INDEX = 'gsi1'
_INDEX_LSI = 'lsi1'
_VISIBLE_S = 180


def _error_code(fn):
    """Return (error code, response) for the error *fn* raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response
    raise AssertionError(
        f'real AWS refuses this Query, but it SUCCEEDED and returned {result.get("Items")!r}'
    )


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A GSI Query filtering on a non-projected attribute is refused; the same filter on a GSI Scan
    is accepted and matches nothing. Controls: the projected-attribute filter and a base Scan match.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbgsi-filt-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'sk', 'AttributeType': 'S'},
                              {'AttributeName': 'gsi1pk', 'AttributeType': 'S'},
                              {'AttributeName': 'lsk', 'AttributeType': 'S'}],
        GlobalSecondaryIndexes=[{
            'IndexName': _INDEX,
            'KeySchema': [{'AttributeName': 'gsi1pk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['kept']},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': _INDEX_LSI,
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                         {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['kept']},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    deadline = time.time() + _VISIBLE_S
    index_status = None
    while time.time() < deadline:
        described = ddb.describe_table(TableName=table)['Table']
        index_status = {i['IndexName']: i['IndexStatus']
                        for i in described.get('GlobalSecondaryIndexes', [])}
        if index_status.get(_INDEX) == 'ACTIVE':
            break
        time.sleep(2)
    assert index_status.get(_INDEX) == 'ACTIVE', (
        f'{_INDEX} never became ACTIVE within {_VISIBLE_S}s: {index_status!r}'
    )

    ddb.put_item(TableName=table, Item={'pk': {'S': 'ITEM#1'}, 'sk': {'S': 'S1'},
                                        'gsi1pk': {'S': 'BUCKET#A'}, 'lsk': {'S': 'L1'},
                                        'kept': {'S': 'projected-value'},
                                        'dropped': {'S': 'excluded-value'}})

    def query_index(filter_expr, values):
        vals = {':g': {'S': 'BUCKET#A'}}
        vals.update(values)
        return ddb.query(TableName=table, IndexName=_INDEX,
                         KeyConditionExpression='gsi1pk = :g',
                         FilterExpression=filter_expr,
                         ExpressionAttributeValues=vals)

    # Positive control 1: the same filter shape over a PROJECTED attribute returns the item from
    # the index, once the entry has arrived. Until then the rejection below proves nothing.
    deadline = time.time() + _VISIBLE_S
    kept_items = []
    while time.time() < deadline:
        kept_items = query_index('kept = :k', {':k': {'S': 'projected-value'}})['Items']
        if kept_items:
            break
        time.sleep(1)
    assert [i['pk']['S'] for i in kept_items] == ['ITEM#1'], (
        f'a filter over the PROJECTED attribute never returned the item within {_VISIBLE_S}s, so '
        f'the refusal below would not be about the projection: {kept_items!r}'
    )
    assert 'dropped' not in kept_items[0], (
        f'the non-projected attribute is present in the index entry, so nothing below is about a '
        f'projection at all: {kept_items[0]!r}'
    )

    # Break exactly one thing: the filter names the NON-projected attribute instead.
    code, response = _error_code(
        lambda: query_index('dropped = :d', {':d': {'S': 'excluded-value'}}))
    assert code == ERR_VALIDATION, (
        f'expected {ERR_VALIDATION!r} for a Query filter naming an attribute {_INDEX} does not '
        f'project, got {code!r} ({response.get("Error", {}).get("Message")!r})'
    )
    assert response.get('Error', {}).get('Message') == "One or more parameter values were invalid: Secondary index gsi1 does not project one or more filter attributes: [dropped]", (
        f"expected AWS's exact ValidationException message, got {response.get('Error', {}).get('Message')!r}"
    )
    # Effect absent: the refused Query carried no page of data at all, not an empty one.
    assert 'Items' not in response and 'Count' not in response, (
        f'the refused Query still returned a page: {response!r}'
    )

    # The asymmetry: Scan accepts the identical filter and matches nothing, having really
    # looked -- ScannedCount counts the index entry it examined and rejected.
    scan = ddb.scan(TableName=table, IndexName=_INDEX, FilterExpression='dropped = :d',
                    ExpressionAttributeValues={':d': {'S': 'excluded-value'}})
    assert scan['Items'] == [], (
        f'the index Scan matched on an attribute the index does not project: {scan["Items"]!r}'
    )
    assert scan['ScannedCount'] == 1, (
        f'the index Scan did not examine the one index entry, so its empty result says nothing '
        f'about the filter: ScannedCount={scan["ScannedCount"]!r}'
    )

    # Positive control 2: the same filter over the same attribute DOES match on the base table,
    # strongly consistently -- so the empty index result above is the projection at work and not a
    # value that never existed.
    base = ddb.scan(TableName=table, FilterExpression='dropped = :d', ConsistentRead=True,
                    ExpressionAttributeValues={':d': {'S': 'excluded-value'}})
    assert [i['pk']['S'] for i in base['Items']] == ['ITEM#1'], (
        f'the base-table Scan with the identical filter did not match, so the empty index result '
        f'is not attributable to the projection: {base["Items"]!r}'
    )
    assert base['Items'][0]['dropped']['S'] == 'excluded-value', (
        f'the base item does not carry the filtered value: {base["Items"][0]!r}'
    )

    # LSI arm: the identical refusal on a LOCAL secondary index, where an LSI Query can read
    # strongly consistent -- no poll for propagation is needed, unlike the GSI arm above.
    def query_lsi(filter_expr, values):
        vals = {':p': {'S': 'ITEM#1'}}
        vals.update(values)
        return ddb.query(TableName=table, IndexName=_INDEX_LSI, ConsistentRead=True,
                         KeyConditionExpression='pk = :p',
                         FilterExpression=filter_expr,
                         ExpressionAttributeValues=vals)

    # Positive control: the same filter shape over the PROJECTED attribute matches on the LSI.
    lsi_kept = query_lsi('kept = :k', {':k': {'S': 'projected-value'}})['Items']
    assert [i['pk']['S'] for i in lsi_kept] == ['ITEM#1'], (
        f'a filter over the PROJECTED attribute did not match on {_INDEX_LSI}: {lsi_kept!r}'
    )
    assert 'dropped' not in lsi_kept[0], (
        f'the non-projected attribute is present in the LSI entry, so nothing below is about a '
        f'projection at all: {lsi_kept[0]!r}'
    )

    # Break exactly one thing: the filter names the NON-projected attribute on the LSI.
    lsi_code, lsi_response = _error_code(
        lambda: query_lsi('dropped = :d', {':d': {'S': 'excluded-value'}}))
    assert lsi_code == ERR_VALIDATION, (
        f'expected {ERR_VALIDATION!r} for a Query filter naming an attribute {_INDEX_LSI} does '
        f'not project, got {lsi_code!r} ({lsi_response.get("Error", {}).get("Message")!r})'
    )
    assert lsi_response.get('Error', {}).get('Message') == (
        "One or more parameter values were invalid: Secondary index lsi1 does not project one "
        "or more filter attributes: [dropped]"
    ), (
        f"expected AWS's exact ValidationException message, got "
        f"{lsi_response.get('Error', {}).get('Message')!r}"
    )
    assert 'Items' not in lsi_response and 'Count' not in lsi_response, (
        f'the refused LSI Query still returned a page: {lsi_response!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
