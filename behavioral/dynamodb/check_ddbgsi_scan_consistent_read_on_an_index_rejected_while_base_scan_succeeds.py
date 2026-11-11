"""ddbgsi-scan-consistent-read-on-an-index-rejected-while-base-scan-succeeds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddbgsi-scan-consistent-read-on-an-index-rejected-while-base-scan-succeeds"
GROUP = 'gsi'
SERVICES = ['dynamodb']

ERR_VALIDATION = 'ValidationException'
_INDEX = 'gsi1'
_VISIBLE_S = 180


def _error_code(fn):
    """Return the error code *fn* raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response
    raise AssertionError(
        f'real AWS refuses a strongly consistent Scan of a global secondary index, but the call '
        f'SUCCEEDED and returned {result.get("Items")!r}'
    )


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A GSI Scan with ConsistentRead=True is refused with ValidationException and no data, while
    a consistent base Scan sees a just-written item and the index Scan without the flag works.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbgsi-scancr-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'sk', 'AttributeType': 'S'},
                              {'AttributeName': 'gsi1pk', 'AttributeType': 'S'}],
        GlobalSecondaryIndexes=[{
            'IndexName': _INDEX,
            'KeySchema': [{'AttributeName': 'gsi1pk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
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
                                        'gsi1pk': {'S': 'BUCKET#A'}, 'body': {'S': 'payload'}})

    # Positive control 1: ConsistentRead=True is accepted on the base table, and it really is
    # strongly consistent -- it sees the write it followed with no poll whatsoever. The table is
    # this check's own, so "exactly one item" is a property of the query, not of the account.
    base = ddb.scan(TableName=table, ConsistentRead=True)
    assert [i['pk']['S'] for i in base['Items']] == ['ITEM#1'], (
        f'the strongly consistent base Scan did not see the write it followed: {base["Items"]!r}'
    )

    # Positive control 2: the identical index Scan, minus the flag, works once the entry arrives.
    deadline = time.time() + _VISIBLE_S
    idx_items = []
    while time.time() < deadline:
        idx_items = ddb.scan(TableName=table, IndexName=_INDEX)['Items']
        if idx_items:
            break
        time.sleep(1)
    assert [i['pk']['S'] for i in idx_items] == ['ITEM#1'], (
        f'the eventually consistent index Scan never returned the item within {_VISIBLE_S}s, so '
        f'the rejection below would not be about consistency: {idx_items!r}'
    )

    # Break exactly one field: the same index Scan, with ConsistentRead=True.
    code, response = _error_code(
        lambda: ddb.scan(TableName=table, IndexName=_INDEX, ConsistentRead=True))
    assert code == ERR_VALIDATION, (
        f'expected {ERR_VALIDATION!r} for a strongly consistent Scan of a GSI, got {code!r} '
        f'({response.get("Error", {}).get("Message")!r})'
    )
    assert response.get('Error', {}).get('Message') == "Consistent reads are not supported on global secondary indexes", (
        f"expected AWS's exact ValidationException message, got {response.get('Error', {}).get('Message')!r}"
    )
    # Effect absent: the refused Scan carried no data whatsoever -- not an empty page, no page.
    assert 'Items' not in response and 'Count' not in response, (
        f'the refused consistent index Scan still returned a page: {response!r}'
    )

    # And the refusal did not disturb the table: the two accepted reads still answer as before.
    still_base = ddb.scan(TableName=table, ConsistentRead=True)
    assert [i['pk']['S'] for i in still_base['Items']] == ['ITEM#1'], (
        f'the refused call changed what the base table holds: {still_base["Items"]!r}'
    )
    still_idx = ddb.scan(TableName=table, IndexName=_INDEX)['Items']
    assert [i['pk']['S'] for i in still_idx] == ['ITEM#1'], (
        f'the refused call disturbed the index contents: {still_idx!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
