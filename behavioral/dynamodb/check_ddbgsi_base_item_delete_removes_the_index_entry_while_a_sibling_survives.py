"""ddbgsi-base-item-delete-removes-the-index-entry-while-a-sibling-survives."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ddbgsi-base-item-delete-removes-the-index-entry-while-a-sibling-survives"
GROUP = 'gsi'
SERVICES = ['dynamodb']

_INDEX = 'gsi1'
_CONVERGE_S = 180


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deleting a base item withdraws its GSI entry while a same-key sibling survives.

    The index converges on exactly the survivor (ScannedCount 1); consistent base reads agree.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbgsi-del-')
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

    deadline = time.time() + _CONVERGE_S
    index_status = None
    while time.time() < deadline:
        described = ddb.describe_table(TableName=table)['Table']
        index_status = {i['IndexName']: i['IndexStatus']
                        for i in described.get('GlobalSecondaryIndexes', [])}
        if index_status.get(_INDEX) == 'ACTIVE':
            break
        time.sleep(2)
    assert index_status.get(_INDEX) == 'ACTIVE', (
        f'{_INDEX} never became ACTIVE within {_CONVERGE_S}s: {index_status!r}'
    )

    doomed = {'pk': {'S': 'ITEM#DOOMED'}, 'sk': {'S': 'S1'}}
    sibling = {'pk': {'S': 'ITEM#SIBLING'}, 'sk': {'S': 'S1'}}
    ddb.put_item(TableName=table, Item={**doomed, 'gsi1pk': {'S': 'BUCKET#A'},
                                        'body': {'S': 'doomed-payload'}})
    ddb.put_item(TableName=table, Item={**sibling, 'gsi1pk': {'S': 'BUCKET#A'},
                                        'body': {'S': 'sibling-payload'}})

    def index_read():
        return ddb.query(TableName=table, IndexName=_INDEX,
                         KeyConditionExpression='gsi1pk = :g',
                         ExpressionAttributeValues={':g': {'S': 'BUCKET#A'}})

    # GSI propagation is eventual with no documented bound, so poll for the key set to a deadline.
    def converge(want, *, what):
        resp = {'Items': [], 'ScannedCount': 0}
        give_up = time.time() + _CONVERGE_S
        while time.time() < give_up:
            resp = index_read()
            if sorted(i['pk']['S'] for i in resp['Items']) == want:
                return resp
            time.sleep(1)
        raise AssertionError(
            f'{what}: the index never converged on {want!r} within {_CONVERGE_S}s; the last read '
            f'held {sorted(i["pk"]["S"] for i in resp["Items"])!r}'
        )

    # Effect present: both items are materialised into the index under the shared index key.
    both = converge(['ITEM#DOOMED', 'ITEM#SIBLING'], what='the two writes')
    assert both['ScannedCount'] == 2, (
        f'the index read examined {both["ScannedCount"]!r} entries, not the 2 written'
    )

    ddb.delete_item(TableName=table, Key=doomed)

    # Effect absent, and only for the item that was deleted.
    after = converge(['ITEM#SIBLING'], what='the delete')
    assert [i['pk']['S'] for i in after['Items']] == ['ITEM#SIBLING'], (
        f'the index did not converge on exactly the surviving item: {after["Items"]!r}'
    )
    assert after['ScannedCount'] == 1, (
        f'the index read that shows the withdrawal examined {after["ScannedCount"]!r} entries; a '
        f'read of an empty or absent index would make the absence vacuous'
    )
    assert after['Items'][0]['body']['S'] == 'sibling-payload', (
        f'the surviving index entry is not the sibling that was written: {after["Items"][0]!r}'
    )

    # The base table agrees, strongly consistently: one gone, one intact.
    gone = ddb.get_item(TableName=table, Key=doomed, ConsistentRead=True)
    assert 'Item' not in gone, (
        f'the deleted item is still on the base table, so the index withdrawal above is not about '
        f'a delete at all: {gone.get("Item")!r}'
    )
    kept = ddb.get_item(TableName=table, Key=sibling, ConsistentRead=True)
    assert kept['Item']['body']['S'] == 'sibling-payload', (
        f'the delete took the sibling with it: {kept.get("Item")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
