"""ddbgsi-index-gains-no-entry-when-a-conditional-write-is-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddbgsi-index-gains-no-entry-when-a-conditional-write-is-rejected"
GROUP = 'gsi'
SERVICES = ['dynamodb']

ERR_CONDITION = 'ConditionalCheckFailedException'
_INDEX = 'gsi1'
_CONVERGE_S = 180


def _error_code(fn):
    """Return (error code, response) for the error *fn* raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response
    raise AssertionError(
        f'real AWS refuses this conditional write, but it SUCCEEDED and returned {result!r}'
    )


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A rejected conditional write adds no GSI entry, while an accepted one moves the item's entry.

    A later barrier write reaching the index proves the refused key stayed empty, not unprocessed.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbgsi-cond-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
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

    def index_query(bucket):
        return ddb.query(TableName=table, IndexName=_INDEX,
                         KeyConditionExpression='gsi1pk = :g',
                         ExpressionAttributeValues={':g': {'S': bucket}})

    def converge(bucket, want_pks, *, what):
        items = []
        give_up = time.time() + _CONVERGE_S
        while time.time() < give_up:
            items = index_query(bucket)['Items']
            if sorted(i['pk']['S'] for i in items) == want_pks:
                return items
            time.sleep(1)
        raise AssertionError(
            f'{what}: the index never converged on {want_pks!r} under {bucket!r} within '
            f'{_CONVERGE_S}s; the last read held {items!r}'
        )

    subject = {'pk': {'S': 'ITEM#SUBJECT'}}
    ddb.put_item(TableName=table, Item={**subject, 'gsi1pk': {'S': 'BUCKET#ORIGINAL'},
                                        'body': {'S': 'original'}})
    converge('BUCKET#ORIGINAL', ['ITEM#SUBJECT'], what='the initial write')

    # Break exactly one thing: the item now exists, so attribute_not_exists(pk) cannot hold.
    code, response = _error_code(lambda: ddb.put_item(
        TableName=table,
        Item={**subject, 'gsi1pk': {'S': 'BUCKET#REFUSED'}, 'body': {'S': 'refused'}},
        ConditionExpression='attribute_not_exists(pk)'))
    assert code == ERR_CONDITION, (
        f'expected {ERR_CONDITION!r} for a PutItem whose attribute_not_exists condition cannot '
        f'hold, got {code!r} ({response.get("Error", {}).get("Message")!r})'
    )
    assert response.get('Error', {}).get('Message') == "The conditional request failed", (
        f"expected AWS's exact ConditionalCheckFailedException message, got {response.get('Error', {}).get('Message')!r}"
    )

    # Effect absent on the base table: the refused write replaced nothing.
    base = ddb.get_item(TableName=table, Key=subject, ConsistentRead=True)['Item']
    assert base['gsi1pk']['S'] == 'BUCKET#ORIGINAL' and base['body']['S'] == 'original', (
        f'the refused conditional write mutated the base item anyway: {base!r}'
    )

    # Barrier: a write issued AFTER the refusal whose index entry we wait for. Once it has
    # arrived the index has processed work queued behind the refusal, so the emptiness asserted
    # next is a property of the index's contents and not of how soon we looked.
    barrier = {'pk': {'S': 'ITEM#BARRIER'}}
    ddb.put_item(TableName=table, Item={**barrier, 'gsi1pk': {'S': 'BUCKET#BARRIER'},
                                        'body': {'S': 'barrier'}})
    converge('BUCKET#BARRIER', ['ITEM#BARRIER'], what='the barrier write')

    refused_entries = index_query('BUCKET#REFUSED')
    assert refused_entries['Items'] == [], (
        f'the refused conditional write still produced an index entry under its would-be index '
        f'key: {refused_entries["Items"]!r}'
    )
    still_original = index_query('BUCKET#ORIGINAL')['Items']
    assert [i['pk']['S'] for i in still_original] == ['ITEM#SUBJECT'], (
        f'the refused write disturbed the index entry that did exist: {still_original!r}'
    )

    # Positive control: the SAME conditional-write mechanism, with a condition that holds, does
    # reach the index -- so the empty read above is not "conditional writes never index".
    ddb.update_item(TableName=table, Key=subject,
                    UpdateExpression='SET gsi1pk = :g, body = :b',
                    ConditionExpression='attribute_exists(pk)',
                    ExpressionAttributeValues={':g': {'S': 'BUCKET#MOVED'},
                                               ':b': {'S': 'moved'}})
    moved = converge('BUCKET#MOVED', ['ITEM#SUBJECT'], what='the accepted conditional write')
    assert moved[0]['body']['S'] == 'moved', (
        f'the accepted conditional write reached the index with the wrong payload: {moved!r}'
    )
    converge('BUCKET#ORIGINAL', [], what='the vacated old index key')

    # Index-wide: exactly two entries exist, under the barrier key and the moved key. The refused
    # key is absent from the index's own contents, not merely from one targeted query.
    index_wide = ddb.scan(TableName=table, IndexName=_INDEX)
    assert sorted(i['gsi1pk']['S'] for i in index_wide['Items']) == ['BUCKET#BARRIER',
                                                                     'BUCKET#MOVED'], (
        f'the index holds the wrong set of entries: '
        f'{sorted(i["gsi1pk"]["S"] for i in index_wide["Items"])!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
