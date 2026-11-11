"""ddbgsi-projected-value-converges-in-the-index-after-an-update."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ddbgsi-projected-value-converges-in-the-index-after-an-update"
GROUP = 'gsi'
SERVICES = ['dynamodb']

_INDEX = 'gsi1'
_CONVERGE_S = 180


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A GSI entry converges on an updated projected label and never gains non-projected 'notes'.

    The base table shows both new values immediately; the index only ever holds one entry.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbgsi-conv-')
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
            'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['label']},
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

    key = {'pk': {'S': 'ITEM#1'}, 'sk': {'S': 'S1'}}

    def index_entries():
        return ddb.query(TableName=table, IndexName=_INDEX,
                         KeyConditionExpression='gsi1pk = :g',
                         ExpressionAttributeValues={':g': {'S': 'BUCKET#A'}})['Items']

    def converge(want, *, what):
        """Poll the index until the projected label equals *want*; collect every value seen.

        GSI writes arrive eventually with no documented bound, so the deadline is a give-up bound.
        """
        seen = set()
        entries = []
        give_up = time.time() + _CONVERGE_S
        while time.time() < give_up:
            entries = index_entries()
            for e in entries:
                if 'label' in e:
                    seen.add(e['label']['S'])
            if len(entries) == 1 and entries[0].get('label') == {'S': want}:
                return entries[0], seen
            time.sleep(1)
        raise AssertionError(
            f'{what}: the index never converged on label={want!r} within {_CONVERGE_S}s; the last '
            f'read was {entries!r} and the values seen over the whole poll were {sorted(seen)!r}'
        )

    ddb.put_item(TableName=table, Item={**key, 'gsi1pk': {'S': 'BUCKET#A'},
                                        'label': {'S': 'v1'}, 'notes': {'S': 'n1'}})

    first, seen_before = converge('v1', what='the initial write')
    assert set(first) == {'pk', 'sk', 'gsi1pk', 'label'}, (
        f"the INCLUDE ['label'] projection must expose exactly the base and index keys plus "
        f"'label', got {sorted(first)!r}"
    )
    assert 'notes' not in first, (
        f'a non-projected attribute leaked into the index entry: {first!r}'
    )

    base_before = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
    assert base_before['notes']['S'] == 'n1' and base_before['label']['S'] == 'v1', (
        f"the base item does not carry the values the index absence above is measured against, so "
        f"that absence would be vacuous: {base_before!r}"
    )

    ddb.update_item(TableName=table, Key=key,
                    UpdateExpression='SET label = :l, notes = :n',
                    ExpressionAttributeValues={':l': {'S': 'v2'}, ':n': {'S': 'n2'}})

    # The base table is strongly consistent, so the new values are readable with no poll at all.
    base_after = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
    assert base_after['label']['S'] == 'v2', (
        f'the strongly consistent base read did not see the update it followed: {base_after!r}'
    )
    assert base_after['notes']['S'] == 'n2', (
        f'the non-projected attribute was not updated on the base item: {base_after!r}'
    )

    after, seen_after = converge('v2', what='the update')
    assert set(after) == {'pk', 'sk', 'gsi1pk', 'label'}, (
        f'the projection stopped governing the index entry after the update: {sorted(after)!r}'
    )
    assert 'notes' not in after, (
        f"updating 'notes' pulled a non-projected attribute into the index entry: {after!r}"
    )
    # Only 'v1' and 'v2' were ever stored, so any other label is invented index state.
    assert seen_before | seen_after <= {'v1', 'v2'}, (
        f'the index exposed a label value that was never written: '
        f'{sorted((seen_before | seen_after) - {"v1", "v2"})!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
