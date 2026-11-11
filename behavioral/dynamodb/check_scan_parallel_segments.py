"""scan-parallel-segments."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "scan-parallel-segments"
GROUP = 'scan'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Parallel scan with TotalSegments/Segment partitions the full table disjointly."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': 'scan-parallel-segments'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for i in range(20):
        ddb.put_item(TableName=table, Item={'pk': {'S': f'par-{i:03d}'}})
    total_segments = 4
    per_segment_pks: list[set[str]] = []
    for seg in range(total_segments):
        seg_pks: set[str] = set()
        params: dict[str, Any] = {'TableName': table, 'TotalSegments': total_segments, 'Segment': seg, 'ConsistentRead': True}
        while True:
            resp = ddb.scan(**params)
            for item in resp['Items']:
                seg_pks.add(item['pk']['S'])
            if 'LastEvaluatedKey' not in resp:
                break
            params['ExclusiveStartKey'] = resp['LastEvaluatedKey']
        per_segment_pks.append(seg_pks)
    all_pks: set[str] = set().union(*per_segment_pks)
    assert len(all_pks) == 20, f'expected 20 unique items across all segments, got {len(all_pks)}'
    total_returned = sum(len(s) for s in per_segment_pks)
    assert total_returned == len(all_pks), (
        f'segments must partition the table disjointly: {total_returned} items returned across '
        f'{total_segments} segments but only {len(all_pks)} unique pks (overlap of '
        f'{total_returned - len(all_pks)}) — a target that ignores Segment/TotalSegments and '
        f'returns the whole table on every call would still pass the count-only assertion'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
