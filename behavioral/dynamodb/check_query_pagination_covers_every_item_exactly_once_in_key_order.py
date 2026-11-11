"""query-pagination-covers-every-item-exactly-once-in-key-order."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-pagination-covers-every-item-exactly-once-in-key-order"
GROUP = 'pagination'
SERVICES = ['dynamodb']

_N_ITEMS = 200
_LIMIT = 7


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paging a Query with Limit=7 returns all 200 numeric sort keys exactly once in ascending
    numeric order, and ScanIndexForward=False returns the exact reverse.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-page-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'seq', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'seq', 'AttributeType': 'N'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    part = 'P'
    written = list(range(_N_ITEMS))
    for start in range(0, _N_ITEMS, 25):
        pending = {table: [{'PutRequest': {'Item': {'pk': {'S': part},
                                                    'seq': {'N': str(i)}}}}
                           for i in written[start:start + 25]]}
        deadline = time.time() + 120
        while pending and time.time() < deadline:
            pending = ddb.batch_write_item(RequestItems=pending).get('UnprocessedItems') or {}
            if pending:
                time.sleep(1)
        assert not pending, f'BatchWriteItem never drained UnprocessedItems: {pending!r}'

    def _page_through(forward: bool) -> tuple[list[int], int]:
        keys: list[int] = []
        pages = 0
        start_key: dict = {}
        while True:
            resp = ddb.query(TableName=table, Limit=_LIMIT, ConsistentRead=True,
                             ScanIndexForward=forward,
                             KeyConditionExpression='pk = :p',
                             ExpressionAttributeValues={':p': {'S': part}},
                             **start_key)
            pages += 1
            keys += [int(i['seq']['N']) for i in resp['Items']]
            if 'LastEvaluatedKey' not in resp:
                return keys, pages
            start_key = {'ExclusiveStartKey': resp['LastEvaluatedKey']}
            assert pages <= _N_ITEMS, (
                f'pagination did not terminate: {pages!r} pages for {_N_ITEMS!r} items'
            )

    forward, pages = _page_through(True)
    backward, _ = _page_through(False)

    assert forward == written, (
        f'forward pagination dropped, duplicated or misordered items: first divergence at index '
        f'{next((i for i, v in enumerate(forward) if i >= len(written) or v != written[i]), None)!r} '
        f'of {len(forward)!r} returned'
    )
    assert len(set(forward)) == _N_ITEMS, (
        f'pagination returned a duplicate item: {len(forward) - len(set(forward))!r} duplicates'
    )
    assert backward == list(reversed(written)), (
        f'ScanIndexForward=False is not the exact reverse order: it began {backward[:5]!r}'
    )
    # ceil(200 / 7) = 29 pages; fewer means the service ignored Limit.
    _expected_min_pages = -(-_N_ITEMS // _LIMIT)
    assert pages >= _expected_min_pages, (
        f'the service returned {pages!r} pages for {_N_ITEMS!r} items at Limit={_LIMIT!r}, which '
        f'is fewer than the {_expected_min_pages!r} the limit allows -- Limit was not honoured'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
