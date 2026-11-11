"""query-natural-1mb-page-truncation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-natural-1mb-page-truncation"
GROUP = 'pagination'
SERVICES = ['dynamodb']

# ~50 KB per item -> ~20 items fit in a 1 MB result page, so 40 items must span >= 2 pages.
_ITEM_BYTES = 50 * 1024
_ITEM_COUNT = 40
_ONE_MB = 1024 * 1024
_MAX_PAGES = 12

# The 1 MB budget does not cap the page: a truncated page is the shortest prefix whose size
# exceeds 1 MB (the item crossing the boundary is included), so `page <= 1 MB` would be wrong.


def _item_bytes(item) -> int:
    """DynamoDB item size for an all-string item: UTF-8 length of each name plus its value."""
    return sum(len(name.encode()) + len(val['S'].encode()) for name, val in item.items())


def _page_bytes(items) -> int:
    """The size real AWS charges a result page against its 1 MB budget."""
    return sum(_item_bytes(it) for it in items)


def _assert_minimal_prefix(resp, page_no) -> None:
    """Assert a truncated page is the shortest prefix of the remaining results exceeding 1 MB.

    The page must exceed 1 MB, and dropping its last item must not.
    """
    items = resp['Items']
    total = _page_bytes(items)
    without_last = total - _item_bytes(items[-1])
    assert total > _ONE_MB, (
        f'page {page_no} carries a LastEvaluatedKey, so it was truncated by the 1 MB result-set '
        f'budget and must therefore have reached it: real AWS includes the item that crosses the '
        f'boundary, so the page exceeds 1 MB. Got {total} bytes over {len(items)} items, which is '
        f'{_ONE_MB - total} bytes short -- an implementation truncating before the budget is '
        f'reached hands the caller more pages than AWS would'
    )
    assert without_last <= _ONE_MB, (
        f'page {page_no} must be the SHORTEST prefix exceeding 1 MB, but dropping its last item '
        f'still leaves {without_last} bytes -- more than one item past the budget, so the page is '
        f'over-packed'
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With no Limit, Query truncates at the 1 MB result-set limit: the page is the shortest prefix
    exceeding 1 MB, LastEvaluatedKey is its last item's key, and resuming yields the rest once each.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    payload = 'x' * _ITEM_BYTES
    expected_sks = [f'{i:03d}' for i in range(_ITEM_COUNT)]
    for sk in expected_sks:
        ddb.put_item(TableName=t, Item={'pk': {'S': 'big'}, 'sk': {'S': sk}, 'payload': {'S': payload}})

    kwargs = {
        'TableName': t,
        'KeyConditionExpression': 'pk = :p',
        'ExpressionAttributeValues': {':p': {'S': 'big'}},
        'ConsistentRead': True,
    }
    first = ddb.query(**kwargs)

    assert 'LastEvaluatedKey' in first, (
        f'an unbounded Query over ~{_ITEM_COUNT * _ITEM_BYTES} bytes must truncate at 1 MB and '
        f'return a LastEvaluatedKey; got Count={first["Count"]} and no LastEvaluatedKey'
    )
    assert 0 < first['Count'] < _ITEM_COUNT, (
        f'first page must be a strict subset of the {_ITEM_COUNT} items, got Count={first["Count"]}'
    )
    assert first['Count'] == len(first['Items']), (
        f'Count {first["Count"]} != len(Items) {len(first["Items"])}'
    )
    assert first['ScannedCount'] == first['Count'], (
        f'no FilterExpression, so ScannedCount must equal Count; got '
        f'ScannedCount={first["ScannedCount"]} Count={first["Count"]}'
    )
    _assert_minimal_prefix(first, 1)

    lek = first['LastEvaluatedKey']
    assert set(lek) == {'pk', 'sk'}, (
        f'a base-table Query LastEvaluatedKey carries exactly the table key attributes, got {sorted(lek)}'
    )
    last_item = first['Items'][-1]
    assert lek == {'pk': last_item['pk'], 'sk': last_item['sk']}, (
        f'LastEvaluatedKey {lek} must be the key of the last item on the page '
        f'({{"pk": {last_item["pk"]}, "sk": {last_item["sk"]}}})'
    )

    seen: list[str] = [it['sk']['S'] for it in first['Items']]
    pages = 1
    resp = first
    while 'LastEvaluatedKey' in resp:
        assert pages < _MAX_PAGES, f'pagination did not terminate within {_MAX_PAGES} pages'
        resp = ddb.query(**kwargs, ExclusiveStartKey=resp['LastEvaluatedKey'])
        pages += 1
        if 'LastEvaluatedKey' in resp:
            _assert_minimal_prefix(resp, pages)
        else:
            # The terminal page is whatever is left, so it is bounded by the budget rather than
            # reaching it. Only the upper bound is meaningful here.
            tail_bytes = _page_bytes(resp['Items'])
            assert tail_bytes <= _ONE_MB + _item_bytes(resp['Items'][-1]), (
                f'the terminal page must still respect the budget to within the single item that '
                f'may cross it; page {pages} was {tail_bytes} bytes'
            )
        seen.extend(it['sk']['S'] for it in resp['Items'])

    assert pages >= 2, f'expected at least 2 pages at 1 MB granularity, got {pages}'
    assert len(seen) == len(set(seen)), (
        f'pagination returned duplicates: {len(seen)} rows, {len(set(seen))} distinct'
    )
    assert seen == expected_sks, (
        f'paginated Query must return all {_ITEM_COUNT} sort keys in order across {pages} pages; '
        f'got {len(seen)} keys, first divergence at index '
        f'{next((i for i, (a, b) in enumerate(zip(seen, expected_sks)) if a != b), len(seen))}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
