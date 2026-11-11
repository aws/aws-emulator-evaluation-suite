"""e2e-event-sourcing."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-event-sourcing"
GROUP = 'e2e_workflows'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Event sourcing: write events for an aggregate, query chronologically, paginate,
    then delete the table and prove it is genuinely gone."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')

    def _delete_table_if_present():
        try:
            ddb.delete_table(TableName=table)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
                raise

    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'aggregate_id', 'KeyType': 'HASH'}, {'AttributeName': 'event_id', 'KeyType': 'RANGE'}], AttributeDefinitions=[{'AttributeName': 'aggregate_id', 'AttributeType': 'S'}, {'AttributeName': 'event_id', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(_delete_table_if_present)
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    aggregate = 'order-abc-123'
    event_types = ['order_created', 'item_added', 'item_added', 'item_removed', 'address_set', 'item_added', 'payment_submitted', 'payment_confirmed', 'shipped', 'delivered']
    for i, event_type in enumerate(event_types):
        ddb.put_item(TableName=table, Item={'aggregate_id': {'S': aggregate}, 'event_id': {'S': f'evt-{i:04d}'}, 'event_type': {'S': event_type}, 'seq': {'N': str(i)}})
    resp = ddb.query(TableName=table, KeyConditionExpression='aggregate_id = :agg', ExpressionAttributeValues={':agg': {'S': aggregate}}, ScanIndexForward=True, ConsistentRead=True)
    assert resp['Count'] == 10, f"Expected 10 events, got {resp['Count']}"
    event_ids = [item['event_id']['S'] for item in resp['Items']]
    assert event_ids == sorted(event_ids), f'Events not in chronological order: {event_ids}'
    all_events: list[dict] = []
    params: dict[str, Any] = {'TableName': table, 'KeyConditionExpression': 'aggregate_id = :agg', 'ExpressionAttributeValues': {':agg': {'S': aggregate}}, 'ScanIndexForward': True, 'Limit': 3, 'ConsistentRead': True}
    pages = 0
    while True:
        page_resp = ddb.query(**params)
        all_events.extend(page_resp['Items'])
        pages += 1
        if 'LastEvaluatedKey' not in page_resp:
            break
        params['ExclusiveStartKey'] = page_resp['LastEvaluatedKey']
    assert len(all_events) == 10, f'Pagination yielded {len(all_events)} events, expected 10'
    assert pages >= 3, f'Expected at least 3 pages with Limit=3, got {pages}'
    paged_ids = [item['event_id']['S'] for item in all_events]
    assert paged_ids == sorted(paged_ids), 'Paginated events lost ordering'
    got_types = [item['event_type']['S'] for item in all_events]
    assert got_types == event_types, f'Reassembled event log mismatched the written sequence: expected {event_types}, got {got_types}'

    ddb.delete_table(TableName=table)
    ddb.get_waiter('table_not_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    try:
        ddb.describe_table(TableName=table)
        raise AssertionError('DescribeTable succeeded on a deleted table')
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        assert code == 'ResourceNotFoundException', f'expected ResourceNotFoundException on a deleted table, got {code}'
        message = exc.response.get('Error', {}).get('Message')
        expected_message = f'Requested resource not found: Table: {table} not found'
        assert message == expected_message, f'expected message {expected_message!r}, got {message!r}'
    try:
        ddb.put_item(TableName=table, Item={'aggregate_id': {'S': aggregate}, 'event_id': {'S': 'evt-post-delete'}})
        raise AssertionError('PutItem succeeded against a deleted table')
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        assert code == 'ResourceNotFoundException', f'expected ResourceNotFoundException writing to a deleted table, got {code}'
        message = exc.response.get('Error', {}).get('Message')
        expected_message = 'Requested resource not found'
        assert message == expected_message, f'expected message {expected_message!r}, got {message!r}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
