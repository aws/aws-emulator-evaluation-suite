"""put-get-collection-types."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-get-collection-types"
GROUP = 'item_crud'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem/GetItem round-trips collection types: L, M, SS, NS, BS."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real-behav', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    item = {'pk': {'S': 'collections'}, 'string_set': {'SS': ['a', 'b', 'c']}, 'number_set': {'NS': ['1', '2', '3']}, 'binary_set': {'BS': [b'x', b'y', b'z']}, 'list_attr': {'L': [{'S': 'x'}, {'N': '42'}, {'BOOL': True}]}, 'map_attr': {'M': {'nested': {'S': 'value'}, 'count': {'N': '7'}}}}
    ddb.put_item(TableName=table, Item=item)
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'collections'}}, ConsistentRead=True).get('Item')
    assert set(got['string_set']['SS']) == {'a', 'b', 'c'}, f"SS round-trip: expected {{'a','b','c'}}, got {got.get('string_set')}"
    assert set(got['number_set']['NS']) == {'1', '2', '3'}, f"NS round-trip: expected {{'1','2','3'}}, got {got.get('number_set')}"
    assert set(got['binary_set']['BS']) == {b'x', b'y', b'z'}, f"BS round-trip: expected {{b'x',b'y',b'z'}}, got {got.get('binary_set')}"
    assert got['list_attr'] == {'L': [{'S': 'x'}, {'N': '42'}, {'BOOL': True}]}, f"L round-trip: expected [S,N,BOOL] list, got {got.get('list_attr')}"
    assert got['map_attr'] == {'M': {'nested': {'S': 'value'}, 'count': {'N': '7'}}}, f"M round-trip: expected nested map, got {got.get('map_attr')}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
