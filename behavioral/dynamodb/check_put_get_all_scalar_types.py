"""put-get-all-scalar-types."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "put-get-all-scalar-types"
GROUP = 'item_crud'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem/GetItem round-trips all scalar types: S, N, B, BOOL, NULL."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    binary_data = base64.b64encode(b'binary-payload').decode('ascii')
    item = {'pk': {'S': 'types-test'}, 'str_attr': {'S': 'text'}, 'num_attr': {'N': '123.456'}, 'bin_attr': {'B': base64.b64decode(binary_data)}, 'bool_true': {'BOOL': True}, 'bool_false': {'BOOL': False}, 'null_attr': {'NULL': True}}
    ddb.put_item(TableName=table, Item=item)
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'types-test'}}, ConsistentRead=True).get('Item')
    assert got is not None, 'expected an Item in the GetItem response, got none'
    assert got['str_attr'] == {'S': 'text'}, f"expected str_attr {{'S': 'text'}}, got {got.get('str_attr')!r}"
    assert got['num_attr'] == {'N': '123.456'}, f"expected num_attr {{'N': '123.456'}}, got {got.get('num_attr')!r}"
    assert got['bool_true'] == {'BOOL': True}, f"expected bool_true {{'BOOL': True}}, got {got.get('bool_true')!r}"
    assert got['bool_false'] == {'BOOL': False}, f"expected bool_false {{'BOOL': False}}, got {got.get('bool_false')!r}"
    assert got['null_attr'] == {'NULL': True}, f"expected null_attr {{'NULL': True}}, got {got.get('null_attr')!r}"
    assert got['bin_attr']['B'] == base64.b64decode(binary_data), f"expected bin_attr bytes {base64.b64decode(binary_data)!r}, got {got.get('bin_attr', {}).get('B')!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
