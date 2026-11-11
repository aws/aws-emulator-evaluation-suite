"""gsi-query-attributes-to-get-validation."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-query-attributes-to-get-validation"
GROUP = 'gsi'
SERVICES = ['dynamodb']

ERR_VALIDATION = 'ValidationException'
_INDEX = 'gsi1'
_PROPAGATE_S = 180


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the Query to be rejected, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Legacy AttributesToGet on a GSI Query: an empty list, a duplicate name and an attribute the
    index does not project are each ValidationException, while the projected attribute succeeds.
    """
    # AttributesToGet carries a model length-min of 1; the empty-list case needs the request to
    # actually reach the service rather than be rejected by the client's own shape check.
    ddb = ctx.client('dynamodb', config=Config(parameter_validation=False))
    table = ctx.unique_name('sim2real-behav-ddbattg-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'sk', 'AttributeType': 'S'},
                              {'AttributeName': 'gsipk', 'AttributeType': 'S'}],
        GlobalSecondaryIndexes=[{
            'IndexName': _INDEX,
            'KeySchema': [{'AttributeName': 'gsipk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['kept']},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(
        TableName=table, WaiterConfig={'Delay': 1, 'MaxAttempts': 60})

    deadline = time.time() + _PROPAGATE_S
    index_status = None
    while time.time() < deadline:
        described = ddb.describe_table(TableName=table)['Table']
        index_status = {i['IndexName']: i['IndexStatus']
                        for i in described.get('GlobalSecondaryIndexes', [])}
        if index_status.get(_INDEX) == 'ACTIVE':
            break
        time.sleep(2)
    assert index_status.get(_INDEX) == 'ACTIVE', (
        f'{_INDEX} never became ACTIVE within {_PROPAGATE_S}s: {index_status!r}'
    )

    ddb.put_item(TableName=table, Item={'pk': {'S': 'ITEM#1'}, 'sk': {'S': 'S1'},
                                        'gsipk': {'S': 'BUCKET#A'},
                                        'kept': {'S': 'kept-value'},
                                        'dropped': {'S': 'excluded-value'}})

    key_conditions = {'gsipk': {'AttributeValueList': [{'S': 'BUCKET#A'}],
                                'ComparisonOperator': 'EQ'}}

    def query(attributes_to_get):
        return ddb.query(TableName=table, IndexName=_INDEX, KeyConditions=key_conditions,
                         AttributesToGet=attributes_to_get)

    # Positive control: the projected attribute alone is served from the index, once it arrives.
    control_items = []
    deadline = time.time() + _PROPAGATE_S
    while time.time() < deadline:
        control_items = query(['kept'])['Items']
        if control_items:
            break
        time.sleep(1)
    assert control_items == [{'kept': {'S': 'kept-value'}}], (
        f'the control AttributesToGet=["kept"] never returned the projected value within '
        f'{_PROPAGATE_S}s: {control_items!r}'
    )

    # An empty AttributesToGet list.
    code, message = _error(lambda: query([]))
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION!r} for an empty list, got {code!r}'
    assert message == (
        "1 validation error detected: Value at 'AttributesToGet' failed to satisfy constraint: "
        "Member must have length greater than or equal to 1"
    ), f"expected AWS's exact ValidationException message, got {message!r}"

    # A duplicate of the same (projected) attribute name.
    code, message = _error(lambda: query(['kept', 'kept']))
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION!r} for a duplicate name, got {code!r}'
    assert message == 'One or more parameter values were invalid: Duplicate value in attribute name: kept', (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # An attribute the GSI's projection does not carry.
    code, message = _error(lambda: query(['dropped']))
    assert code == ERR_VALIDATION, (
        f'expected {ERR_VALIDATION!r} for an attribute {_INDEX} does not project, got {code!r}'
    )
    assert message == f'One or more parameter values were invalid: Global secondary index {_INDEX} does not project [dropped]', (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # None of the three rejected calls wrote anything: the base table still holds only the one item.
    base = ddb.scan(TableName=table, ConsistentRead=True)
    assert base['Count'] == 1, f'expected the one item put above and nothing else, got {base!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
