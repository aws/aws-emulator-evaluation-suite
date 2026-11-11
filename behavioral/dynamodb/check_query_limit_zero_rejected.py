"""query-limit-zero-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-limit-zero-rejected"
GROUP = 'query'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; an accepted call fails the check."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get('Error', {})
        return error.get('Code'), error.get('Message')
    raise AssertionError('expected the call to be refused, but it succeeded')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query and Scan with Limit=0, sent without client-side validation, raise ValidationException with the exact
    message, while the same Query and Scan with Limit=1 find the item.
    """
    ddb = ctx.client('dynamodb')
    ddb_raw = ctx.client('dynamodb', config=Config(parameter_validation=False))
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=t, Item={'pk': {'S': 'lz-1'}})

    query_control = ddb.query(
        TableName=t,
        KeyConditionExpression='pk = :p',
        ExpressionAttributeValues={':p': {'S': 'lz-1'}},
        Limit=1,
    )
    assert query_control['Count'] == 1, f'expected positive-control Query(Limit=1) to find the item, got Count={query_control["Count"]}'

    scan_control = ddb.scan(TableName=t, Limit=1)
    assert scan_control['Count'] == 1, f'expected positive-control Scan(Limit=1) to find the item, got Count={scan_control["Count"]}'

    query_limit_message = (
        "1 validation error detected: Value at 'Limit' failed to satisfy constraint: "
        'Member must have value greater than or equal to 1'
    )
    query_code, query_message = _error(
        lambda: ddb_raw.query(
            TableName=t,
            KeyConditionExpression='pk = :p',
            ExpressionAttributeValues={':p': {'S': 'lz-1'}},
            Limit=0,
        )
    )
    assert query_code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {query_code}'
    assert query_message == query_limit_message, f'unexpected Query message {query_message!r}'

    scan_code, scan_message = _error(lambda: ddb_raw.scan(TableName=t, Limit=0))
    assert scan_code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {scan_code}'
    # Scan words the same refusal differently from Query (lowercase member name, quoted value).
    scan_limit_message = (
        "1 validation error detected: Value '0' at 'limit' failed to satisfy constraint: "
        'Member must have value greater than or equal to 1'
    )
    assert scan_message == scan_limit_message, f'unexpected Scan message {scan_message!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
