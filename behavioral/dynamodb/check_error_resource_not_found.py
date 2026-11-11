"""error-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-resource-not-found"
GROUP = 'errors'
SERVICES = ['dynamodb']
ERR_RESOURCE_NOT_FOUND = 'ResourceNotFoundException'


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTable on a table that was never created raises ResourceNotFoundException, while
    the identical call against a real table in the same account succeeds — proving the rejection
    is specific to the missing table, not a blanket DescribeTable failure."""
    ddb = ctx.client('dynamodb')

    real_name = ctx.unique_name('sim2real-behav-rnf-')
    ddb.create_table(
        TableName=real_name,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=real_name))
    ddb.get_waiter('table_exists').wait(TableName=real_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    control = ddb.describe_table(TableName=real_name)['Table']
    assert control['TableName'] == real_name, (
        f'positive control failed: expected DescribeTable({real_name!r}) to succeed, '
        f'got TableName={control.get("TableName")!r}'
    )

    ghost = f'{real_name}-ghost'
    code, message = _error_code(lambda: ddb.describe_table(TableName=ghost))
    assert code == ERR_RESOURCE_NOT_FOUND, (
        f'expected {ERR_RESOURCE_NOT_FOUND} for DescribeTable on a table that was never '
        f'created, got {code}'
    )
    assert message == f"Requested resource not found: Table: {ghost} not found", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {message!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a lookup real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(
        f'real AWS rejects DescribeTable on a table that was never created, but it SUCCEEDED '
        f'and returned {result!r}'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
