"""error-validation-empty-key."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-validation-empty-key"
GROUP = 'errors'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetItem with empty string key value raises ValidationException; a non-empty key on the
    same table still succeeds, proving the table itself is healthy and this isn't a target that
    rejects every GetItem."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={'pk': {'S': 'valid-key'}})
    control = ddb.get_item(TableName=table, Key={'pk': {'S': 'valid-key'}}, ConsistentRead=True)
    assert 'Item' in control, f'positive control: expected Item for a non-empty key, got {control}'

    try:
        ddb.get_item(TableName=table, Key={'pk': {'S': ''}}, ConsistentRead=True)
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        message = exc.response.get('Error', {}).get('Message')
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}'
    assert message == "One or more parameter values are not valid. The AttributeValue for a key attribute cannot contain an empty string value. Key: pk", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
