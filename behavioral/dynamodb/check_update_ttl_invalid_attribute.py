"""update-ttl-invalid-attribute."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-ttl-invalid-attribute"
GROUP = 'ttl'
SERVICES = ['dynamodb']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTimeToLive with an empty AttributeName (client validation off) is rejected with ValidationException and
    its exact message and TTL stays DISABLED; the same call with a valid name then returns ENABLING or ENABLED.
    """
    ddb = ctx.client('dynamodb')
    unvalidated_ddb = ctx.client('dynamodb', config=Config(parameter_validation=False))
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    rejected = False
    try:
        unvalidated_ddb.update_time_to_live(
            TableName=t,
            TimeToLiveSpecification={'Enabled': True, 'AttributeName': ''},
        )
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        assert code == 'ValidationException', f'expected ValidationException, got {code}'
        message = exc.response.get('Error', {}).get('Message')
        expected = ("1 validation error detected: Value '' at 'timeToLiveSpecification.attributeName' "
                    "failed to satisfy constraint: Member must have length greater than or equal to 1")
        assert message == expected, f'expected message {expected!r}, got {message!r}'
        rejected = True
    assert rejected, 'an empty TTL AttributeName must be rejected, not silently accepted'

    ttl = ddb.describe_time_to_live(TableName=t)['TimeToLiveDescription']
    assert ttl['TimeToLiveStatus'] == 'DISABLED', ttl

    valid_attr = 'expiresAt'
    ddb.update_time_to_live(
        TableName=t,
        TimeToLiveSpecification={'Enabled': True, 'AttributeName': valid_attr},
    )
    enabled = ddb.describe_time_to_live(TableName=t)['TimeToLiveDescription']
    assert enabled['TimeToLiveStatus'] in ('ENABLING', 'ENABLED'), enabled
    assert enabled.get('AttributeName') == valid_attr, enabled


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
