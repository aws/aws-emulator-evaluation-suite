"""global-table-settings-index-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "global-table-settings-index-not-found"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']

_LEGACY_VERSION_MESSAGE = (
    "One or more parameter values were invalid: DynamoDB global tables version 2017.11.29 is not "
    "supported. We recommend using DynamoDB global tables version 2019.11.21, instead of version "
    "2017.11.29 (Legacy)."
)


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message', '')
    raise AssertionError('expected a ClientError but the call succeeded')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For an ACTIVE table, CreateGlobalTable raises the version ValidationException, UpdateGlobalTableSettings naming
    a missing index raises GlobalTableNotFoundException, each with the exact message, and ListGlobalTables
    does not list the table.
    """
    ddb = ctx.client('dynamodb')
    name = ctx.unique_name('sim2real-behav-gt-')
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'gsi_pk', 'AttributeType': 'S'},
        ],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5},
        GlobalSecondaryIndexes=[
            {
                'IndexName': 'real-gsi',
                'KeySchema': [{'AttributeName': 'gsi_pk', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5},
            }
        ],
        StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'NEW_AND_OLD_IMAGES'},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Positive control: the account and this table are otherwise healthy before Global Tables
    # enters the picture at all -- so a later rejection cannot be "everything is denied".
    described = ddb.describe_table(TableName=name)['Table']
    assert described['TableStatus'] == 'ACTIVE', described['TableStatus']

    create_code, create_message = _error_code_and_message(
        lambda: ddb.create_global_table(GlobalTableName=name, ReplicationGroup=[{'RegionName': ctx.region}])
    )
    assert create_code == 'ValidationException', f'expected ValidationException, got {create_code}: {create_message}'
    assert create_message == _LEGACY_VERSION_MESSAGE, (
        f'expected message {_LEGACY_VERSION_MESSAGE!r}, got {create_message!r}'
    )

    # The index-focused call, pointed at a fake index anyway, still fails deterministically with
    # GlobalTableNotFoundException -- nothing here is tracked by the legacy control plane -- rather
    # than ever reaching the per-index validation IndexNotFoundException would come from.
    update_code, update_message = _error_code_and_message(
        lambda: ddb.update_global_table_settings(
            GlobalTableName=name,
            GlobalTableGlobalSecondaryIndexSettingsUpdate=[
                {'IndexName': 'totally-fake-gsi', 'ProvisionedWriteCapacityUnits': 5}
            ],
        )
    )
    assert update_code == 'GlobalTableNotFoundException', f'expected GlobalTableNotFoundException, got {update_code}: {update_message}'
    expected_not_found = f"Global table with name: '{name}' does not exist."
    assert update_message == expected_not_found, f'expected message {expected_not_found!r}, got {update_message!r}'

    # Effect absent, via an independent read at the destination: this table was never registered
    # as a global table.
    listed = ddb.list_global_tables()['GlobalTables']
    assert not any(gt['GlobalTableName'] == name for gt in listed), listed


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
