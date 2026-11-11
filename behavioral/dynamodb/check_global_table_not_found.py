"""global-table-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-table-not-found"
GROUP = 'errors'
SERVICES = ['dynamodb']


_LEGACY_VERSION_MESSAGE = (
    "One or more parameter values were invalid: DynamoDB global tables version 2017.11.29 is not "
    "supported. We recommend using DynamoDB global tables version 2019.11.21, instead of version "
    "2017.11.29 (Legacy)."
)


def _error_code_and_message(fn):
    """Return fn()'s error code and message; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected a ClientError, but the call SUCCEEDED and returned {result!r}')


def _wait_active(ddb, name, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_global_table(GlobalTableName=name)['GlobalTableDescription']['GlobalTableStatus']
        if status == 'ACTIVE':
            return
        time.sleep(interval_s)
    raise AssertionError(f'global table {name} never reached ACTIVE, last status={status!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Describe/UpdateGlobalTable and Describe/UpdateGlobalTableSettings return
    GlobalTableNotFoundException for an unregistered name; the control is either a working real
    2017.11.29 global table or CreateGlobalTable's version-support ValidationException."""
    ddb = ctx.client('dynamodb')
    real_name = ctx.unique_name('sim2real-behav-gt-')
    fake_name = ctx.unique_name('sim2real-behav-no-such-global-table-')

    ddb.create_table(
        TableName=real_name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'NEW_AND_OLD_IMAGES'},
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=real_name))
    ddb.get_waiter('table_exists').wait(TableName=real_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # CreateGlobalTable is the one call here that may legitimately succeed (where legacy Global
    # Tables is still creatable), so it is caught explicitly rather than through the helper.
    try:
        ddb.create_global_table(GlobalTableName=real_name, ReplicationGroup=[{'RegionName': ctx.region}])
        create_code, create_message = None, None
    except ClientError as exc:
        create_code = exc.response.get('Error', {}).get('Code')
        create_message = exc.response.get('Error', {}).get('Message')
    if create_code is None:
        # Version 2017.11.29 is still creatable here: the calls succeeding on the real global
        # table rule out a blanket GlobalTableNotFoundException.
        _wait_active(ddb, real_name)
        real_describe = ddb.describe_global_table(GlobalTableName=real_name)['GlobalTableDescription']
        assert real_describe['GlobalTableName'] == real_name, real_describe
        ddb.describe_global_table_settings(GlobalTableName=real_name)
        ddb.update_global_table_settings(GlobalTableName=real_name, GlobalTableBillingMode='PAY_PER_REQUEST')
    else:
        # Version 2017.11.29 is withdrawn here: CreateGlobalTable's distinct version-support
        # ValidationException is the control against a blanket GlobalTableNotFoundException.
        assert create_code == 'ValidationException', (
            f'expected ValidationException (legacy Global Tables version withdrawn), got {create_code}'
        )
        assert create_message == _LEGACY_VERSION_MESSAGE, (
            f'expected message {_LEGACY_VERSION_MESSAGE!r}, got {create_message!r}'
        )

    # DescribeGlobalTable/UpdateGlobalTable prefix the not-found text; the two settings
    # operations do not.
    expected_not_found = f"Global table not found: Global table with name: '{fake_name}' does not exist."
    expected_settings_not_found = f"Global table with name: '{fake_name}' does not exist."

    describe_code, describe_message = _error_code_and_message(lambda: ddb.describe_global_table(GlobalTableName=fake_name))
    assert describe_code == 'GlobalTableNotFoundException', f'expected GlobalTableNotFoundException, got {describe_code}'
    assert describe_message == expected_not_found, f'expected message {expected_not_found!r}, got {describe_message!r}'

    # A "Create" replica action can hit the 2017.11.29 version-support ValidationException
    # first; "Delete" still resolves the existence check.
    update_code, update_message = _error_code_and_message(
        lambda: ddb.update_global_table(
            GlobalTableName=fake_name,
            ReplicaUpdates=[{'Delete': {'RegionName': ctx.region}}],
        )
    )
    assert update_code == 'GlobalTableNotFoundException', f'expected GlobalTableNotFoundException, got {update_code}'
    assert update_message == expected_not_found, f'expected message {expected_not_found!r}, got {update_message!r}'

    if create_code is None:
        # The real global table's replication group is untouched by the failed update.
        real_replication_group = ddb.describe_global_table(GlobalTableName=real_name)['GlobalTableDescription'][
            'ReplicationGroup'
        ]
        assert [r['RegionName'] for r in real_replication_group] == [ctx.region], real_replication_group

    settings_describe_code, settings_describe_message = _error_code_and_message(
        lambda: ddb.describe_global_table_settings(GlobalTableName=fake_name)
    )
    assert settings_describe_code == 'GlobalTableNotFoundException', f'expected GlobalTableNotFoundException, got {settings_describe_code}'
    assert settings_describe_message == expected_settings_not_found, (
        f'expected message {expected_settings_not_found!r}, got {settings_describe_message!r}'
    )

    settings_update_code, settings_update_message = _error_code_and_message(
        lambda: ddb.update_global_table_settings(
            GlobalTableName=fake_name,
            GlobalTableBillingMode='PAY_PER_REQUEST',
        )
    )
    assert settings_update_code == 'GlobalTableNotFoundException', f'expected GlobalTableNotFoundException, got {settings_update_code}'
    assert settings_update_message == expected_settings_not_found, (
        f'expected message {expected_settings_not_found!r}, got {settings_update_message!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
