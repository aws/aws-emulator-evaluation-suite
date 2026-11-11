"""global-table-already-exists."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-table-already-exists"
GROUP = 'errors'
SERVICES = ['dynamodb']

_LEGACY_VERSION_MESSAGE = (
    "One or more parameter values were invalid: DynamoDB global tables version 2017.11.29 is not "
    "supported. We recommend using DynamoDB global tables version 2019.11.21, instead of version "
    "2017.11.29 (Legacy)."
)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _error_code_and_message(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, so an
    emulator that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected a ClientError, but the call SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGlobalTable never succeeds a second time for one name: where the legacy (2017.11.29) API
    still creates, the duplicate is refused GlobalTableAlreadyExistsException; where it is retired,
    the version-support ValidationException repeats identically on a second attempt."""
    ddb = ctx.client('dynamodb')
    table_name = ctx.unique_name('sim2real-behav-gt-')
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'NEW_AND_OLD_IMAGES'},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter('table_exists').wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    try:
        ddb.create_global_table(GlobalTableName=table_name, ReplicationGroup=[{'RegionName': ctx.region}])
        first_code, first_message = None, ''
    except ClientError as exc:
        first_code = exc.response['Error']['Code']
        first_message = exc.response['Error'].get('Message', '')

    if first_code is None:
        # Legacy global tables ARE creatable here -- exercise the real
        # already-exists boundary on a duplicate attempt.
        _poll_until(
            lambda: ddb.describe_global_table(GlobalTableName=table_name)['GlobalTableDescription'],
            lambda d: d.get('GlobalTableStatus') == 'ACTIVE',
            timeout_s=180,
            interval_s=3.0,
            description=f'global table {table_name} ACTIVE',
        )
        code, _message = _error_code_and_message(
            lambda: ddb.create_global_table(GlobalTableName=table_name, ReplicationGroup=[{'RegionName': ctx.region}])
        )
        # Code only: the exact message of this refusal is not known, because current regions
        # refuse a legacy CreateGlobalTable outright.
        assert code == 'GlobalTableAlreadyExistsException', f'expected GlobalTableAlreadyExistsException, got {code}'
    else:
        # Legacy (2017.11.29) global tables can no longer be created at all
        # here -- CreateGlobalTable must reject deterministically and
        # IDENTICALLY on every attempt (never silently succeeding on a retry).
        # The rejection must be the version gate specifically, not just any
        # ValidationException, or this would pass against a target that rejects
        # CreateGlobalTable for an unrelated reason (e.g. a malformed request).
        assert first_code == 'ValidationException', f'expected ValidationException, got {first_code}'
        assert first_message == _LEGACY_VERSION_MESSAGE, (
            f'expected message {_LEGACY_VERSION_MESSAGE!r}, got: {first_message!r}'
        )
        second_code, second_message = _error_code_and_message(
            lambda: ddb.create_global_table(GlobalTableName=table_name, ReplicationGroup=[{'RegionName': ctx.region}])
        )
        assert second_code == 'ValidationException', (
            f'expected the SAME deterministic rejection on a repeated attempt, got {second_code}'
        )
        assert second_message == first_message, (
            f'expected the identical rejection message on a repeated attempt, got: '
            f'{first_message!r} then {second_message!r}'
        )

        # Effect-absent: two rejected CreateGlobalTable calls must not have
        # registered the table as a global table on the side despite the error.
        not_found_code, not_found_message = _error_code_and_message(
            lambda: ddb.describe_global_table(GlobalTableName=table_name)
        )
        assert not_found_code == 'GlobalTableNotFoundException', (
            f'CreateGlobalTable was rejected but the table is registered as a global table anyway '
            f'(describe_global_table returned {not_found_code!r} instead of GlobalTableNotFoundException)'
        )
        expected_not_found = (
            f"Global table not found: Global table with name: '{table_name}' does not exist."
        )
        assert not_found_message == expected_not_found, (
            f'expected message {expected_not_found!r}, got {not_found_message!r}'
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
