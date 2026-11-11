"""resource-policy-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-not-found"
GROUP = 'errors'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _delete_table_past_lock(ddb, table_name, *, timeout_s=50.0, interval_s=5.0):
    """DeleteTable can hit a transient ResourceInUseException while the
    resource-policy mutations this check just issued against the same table
    are still settling -- retry past that instead of leaking the table."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            if exc.response['Error']['Code'] != 'ResourceInUseException' or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; an accepted call fails the check."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get('Error', {})
        return error.get('Code'), error.get('Message')
    raise AssertionError('expected the call to be refused, but it succeeded')


def _error_code_past_throttle(fn, *, timeout_s=60.0, interval_s=5.0):
    """Call fn() and return ("SUCCESS", None) or the ClientError's (code, message) --
    retrying while that code is ThrottlingException or ResourceInUseException.
    Resource-policy mutations on the SAME resource are rate-limited to roughly
    one per ~15s (ThrottlingException), and a mutation issued shortly after a
    prior Put/Get on the same table can also see a transient
    ResourceInUseException while that mutation's own in-flight lock settles --
    a check that issues back-to-back Put/Get/Delete/Delete calls must ride out
    both rather than treating either as the behavior under test."""
    def _attempt():
        try:
            fn()
            return 'SUCCESS', None
        except ClientError as exc:
            return exc.response['Error']['Code'], exc.response['Error'].get('Message')
    return _poll_until(
        _attempt,
        lambda r: r[0] not in ('ThrottlingException', 'ResourceInUseException'),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description='past resource-policy modification-rate cooldown',
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on a table without a policy raises PolicyNotFoundException with the exact message; an attached
    policy reads back, DeleteResourcePolicy removes it, and a repeat delete succeeds while Get raises the same error.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: _delete_table_past_lock(ddb, t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    arn = ddb.describe_table(TableName=t)['Table']['TableArn']

    not_found_message = f'Resource-based policy not found for the provided ResourceArn: {arn}'
    baseline_code, baseline_message = _error(lambda: ddb.get_resource_policy(ResourceArn=arn))
    assert baseline_code == 'PolicyNotFoundException', f'expected PolicyNotFoundException, got {baseline_code}'
    assert baseline_message == not_found_message, f'unexpected message {baseline_message!r}'

    account_id = arn.split(':')[4]
    policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        f'"Principal":{{"AWS":"arn:aws:iam::{account_id}:root"}},'
        '"Action":"dynamodb:DescribeTable","Resource":"' + arn + '"}]}'
    )
    put_resp = ddb.put_resource_policy(ResourceArn=arn, Policy=policy)
    revision = put_resp['RevisionId']

    # GetResourcePolicy is eventually-consistent immediately after a Put.
    def _get_policy():
        try:
            return ('ok', ddb.get_resource_policy(ResourceArn=arn))
        except ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'PolicyNotFoundException':
                return ('pending', None)
            raise

    _, attached = _poll_until(
        _get_policy,
        lambda r: r[0] == 'ok',
        timeout_s=30,
        interval_s=2.0,
        description='policy visible after PutResourcePolicy',
    )
    assert attached['RevisionId'] == revision, attached
    assert 'DescribeTable' in attached['Policy'], attached

    # First deletion -- a write against the same resource shortly after the
    # Put, so ride out DynamoDB's resource-policy modification-rate cooldown.
    first_delete_result, _ = _error_code_past_throttle(lambda: ddb.delete_resource_policy(ResourceArn=arn))
    assert first_delete_result == 'SUCCESS', f'expected DeleteResourcePolicy to succeed, got {first_delete_result}'

    def _get_after_delete():
        try:
            ddb.get_resource_policy(ResourceArn=arn)
            return 'still-present', None
        except ClientError as exc:
            return exc.response['Error']['Code'], exc.response['Error'].get('Message')

    final_code, final_message = _poll_until(
        _get_after_delete,
        lambda r: r[0] == 'PolicyNotFoundException',
        timeout_s=30,
        interval_s=2.0,
        description='policy gone after DeleteResourcePolicy',
    )
    assert final_code == 'PolicyNotFoundException', final_code
    assert final_message == not_found_message, f'unexpected message {final_message!r}'

    # DeleteResourcePolicy is idempotent: calling it again once the policy is
    # already gone succeeds as a no-op -- a second write against the same
    # resource in quick succession, so ride out the modification-rate cooldown.
    redelete_code, _ = _error_code_past_throttle(lambda: ddb.delete_resource_policy(ResourceArn=arn))
    assert redelete_code == 'SUCCESS', f'expected DeleteResourcePolicy to be an idempotent no-op success, got {redelete_code}'

    # Independent terminal read: the idempotent redelete must not have a side
    # effect of its own (e.g. leaving a policy behind) -- confirm via a fresh
    # GetResourcePolicy, not the redelete call's own response.
    still_absent_code, still_absent_message = _error_code_past_throttle(
        lambda: ddb.get_resource_policy(ResourceArn=arn)
    )
    assert still_absent_code == 'PolicyNotFoundException', (
        f'expected no policy to exist after the idempotent redelete, got {still_absent_code}'
    )
    assert still_absent_message == not_found_message, f'unexpected message {still_absent_message!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
