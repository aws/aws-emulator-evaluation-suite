"""resource-policy-revision-mismatch."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-revision-mismatch"
GROUP = 'errors'
SERVICES = ['dynamodb']
ERR_POLICY_NOT_FOUND = 'PolicyNotFoundException'


_CLEANUP_S = 900.0  # the suite's cleanup budget, shared by the check's teardowns


def _retry_in_use(fn, cleanup_deadline):
    """Run a delete; retry ResourceInUseException while a policy update settles, not-found is done."""
    deadline = cleanup_deadline.setdefault('t', time.monotonic() + _CLEANUP_S)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code in ('ResourceNotFoundException', ERR_POLICY_NOT_FOUND):
                return
            if code != 'ResourceInUseException' or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error_code(fn):
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING an update real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'expected PutResourcePolicy to be rejected, but it SUCCEEDED: {result!r}')


def _poll_for_revision(ddb, arn, expected_revision, *, timeout_s=60, interval_s=3):
    """PutResourcePolicy's effect on GetResourcePolicy can lag briefly -- a read issued
    immediately after a successful put may still 404 with PolicyNotFoundException. Poll until
    the expected revision is actually visible."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ddb.get_resource_policy(ResourceArn=arn)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') != ERR_POLICY_NOT_FOUND:
                raise
            last = None
        else:
            if last['RevisionId'] == expected_revision:
                return last
        time.sleep(interval_s)
    raise AssertionError(
        f'GetResourcePolicy never reflected revision {expected_revision!r} within {timeout_s}s; last saw {last!r}'
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with an ExpectedRevisionId that is not the current revision raises PolicyNotFoundException with
    the exact message and leaves the policy unchanged; the same update with the current revision applies.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    cleanup_deadline: dict = {}
    ctx.on_cleanup(lambda: _retry_in_use(lambda: ddb.delete_table(TableName=t), cleanup_deadline))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    arn = ddb.describe_table(TableName=t)['Table']['TableArn']
    account_id = arn.split(':')[4]
    policy_v1 = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        f'"Principal":{{"AWS":"arn:aws:iam::{account_id}:root"}},'
        '"Action":"dynamodb:DescribeTable","Resource":"' + arn + '"}]}'
    )
    # Positive control: the initial PutResourcePolicy (no ExpectedRevisionId yet exists) succeeds.
    put1 = ddb.put_resource_policy(ResourceArn=arn, Policy=policy_v1)
    real_revision = put1['RevisionId']
    ctx.on_cleanup(lambda: _retry_in_use(lambda: ddb.delete_resource_policy(ResourceArn=arn), cleanup_deadline))

    # Break exactly one thing: submit a well-formed but never-valid ExpectedRevisionId.
    policy_v2 = policy_v1.replace('DescribeTable', 'GetItem')
    code, message = _error_code(
        lambda: ddb.put_resource_policy(
            ResourceArn=arn, Policy=policy_v2, ExpectedRevisionId='bogus-revision-id-xyz'
        )
    )
    assert code == ERR_POLICY_NOT_FOUND, f'expected {ERR_POLICY_NOT_FOUND}, got {code}'
    expected = (
        'Resource-based policy not found for the provided ResourceArn: Requested update for policy with '
        f'revision id bogus-revision-id-xyz, but the policy associated to target table {t} has revision '
        f'id {real_revision}.'
    )
    assert message == expected, f'expected message {expected!r}, got {message!r}'

    # Effect absent, via an independent read: the rejected update must not have applied. (Bounded
    # retry: PutResourcePolicy's own effect can itself still be propagating to GetResourcePolicy.)
    unchanged = _poll_for_revision(ddb, arn, real_revision)
    assert 'DescribeTable' in unchanged['Policy'], 'rejected mismatched update must not apply'

    # Restore: the identical update, resubmitted with the CURRENT (correct) revision, succeeds.
    put2 = ddb.put_resource_policy(ResourceArn=arn, Policy=policy_v2, ExpectedRevisionId=real_revision)
    assert put2['RevisionId'] != real_revision, 'a successful PutResourcePolicy must advance the RevisionId'

    # Terminal read, independent of the mutating call above: the new policy is what is now stored.
    applied = _poll_for_revision(ddb, arn, put2['RevisionId'])
    assert 'GetItem' in applied['Policy'] and 'DescribeTable' not in applied['Policy'], applied


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
