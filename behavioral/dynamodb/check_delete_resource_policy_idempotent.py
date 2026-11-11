"""delete-resource-policy-idempotent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-idempotent"
GROUP = 'errors'
SERVICES = ['dynamodb']
ERR_POLICY_NOT_FOUND = 'PolicyNotFoundException'


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An accepted call raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected a ClientError, but the call succeeded: {result!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy on a table without a policy succeeds with an empty RevisionId and attaches nothing,
    while the same call with an ExpectedRevisionId raises PolicyNotFoundException with the exact message.
    """
    ddb = ctx.client('dynamodb')
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

    arn = ddb.describe_table(TableName=t)['Table']['TableArn']

    # Baseline: no policy has ever been attached.
    baseline_code, baseline_msg = _error(lambda: ddb.get_resource_policy(ResourceArn=arn))
    assert baseline_code == ERR_POLICY_NOT_FOUND, baseline_code
    expected_get = f'Resource-based policy not found for the provided ResourceArn: {arn}'
    assert baseline_msg == expected_get, f'expected message {expected_get!r}, got {baseline_msg!r}'

    # Positive control: the claim this check is named for is that a BARE delete against a
    # policy-less resource is idempotent -- it must succeed as a no-op, not raise. Without this,
    # the ExpectedRevisionId negative below cannot be told apart from "DeleteResourcePolicy always
    # rejects when there's no policy", which would falsify the idempotency the check's name asserts.
    resp = ddb.delete_resource_policy(ResourceArn=arn)
    assert resp.get('RevisionId', '') == '', f'expected a no-op with an empty RevisionId, got {resp}'

    # The no-op must not have created a policy as a side effect.
    after_noop_code, after_noop_msg = _error(lambda: ddb.get_resource_policy(ResourceArn=arn))
    assert after_noop_code == ERR_POLICY_NOT_FOUND, after_noop_code
    assert after_noop_msg == expected_get, (
        f'expected message {expected_get!r}, got {after_noop_msg!r}'
    )

    # An ExpectedRevisionId can never match a nonexistent policy.
    code, message = _error(
        lambda: ddb.delete_resource_policy(
            ResourceArn=arn, ExpectedRevisionId='bogus-revision-id-0001'
        )
    )
    assert code == ERR_POLICY_NOT_FOUND, f'expected {ERR_POLICY_NOT_FOUND}, got {code}'
    expected_msg = (
        'Resource-based policy not found for the provided ResourceArn: Requested update for '
        f'policy with revision id bogus-revision-id-0001, but table {t} has no associated policy.'
    )
    assert message == expected_msg, f'expected message {expected_msg!r}, got {message!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
