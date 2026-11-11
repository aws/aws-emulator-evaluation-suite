"""put-resource-policy-oversized."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-oversized"
GROUP = 'errors'
SERVICES = ['dynamodb']

_RETRYABLE = ('ThrottlingException', 'ResourceInUseException')


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, 'response', None)
    if not response:
        return None
    return response.get('Error', {}).get('Code')


def _put_policy_with_retry(ddb, table_arn: str, policy: str, *, timeout_s: float = 90,
                            interval_s: float = 5) -> dict[str, Any]:
    """DynamoDB's resource-policy control-plane enforces a tight per-resource request rate;
    back-to-back PutResourcePolicy calls against a just-created table can transiently 429
    (ThrottlingException) or report the resource as still settling (ResourceInUseException) --
    retry for a bounded time rather than treating either as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ddb.put_resource_policy(ResourceArn=table_arn, Policy=policy)
        except ClientError as exc:
            if _error_code_from_exc(exc) in _RETRYABLE and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _reject_oversized_with_retry(ddb, table_arn: str, policy: str, *, timeout_s: float = 90,
                                  interval_s: float = 5) -> dict[str, Any]:
    """Call PutResourcePolicy with the oversized document, tolerating the same transient
    ThrottlingException/ResourceInUseException as the control put above. An unexpected SUCCESS
    raises rather than returning a falsy sentinel -- an emulator ACCEPTING input real AWS refuses is
    the strongest signal available."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = ddb.put_resource_policy(ResourceArn=table_arn, Policy=policy)
        except ClientError as exc:
            code = _error_code_from_exc(exc)
            if code in _RETRYABLE and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return exc.response.get('Error', {})
        raise AssertionError(
            f'real AWS rejects an oversized resource policy, but PutResourcePolicy SUCCEEDED '
            f'and returned {result!r}')


def _get_policy_matching_sid(ddb, table_arn: str, expected_sid: str, *, timeout_s: float = 60,
                              interval_s: float = 3) -> dict[str, Any]:
    """PutResourcePolicy's effect can lag briefly; a GetResourcePolicy issued immediately after
    may still 404 (PolicyNotFoundException) or briefly return the PREVIOUS statement -- poll
    until the expected statement is actually visible."""
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        try:
            resp = ddb.get_resource_policy(ResourceArn=table_arn)
        except ClientError as exc:
            if _error_code_from_exc(exc) in ('ThrottlingException', 'PolicyNotFoundException'):
                time.sleep(interval_s)
                continue
            raise
        if json.loads(resp['Policy'])['Statement'][0]['Sid'] == expected_sid:
            return resp
        last = resp
        time.sleep(interval_s)
    raise AssertionError(
        f'GetResourcePolicy never reflected Sid={expected_sid!r} within {timeout_s}s; last saw '
        f'{last!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with a policy over 20480 bytes raises ValidationException with the exact size message and
    leaves the table's existing policy and RevisionId unchanged, while an ordinary policy is accepted.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    arn = ddb.describe_table(TableName=t)['Table']['TableArn']
    account_id = arn.split(':')[4]

    def _policy(sid: str) -> str:
        # DynamoDB rejects a Sid containing non-alphanumeric characters (e.g. a hyphen) with a
        # ValidationException before size or content is even considered, so Sid stays alphanumeric.
        return json.dumps({
            'Version': '2012-10-17',
            'Statement': [{
                'Sid': sid,
                'Effect': 'Allow',
                'Principal': {'AWS': f'arn:aws:iam::{account_id}:root'},
                'Action': 'dynamodb:DescribeTable',
                'Resource': arn,
            }],
        })

    # Positive control: an ordinary-sized policy MUST be accepted -- otherwise "rejects the
    # oversized one" is indistinguishable from "rejects every PutResourcePolicy on this table".
    valid_policy = _policy('PositiveControl')
    control_put = _put_policy_with_retry(ddb, arn, valid_policy)
    control_revision = control_put['RevisionId']
    # No separate delete_resource_policy cleanup: DeleteTable removes any attached resource
    # policy with the table, and an extra call here only adds another throttling-prone
    # PutResourcePolicy-surface request to the 60s teardown budget for no benefit.

    control_read = _get_policy_matching_sid(ddb, arn, 'PositiveControl')
    assert control_read['RevisionId'] == control_revision, (
        f'positive control: GetResourcePolicy RevisionId {control_read["RevisionId"]!r} does not '
        f'match the PutResourcePolicy response {control_revision!r}'
    )

    # A syntactically-valid but grossly oversized policy document (the documented resource-policy
    # size ceiling is far smaller than this) built by padding the Sid field.
    oversized_policy = _policy('x' * 500_000)

    error = _reject_oversized_with_retry(ddb, arn, oversized_policy)
    code = error.get('Code')
    message = error.get('Message')
    assert code == 'ValidationException', (
        f'expected a size-limit rejection for an oversized policy, got {code} ({error})'
    )
    expected_message = (
        'One or more parameter values were invalid: Maximum policy size of 20480 bytes exceeded'
    )
    assert message == expected_message, (
        f'expected message {expected_message!r}, got {message!r}'
    )

    # Effect absent, via an independent read at a different operation: the rejected oversized PUT
    # must not have touched the pre-existing policy at all -- not overwritten, not truncated, not
    # revision-bumped.
    after = ddb.get_resource_policy(ResourceArn=arn)
    assert after['RevisionId'] == control_revision, (
        f'a rejected oversized PutResourcePolicy must not change the RevisionId of the existing '
        f'policy, got {after["RevisionId"]!r}, expected unchanged {control_revision!r}'
    )
    assert json.loads(after['Policy']) == json.loads(valid_policy), (
        f'a rejected oversized PutResourcePolicy must leave the existing policy byte-identical, '
        f'got {after["Policy"]!r}, expected {valid_policy!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
