"""resource-policy-lifecycle."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-lifecycle"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each PutResourcePolicy returns a new RevisionId that GetResourcePolicy reports with the latest document, and
    after DeleteResourcePolicy, GetResourcePolicy raises PolicyNotFoundException with the exact message.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    arn = ddb.describe_table(TableName=t)['Table']['TableArn']
    account_id = arn.split(':')[4]
    policy_doc_v1 = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        f'"Principal":{{"AWS":"arn:aws:iam::{account_id}:root"}},'
        '"Action":"dynamodb:DescribeTable","Resource":"' + arn + '"}]}'
    )
    put1 = _put_policy_with_retry(ddb, arn, policy_doc_v1)
    rev1 = put1['RevisionId']
    assert rev1, f'PutResourcePolicy returned no RevisionId: {put1}'

    got1 = _get_policy_containing(ddb, arn, 'DescribeTable')
    assert got1['RevisionId'] == rev1, got1
    assert 'DescribeTable' in got1['Policy'], got1

    policy_doc_v2 = policy_doc_v1.replace('DescribeTable', 'GetItem')
    put2 = _put_policy_with_retry(ddb, arn, policy_doc_v2, expected_revision_id=rev1)
    rev2 = put2['RevisionId']
    assert rev2 != rev1, 'a successful policy update must yield a new RevisionId'

    got2 = _get_policy_containing(ddb, arn, 'GetItem')
    assert 'GetItem' in got2['Policy'], got2

    _delete_policy_with_retry(ddb, arn, rev2)
    code, message = _poll_until(
        lambda: _get_policy_outcome(ddb, arn),
        lambda r: r[0] == 'PolicyNotFoundException',
        timeout_s=60,
        interval_s=3,
    )
    assert code == 'PolicyNotFoundException', f'expected PolicyNotFoundException, got {code}'
    expected = f'Resource-based policy not found for the provided ResourceArn: {arn}'
    assert message == expected, f'unexpected message {message!r}'


def _error_code_from_exc(exc: ClientError) -> str | None:
    response = getattr(exc, 'response', None)
    if not response:
        return None
    return response.get('Error', {}).get('Code')


def _put_policy_with_retry(
    ddb: Any, arn: str, policy: str, *, expected_revision_id: str | None = None,
    timeout_s: float = 90, interval_s: float = 5,
) -> dict[str, Any]:
    # DynamoDB's resource-policy control-plane surface enforces a tight per-resource request
    # rate; back-to-back Put/Get/Delete ResourcePolicy calls against a just-created table can
    # transiently 429 (ThrottlingException) or report the resource as still settling
    # (ResourceInUseException) -- retry for a bounded time rather than treating either as a hard
    # failure.
    kwargs: dict[str, Any] = {'ResourceArn': arn, 'Policy': policy}
    if expected_revision_id is not None:
        kwargs['ExpectedRevisionId'] = expected_revision_id
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ddb.put_resource_policy(**kwargs)
        except ClientError as exc:
            code = _error_code_from_exc(exc)
            if code in ('ThrottlingException', 'ResourceInUseException') and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_policy_with_retry(
    ddb: Any, arn: str, expected_revision_id: str, *, timeout_s: float = 120, interval_s: float = 10,
) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_resource_policy(ResourceArn=arn, ExpectedRevisionId=expected_revision_id)
            return
        except ClientError as exc:
            code = _error_code_from_exc(exc)
            if code in ('ThrottlingException', 'ResourceInUseException') and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _get_policy_outcome(ddb: Any, arn: str) -> tuple[str | None, str | None]:
    """(code, message) of GetResourcePolicy's refusal, or ('still-present', None) while it succeeds."""
    try:
        ddb.get_resource_policy(ResourceArn=arn)
    except ClientError as exc:
        return _error_code_from_exc(exc), exc.response.get('Error', {}).get('Message')
    return 'still-present', None


def _get_policy_containing(
    ddb: Any, arn: str, needle: str, *, timeout_s: float = 60, interval_s: float = 3,
) -> dict[str, Any]:
    # PutResourcePolicy's effect can lag briefly; a GetResourcePolicy issued immediately after
    # may still 404 (PolicyNotFoundException) or briefly return the PREVIOUS statement -- poll
    # until the expected content is actually visible.
    def _attempt() -> dict[str, Any] | None:
        try:
            resp = ddb.get_resource_policy(ResourceArn=arn)
        except ClientError as exc:
            code = _error_code_from_exc(exc)
            if code in ('ThrottlingException', 'PolicyNotFoundException'):
                return None
            raise
        if needle in resp['Policy']:
            return resp
        return None

    return _poll_until(_attempt, lambda r: r is not None, timeout_s=timeout_s, interval_s=interval_s)


def _poll_until(
    probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'condition not met within {timeout_s}s, last value: {last!r}')


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
