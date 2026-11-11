"""register-scalable-target-rejects-nonexistent-table."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-scalable-target-rejects-nonexistent-table"
GROUP = 'scalable-targets'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(
        f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


def _delete_table(ddb, name):
    for _ in range(8):
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException':
                raise RuntimeError(f'table {name!r} not deleted: {code}') from exc
            time.sleep(6)
    raise RuntimeError(f'table {name!r} still ResourceInUseException after retries')


def _deregister(aas, resource_id):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=_DIM)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ObjectNotFoundException':
            raise


def _targets(aas, resource_id):
    out = []
    token = None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceIds': [resource_id]}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scalable_targets(**kwargs)
        out.extend(page['ScalableTargets'])
        token = page.get('NextToken')
        if not token:
            return out


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """Registering a target for a nonexistent DynamoDB table is refused and leaves no target behind;
    the identical registration against an existing table succeeds as a positive control.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    absent_table = ctx.unique_name('sim2real-behav-aas-absent-')
    real_table = ctx.unique_name('sim2real-behav-aas-present-')
    absent_id = f'table/{absent_table}'
    real_id = f'table/{real_table}'

    # The table must genuinely not exist for the claim to mean anything.
    missing = _client_error(lambda: ddb.describe_table(TableName=absent_table))
    assert missing.get('Code') == 'ResourceNotFoundException', (
        f'the table this check assumes is absent answered DescribeTable with '
        f'{missing.get("Code")!r}'
    )

    error = _client_error(lambda: aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=absent_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=4))
    assert error.get('Code') == 'ValidationException', (
        f'registering a target for a nonexistent table was rejected with '
        f'{error.get("Code")!r}, expected "ValidationException"'
    )
    assert error.get('Message') == f'DynamoDB table does not exist: {absent_id}', (
        f'the rejection message was {error.get("Message")!r}, expected '
        f'"DynamoDB table does not exist: {absent_id}"'
    )
    assert _targets(aas, absent_id) == [], (
        f'a scalable target exists for {absent_id!r} after the registration was refused'
    )

    # Positive control: the same call, same dimension, against a table that exists.
    ddb.create_table(
        TableName=real_table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, real_table))
    _poll_until(lambda: ddb.describe_table(TableName=real_table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120,
                description=f'table {real_table!r} becoming ACTIVE')
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=real_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=4)
    ctx.on_cleanup(lambda: _deregister(aas, real_id))
    registered = _targets(aas, real_id)
    assert len(registered) == 1, (
        f'the positive control did not register exactly one target: {registered!r}'
    )
    assert (registered[0]['MinCapacity'], registered[0]['MaxCapacity']) == (1, 4), (
        f'the positive control registered '
        f'({registered[0]["MinCapacity"]}, {registered[0]["MaxCapacity"]}), expected (1, 4)'
    )
    assert _targets(aas, absent_id) == [], (
        f'registering the real table also produced a target for {absent_id!r}'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
