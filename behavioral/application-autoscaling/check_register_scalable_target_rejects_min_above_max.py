"""register-scalable-target-rejects-min-above-max."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-scalable-target-rejects-min-above-max"
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
    """Call fn() and return its botocore error response; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
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
    """MinCapacity above MaxCapacity is refused with ValidationException, and because the call is an
    upsert, the existing (1, 10) target is left exactly as it was and stays updatable afterwards.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-minmax-')
    resource_id = f'table/{table}'

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120,
                description=f'table {table!r} becoming ACTIVE')

    # Positive control: the same call shape, valid bounds.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    before = _targets(aas, resource_id)
    assert len(before) == 1 and (before[0]['MinCapacity'], before[0]['MaxCapacity']) == (1, 10), (
        f'the positive control did not register (1, 10): {before!r}'
    )

    response = _client_error(lambda: aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=9, MaxCapacity=2))
    error = response.get('Error', {})
    assert error.get('Code') == 'ValidationException', (
        f'an inverted (9, 2) bound pair was rejected with {error.get("Code")!r}, expected '
        f'"ValidationException"'
    )
    status = response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert status == 400, f'the inverted-bounds rejection carried HTTP {status!r}, expected 400'
    expected_message = "Maximum capacity cannot be less than minimum capacity"
    assert error.get('Message') == expected_message, f"expected the message {expected_message!r}, got {error.get('Message')!r}"

    after = _targets(aas, resource_id)
    assert len(after) == 1, (
        f'the rejected upsert changed how many targets exist: {after!r}'
    )
    assert (after[0]['MinCapacity'], after[0]['MaxCapacity']) == (1, 10), (
        f'the rejected upsert still moved the bounds to '
        f'({after[0]["MinCapacity"]}, {after[0]["MaxCapacity"]}); a refused call must leave the '
        f'target at (1, 10)'
    )
    assert after[0]['ScalableTargetARN'] == before[0]['ScalableTargetARN'], (
        f'the target ARN changed from {before[0]["ScalableTargetARN"]!r} to '
        f'{after[0]["ScalableTargetARN"]!r} across a refused call'
    )
    assert ddb.describe_table(TableName=table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits'] == 1, (
        'the refused registration moved the table\'s provisioned read capacity'
    )

    # Positive control after the rejection: the target is still usable, so the refusal did not
    # wedge it.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=9)
    reused = _targets(aas, resource_id)
    assert (reused[0]['MinCapacity'], reused[0]['MaxCapacity']) == (1, 9), (
        f'the target could not be updated after the rejection: {reused!r}'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
