"""put-scheduled-action-rejects-invalid-cron-expression."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scheduled-action-rejects-invalid-cron-expression"
GROUP = 'scheduled-actions'
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


def _actions(aas, resource_id):
    out = []
    token = None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scheduled_actions(**kwargs)
        out.extend(page['ScheduledActions'])
        token = page.get('NextToken')
        if not token:
            return out


@tags('axis:rejection', 'cap:c1', 'cap:c4', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """PutScheduledAction refuses an unparseable cron, naming the offending position, and stores
    nothing; a valid cron under the same name succeeds, and re-putting that name is an upsert.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-badcron-')
    action = ctx.unique_name('sim2real-behav-aas-cronsa-')
    resource_id = f'table/{table}'

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}, {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120,
                description=f'table {table!r} becoming ACTIVE')
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=10,
                                 Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'})
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    error = _client_error(lambda: aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule='cron(not a cron)', Timezone='UTC',
        ScalableTargetAction={'MinCapacity': 2, 'MaxCapacity': 6}))
    assert error.get('Code') == 'ValidationException', (
        f'an unparseable cron was rejected with {error.get("Code")!r}, expected '
        f'"ValidationException"'
    )
    assert error.get('Message') == (
        'Invalid schedule expression. Details: Invalid CRON expression: error at position 0, '
        "details: Illegal characters for this position: 'NOT'"
    ), (
        f'the rejection message was {error.get("Message")!r}; real AWS reports the parse position '
        f'and the offending token'
    )
    assert _actions(aas, resource_id) == [], (
        'the refused scheduled action was stored anyway; a rejected schedule must leave nothing '
        'behind for a scheduler to trip over later'
    )
    assert ddb.describe_table(TableName=table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits'] == 1, (
        'the refused scheduled action moved the table\'s provisioned read capacity'
    )

    # Positive control: the same name and target with a parseable one-shot cron.
    valid_schedule = 'cron(30 4 15 6 ? 2035)'
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule=valid_schedule, Timezone='UTC',
        ScalableTargetAction={'MinCapacity': 2, 'MaxCapacity': 6})
    stored = _actions(aas, resource_id)
    assert [a['ScheduledActionName'] for a in stored] == [action], (
        f'the positive control did not leave exactly one scheduled action: '
        f'{[a["ScheduledActionName"] for a in stored]!r}'
    )
    assert stored[0]['Schedule'] == valid_schedule, (
        f'the stored schedule came back as {stored[0]["Schedule"]!r}, expected {valid_schedule!r}'
    )
    assert stored[0]['ScalableTargetAction'] == {'MinCapacity': 2, 'MaxCapacity': 6}, (
        f'the stored ScalableTargetAction came back as {stored[0]["ScalableTargetAction"]!r}'
    )

    # The same NAME again with different bounds is an upsert, not a conflict.
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        ScheduledActionName=action, Schedule=valid_schedule, Timezone='UTC',
        ScalableTargetAction={'MinCapacity': 4, 'MaxCapacity': 9})
    upserted = _actions(aas, resource_id)
    assert [a['ScheduledActionName'] for a in upserted] == [action], (
        f're-putting the same scheduled-action name produced '
        f'{[a["ScheduledActionName"] for a in upserted]!r} instead of updating the one entry'
    )
    assert upserted[0]['ScalableTargetAction'] == {'MinCapacity': 4, 'MaxCapacity': 9}, (
        f'the upsert did not replace the bounds: {upserted[0]["ScalableTargetAction"]!r}'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
