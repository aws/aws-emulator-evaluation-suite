"""describe-scheduled-actions-pages-past-fifty."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-scheduled-actions-pages-past-fifty"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_PROV = {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}



def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _create_table(ctx, ddb, name, **extra):
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=extra.pop('AttributeDefinitions',
                                       [{'AttributeName': 'pk', 'AttributeType': 'S'}]),
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
        **extra,
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, name))
    _poll_until(lambda: ddb.describe_table(TableName=name)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=180, description=f'table {name!r} ACTIVE')


def _delete_table(ddb, name):
    """DeleteTable refuses while the table is UPDATING; retry that, bounded."""
    deadline = time.monotonic() + 45
    while True:
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException' or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _deregister(aas, ns, resource_id, dim):
    try:
        aas.deregister_scalable_target(ServiceNamespace=ns, ResourceId=resource_id,
                                       ScalableDimension=dim)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ObjectNotFoundException':
            raise


def _targets(aas, ns, resource_id):
    out = []
    for page in aas.get_paginator('describe_scalable_targets').paginate(
            ServiceNamespace=ns, ResourceIds=[resource_id]):
        out.extend(page['ScalableTargets'])
    return out


@tags('axis:happy-path', 'cap:c1', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """DescribeScheduledActions pages fifty at a time: 55 actions come back as 50 with a NextToken
    then 5 without, each action exactly once with its own schedule and bounds; the paginator agrees.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-sa55-')
    _create_table(ctx, ddb, table, BillingMode='PROVISIONED', ProvisionedThroughput=_PROV)
    resource_id = f'table/{table}'
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, _NS, resource_id, _DIM))

    expected = {}
    for i in range(55):
        name = f'nightly-{i:02d}'
        schedule = f'cron({i} 3 * * ? *)'
        bounds = (1, 2 + i % 7)
        aas.put_scheduled_action(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            ScheduledActionName=name, Schedule=schedule,
            ScalableTargetAction={'MinCapacity': bounds[0], 'MaxCapacity': bounds[1]})
        expected[name] = (schedule, bounds)

    first = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id)
    token = first.get('NextToken')
    assert len(first['ScheduledActions']) == 50 and token, (
        f'the first page held {len(first["ScheduledActions"])} actions with NextToken '
        f'{"present" if token else "absent"}; 55 actions page as 50 plus a token')
    second = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id,
                                            NextToken=token)
    assert len(second['ScheduledActions']) == 5 and not second.get('NextToken'), (
        f'the second page held {len(second["ScheduledActions"])} actions with NextToken '
        f'{"present" if second.get("NextToken") else "absent"}; the remaining 5 end the listing')

    listed = [a['ScheduledActionName'] for p in (first, second) for a in p['ScheduledActions']]
    assert len(listed) == len(set(listed)), (
        f'an action was listed on both pages: {sorted(n for n in listed if listed.count(n) > 1)!r}')
    got = {a['ScheduledActionName']: (a['Schedule'], (a['ScalableTargetAction']['MinCapacity'],
                                                      a['ScalableTargetAction']['MaxCapacity']))
           for p in (first, second) for a in p['ScheduledActions']}
    assert got == expected, (
        f'the pages differ from what was put: missing {sorted(set(expected) - set(got))!r}, '
        f'extra {sorted(set(got) - set(expected))!r}, changed '
        f'{sorted(n for n in set(got) & set(expected) if got[n] != expected[n])!r}')
    assert all(a['ResourceId'] == resource_id and a['ScalableDimension'] == _DIM
               for p in (first, second) for a in p['ScheduledActions']), (
        'a listed action names a different resource or dimension than the one filtered on')

    sizes = [len(p['ScheduledActions']) for p in aas.get_paginator(
        'describe_scheduled_actions').paginate(ServiceNamespace=_NS, ResourceId=resource_id)]
    assert sizes == [50, 5], f'the SDK paginator walked pages of {sizes!r}, expected [50, 5]'


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
