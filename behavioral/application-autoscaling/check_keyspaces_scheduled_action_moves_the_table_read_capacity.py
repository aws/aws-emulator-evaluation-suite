"""keyspaces-scheduled-action-moves-the-table-read-capacity."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "keyspaces-scheduled-action-moves-the-table-read-capacity"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'cassandra'
_READ = 'cassandra:table:ReadCapacityUnits'
_FIRING_TIMEOUT_S = 300


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:data-plane', 'concern:representation',
      'dp:api', 'plane:data', 'timing:real-time')
def run(ctx) -> None:
    """A one-time scheduled action on a Keyspaces table's read dimension raises the floor when it
    fires and the new floor reaches the table: Keyspaces reports the read capacity the action set,
    and the write capacity it never named is untouched.
    """
    ks = ctx.client('keyspaces')
    aas = ctx.client('application-autoscaling')
    keyspace, table = _keyspaces_table(ctx, read=1, write=1)
    resource_id = f'keyspace/{keyspace}/table/{table}'
    action = ctx.unique_name('sim2real-behav-aas-ks-sa-')

    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_READ, MinCapacity=1, MaxCapacity=10)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id, _READ))

    schedule, fire_at = _next_minute_at()
    # Deregistering the target deletes its scheduled actions, so the target's cleanup covers it.
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_READ,
        ScheduledActionName=action, Schedule=schedule,
        ScalableTargetAction={'MinCapacity': 4, 'MaxCapacity': 10},
    )

    activities = _poll_until(
        lambda: _activities(aas, resource_id, _READ),
        lambda acts: len(acts) >= 2 and all(a['StatusCode'] == 'Successful' for a in acts),
        timeout_s=_FIRING_TIMEOUT_S, interval_s=5.0,
        description=f'the action firing at {fire_at.isoformat()} and the scale-out it causes, '
                    f'both Successful')
    assert len(activities) == 2, (
        f'expected the dispatch and one scale-out, saw {len(activities)}: '
        f'{[(a["Cause"], a["Description"]) for a in activities]!r}')
    scale_out, dispatch = activities[0], activities[1]
    assert dispatch['Cause'] == f'scheduled action name {action} was triggered', (
        f'the older activity has cause {dispatch["Cause"]!r}, expected the dispatch of {action!r}')
    assert dispatch['Description'] == 'Setting min capacity to 4 and max capacity to 10', (
        f'the dispatch described itself as {dispatch["Description"]!r}')
    assert scale_out['Cause'] == 'minimum capacity was set to 4', (
        f'the follow-on activity cause was {scale_out["Cause"]!r}; a floor of 4 above a live '
        f'capacity of 1 is recorded as "minimum capacity was set to 4"')
    assert scale_out['Description'] == 'Setting table read capacity units to 4.', (
        f'the follow-on activity described itself as {scale_out["Description"]!r}')
    assert scale_out['StatusMessage'] == (
        'Successfully set table read capacity units to 4. Change successfully fulfilled by '
        'cassandra.'
    ), f'the scale-out status message was {scale_out["StatusMessage"]!r}'

    target = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[resource_id],
                                           ScalableDimension=_READ)['ScalableTargets']
    assert [(t['MinCapacity'], t['MaxCapacity']) for t in target] == [(4, 10)], (
        f'the registered bounds read back as '
        f'{[(t["MinCapacity"], t["MaxCapacity"]) for t in target]!r}, expected [(4, 10)]')
    spec = _poll_until(
        lambda: ks.get_table(keyspaceName=keyspace, tableName=table),
        lambda t: t['status'] == 'ACTIVE', timeout_s=180, interval_s=5.0,
        description=f'table {table!r} settling ACTIVE')['capacitySpecification']
    assert spec['throughputMode'] == 'PROVISIONED', (
        f'the table switched to {spec["throughputMode"]!r}; scaling never changes the mode')
    assert spec['readCapacityUnits'] == 4, (
        f'Keyspaces reports {spec["readCapacityUnits"]} read capacity units; the scheduled floor '
        f'of 4 must reach the table')
    assert spec['writeCapacityUnits'] == 1, (
        f'write capacity moved to {spec["writeCapacityUnits"]}; only reads were scheduled')


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description='condition'):
    """Bounded retry with a deadline that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _keyspaces_table(ctx, *, read, write):
    """A fresh keyspace holding one PROVISIONED table, both ACTIVE; returns (keyspace, table)."""
    ks = ctx.client('keyspaces')
    keyspace = ctx.unique_name('sim2real_aas_ks_')
    table = 'sim2real_t'
    ks.create_keyspace(keyspaceName=keyspace, tags=[{'key': 'sim2real', 'value': CHECK}])
    ctx.on_cleanup(lambda: _delete_keyspace(ks, keyspace))
    _poll_until(lambda: _keyspace_exists(ks, keyspace), bool, timeout_s=120, interval_s=3.0,
                description=f'keyspace {keyspace!r} becoming readable')
    ks.create_table(
        keyspaceName=keyspace, tableName=table,
        schemaDefinition={'allColumns': [{'name': 'pk', 'type': 'text'}],
                          'partitionKeys': [{'name': 'pk'}]},
        capacitySpecification=_capacity(read, write),
        tags=[{'key': 'sim2real', 'value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ks, keyspace, table))
    _poll_until(lambda: _table_status(ks, keyspace, table),
                lambda s: s == 'ACTIVE', timeout_s=300, interval_s=5.0,
                description=f'table {keyspace}.{table} becoming ACTIVE')
    return keyspace, table


def _table_status(ks, keyspace, table):
    """The table's status; a table not yet readable after CreateTable reads as None."""
    try:
        return ks.get_table(keyspaceName=keyspace, tableName=table)['status']
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise
        return None


def _keyspace_exists(ks, keyspace):
    try:
        ks.get_keyspace(keyspaceName=keyspace)
        return True
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise
        return False


def _delete_table(ks, keyspace, table):
    deadline = time.monotonic() + 40
    while True:
        try:
            ks.delete_table(keyspaceName=keyspace, tableName=table)
            return
        except ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'ResourceNotFoundException':
                return
            if code != 'ConflictException' or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _delete_keyspace(ks, keyspace):
    """Delete the keyspace; a table still being deleted inside it is a ConflictException."""
    deadline = time.monotonic() + 40
    while True:
        try:
            ks.delete_keyspace(keyspaceName=keyspace)
            return
        except ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'ResourceNotFoundException':
                return
            if code != 'ConflictException' or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _deregister(aas, resource_id, dimension):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=dimension)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ObjectNotFoundException':
            raise


def _activities(aas, resource_id, dimension):
    out, token = [], None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id,
                  'ScalableDimension': dimension}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _next_minute_at(min_lead_s=30):
    """A one-time at() expression for the next whole UTC minute at least ``min_lead_s`` away."""
    now = datetime.datetime.now(datetime.timezone.utc)
    fire = now.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    if (fire - now).total_seconds() < min_lead_s:
        fire += datetime.timedelta(minutes=1)
    return f'at({fire:%Y-%m-%dT%H:%M:%S})', fire




def _capacity(read, write):
    """PROVISIONED at (read, write), or on-demand when both are None."""
    if read is None and write is None:
        return {'throughputMode': 'PAY_PER_REQUEST'}
    return {'throughputMode': 'PROVISIONED', 'readCapacityUnits': read,
            'writeCapacityUnits': write}


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
