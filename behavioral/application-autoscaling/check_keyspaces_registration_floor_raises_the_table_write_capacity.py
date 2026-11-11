"""keyspaces-registration-floor-raises-the-table-write-capacity."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "keyspaces-registration-floor-raises-the-table-write-capacity"
GROUP = 'data-plane'
SERVICES = ['application-autoscaling']

_NS = 'cassandra'
_WRITE = 'cassandra:table:WriteCapacityUnits'


@tags('axis:happy-path', 'cap:c1', 'concern:data-plane', 'concern:representation', 'dp:api',
      'plane:data')
def run(ctx) -> None:
    """A write MinCapacity above the table's provisioned write capacity raises the Keyspaces table
    to the floor: the registration activity succeeds and the read capacity is untouched.
    """
    ks = ctx.client('keyspaces')
    aas = ctx.client('application-autoscaling')
    keyspace, table = _keyspaces_table(ctx, read=2, write=1)
    resource_id = f'keyspace/{keyspace}/table/{table}'
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_WRITE, MinCapacity=3, MaxCapacity=8)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id, _WRITE))

    activities = _poll_until(
        lambda: _activities(aas, resource_id, _WRITE),
        lambda acts: acts and all(a['StatusCode'] == 'Successful' for a in acts),
        timeout_s=240, interval_s=5.0, description='the registration activity being Successful')
    shapes = [(a['Cause'], a['Description'], a['StatusMessage']) for a in activities]
    assert shapes == [(
        'minimum capacity was set to 3', 'Setting table write capacity units to 3.',
        'Successfully set table write capacity units to 3. Change successfully fulfilled by '
        'cassandra.',
    )], f'activities were {shapes!r}'
    spec = _poll_until(
        lambda: ks.get_table(keyspaceName=keyspace, tableName=table),
        lambda t: t['status'] == 'ACTIVE', timeout_s=180, interval_s=5.0,
        description=f'table {table!r} settling ACTIVE')['capacitySpecification']
    assert (spec['throughputMode'], spec['writeCapacityUnits'], spec['readCapacityUnits']) == (
        'PROVISIONED', 3, 2), (
        f'Keyspaces reports {spec["throughputMode"]} with write {spec["writeCapacityUnits"]} / '
        f'read {spec["readCapacityUnits"]}; the floor of 3 must reach writes only')


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
