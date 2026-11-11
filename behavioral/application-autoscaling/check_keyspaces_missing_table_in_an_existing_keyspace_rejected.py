"""keyspaces-missing-table-in-an-existing-keyspace-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "keyspaces-missing-table-in-an-existing-keyspace-rejected"
GROUP = 'scalable-targets'
SERVICES = ['application-autoscaling']

_NS = 'cassandra'
_WRITE = 'cassandra:table:WriteCapacityUnits'
_MISSING = 'sim2real_never_created'


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """RegisterScalableTarget refuses a missing table in an existing keyspace with a
    ValidationException naming the resource and registers nothing; the real table registers.
    """
    aas = ctx.client('application-autoscaling')
    keyspace, table = _keyspaces_table(ctx, read=2, write=2)
    missing_id = f'keyspace/{keyspace}/table/{_MISSING}'
    real_id = f'keyspace/{keyspace}/table/{table}'
    for rid in (missing_id, real_id):
        ctx.on_cleanup(lambda rid=rid: _deregister(aas, rid, _WRITE))

    code, message = _error(lambda: aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=missing_id, ScalableDimension=_WRITE,
        MinCapacity=1, MaxCapacity=5))
    assert code == 'ValidationException', f'a missing table was refused with {code!r}'
    expected = (f'Validation failed for resource: {missing_id}, scalable dimension: {_WRITE}. '
                f'Reason: Table {_MISSING} does not exist in keyspace {keyspace}')
    assert message == expected, f'refusal message {message!r}, expected {expected!r}'
    assert _bounds(aas, missing_id) is None, 'the missing table is registered anyway'

    # Positive control: the table that exists in the same keyspace registers.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=real_id,
                                 ScalableDimension=_WRITE, MinCapacity=1, MaxCapacity=5)
    assert _bounds(aas, real_id) == (1, 5), (
        f'the existing table registered with bounds {_bounds(aas, real_id)!r}, expected (1, 5)')


def _bounds(aas, resource_id):
    found = []
    for page in aas.get_paginator('describe_scalable_targets').paginate(
            ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=_WRITE):
        found.extend((t['MinCapacity'], t['MaxCapacity']) for t in page['ScalableTargets'])
    assert len(found) <= 1, f'{len(found)} targets share one resource id'
    return found[0] if found else None


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
