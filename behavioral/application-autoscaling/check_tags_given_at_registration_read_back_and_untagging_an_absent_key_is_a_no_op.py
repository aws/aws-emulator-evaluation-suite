"""tags-given-at-registration-read-back-and-untagging-an-absent-key-is-a-no-op."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tags-given-at-registration-read-back-and-untagging-an-absent-key-is-a-no-op"
GROUP = 'tagging'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_PROV = {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}



def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description='condition'):
    """Bounded poll that RAISES on timeout, never returns its last value."""
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
    """DeleteTable refuses while the table is UPDATING; retry that, bounded, and raise otherwise."""
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
    """Tags given to RegisterScalableTarget read back under its returned ARN, a target registered
    without Tags lists none, and untagging a key the target never carried changes nothing.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-tagc-')
    _create_table(ctx, ddb, table, BillingMode='PROVISIONED', ProvisionedThroughput=_PROV)
    resource_id = f'table/{table}'
    write_dim = 'dynamodb:table:WriteCapacityUnits'
    given = {'team': 'blue', 'env': 'test', 'sim2real': CHECK}

    arn = aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=5, Tags=given)['ScalableTargetARN']
    ctx.on_cleanup(lambda: _deregister(aas, _NS, resource_id, _DIM))
    plain_arn = aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=write_dim,
        MinCapacity=1, MaxCapacity=5)['ScalableTargetARN']
    ctx.on_cleanup(lambda: _deregister(aas, _NS, resource_id, write_dim))

    described = {t['ScalableDimension']: t['ScalableTargetARN']
                 for t in _targets(aas, _NS, resource_id)}
    assert described == {_DIM: arn, write_dim: plain_arn}, (
        f'DescribeScalableTargets reports {len(described)} targets whose ARNs '
        f'{"match" if described.get(_DIM) == arn else "do not match"} the registrations')
    assert arn != plain_arn, 'the read and write targets of one table share one ARN'

    tags_read = aas.list_tags_for_resource(ResourceARN=arn)['Tags']
    assert tags_read == given, f'the tags given at registration read back as {tags_read!r}'
    plain = aas.list_tags_for_resource(ResourceARN=plain_arn)['Tags']
    assert plain == {}, f'the target registered without Tags lists {plain!r}'

    aas.untag_resource(ResourceARN=arn, TagKeys=['never-set'])
    after = aas.list_tags_for_resource(ResourceARN=arn)['Tags']
    assert after == given, f'untagging a key the target never carried left {after!r}'
    aas.untag_resource(ResourceARN=arn, TagKeys=['env'])
    trimmed = aas.list_tags_for_resource(ResourceARN=arn)['Tags']
    assert trimmed == {'team': 'blue', 'sim2real': CHECK}, (
        f'untagging env left {trimmed!r}, expected only team and sim2real')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
