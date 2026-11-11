"""aws-prefixed-tag-key-rejected-on-scalable-target."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aws-prefixed-tag-key-rejected-on-scalable-target"
GROUP = 'tagging'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_SYSTEM = 'Caller is an end user and not allowed to mutate system tags'


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


def _create_table(ddb, name, read_capacity):
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': read_capacity, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )


def _wait_active(ddb, name):
    _poll_until(lambda: ddb.describe_table(TableName=name)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {name!r} becoming ACTIVE')


def _delete_table(ddb, name):
    deadline = time.monotonic() + 40
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
            time.sleep(3)


def _deregister(aas, resource_id, dimension=_DIM):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=dimension)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ObjectNotFoundException':
            raise


def _client_error(fn):
    """The Error dict ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'concern:representation',
      'plane:control')
def run(ctx) -> None:
    """TagResource with an aws:-prefixed key beside a user key is refused atomically (neither lands)
    and UntagResource of one is refused too, while a user key alone tags and untags normally.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-awstag-')
    resource_id = f'table/{table}'

    _create_table(ddb, table, 1)
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _wait_active(ddb, table)
    arn = aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=10, Tags={'owner': 'sim2real'})['ScalableTargetARN']
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))

    error = _client_error(lambda: aas.tag_resource(
        ResourceARN=arn, Tags={'aws:cost-center': 'x', 'env': 'test'}))
    assert error['Code'] == 'ValidationException', (
        f'an aws:-prefixed tag key was refused with {error["Code"]!r}, expected '
        f'"ValidationException"')
    assert error['Message'] == _SYSTEM, (
        f'the refusal message was {error["Message"]!r}, expected {_SYSTEM!r}')
    assert aas.list_tags_for_resource(ResourceARN=arn)['Tags'] == {'owner': 'sim2real'}, (
        'the refused batch was partly applied; the tags must still be exactly {"owner": "sim2real"}')

    error = _client_error(lambda: aas.untag_resource(ResourceARN=arn,
                                                     TagKeys=['aws:cost-center']))
    assert (error['Code'], error['Message']) == ('ValidationException', _SYSTEM), (
        f'untagging an aws:-prefixed key gave ({error["Code"]!r}, {error["Message"]!r}), expected '
        f'("ValidationException", {_SYSTEM!r})')

    aas.tag_resource(ResourceARN=arn, Tags={'env': 'test'})
    assert aas.list_tags_for_resource(ResourceARN=arn)['Tags'] == {'owner': 'sim2real',
                                                                   'env': 'test'}, (
        'the user-key positive control did not add env=test beside owner')
    aas.untag_resource(ResourceARN=arn, TagKeys=['env', 'never-set'])
    assert aas.list_tags_for_resource(ResourceARN=arn)['Tags'] == {'owner': 'sim2real'}, (
        'untagging env plus a key that was never set did not leave exactly owner')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
