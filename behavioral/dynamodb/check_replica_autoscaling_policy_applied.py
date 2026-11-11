"""replica-autoscaling-policy-applied."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replica-autoscaling-policy-applied"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _error_response(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response
    return None


def _other_region(region):
    for r in ('us-east-1', 'us-west-2', 'us-east-2'):
        if r != region:
            return r
    return 'us-east-1'


def _wait_table_active(ddb, name, timeout_s=90):
    return _poll_until(
        lambda: ddb.describe_table(TableName=name)['Table'],
        lambda t: t['TableStatus'] == 'ACTIVE'
        and all(idx.get('IndexStatus', 'ACTIVE') == 'ACTIVE' for idx in t.get('GlobalSecondaryIndexes', []))
        and all(r.get('ReplicaStatus', 'ACTIVE') == 'ACTIVE' for r in t.get('Replicas', [])),
        timeout_s=timeout_s,
        interval_s=1.0,
        description=f'table {name} ACTIVE',
    )


def _autoscaling_role(ctx):
    """ARN of the Application Auto Scaling DynamoDB service-linked role, created if absent.

    DynamoDB's replication role may only pass this role; it is account-level and not torn down.
    """
    iam = ctx.client('iam')
    role_name = 'AWSServiceRoleForApplicationAutoScaling_DynamoDBTable'
    try:
        return iam.create_service_linked_role(
            AWSServiceName='dynamodb.application-autoscaling.amazonaws.com'
        )['Role']['Arn']
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') == 'InvalidInput':
            return iam.get_role(RoleName=role_name)['Role']['Arn']
        raise


def _cleanup_aas_target(aas, resource_id, dimension):
    for pol in aas.describe_scaling_policies(
        ServiceNamespace='dynamodb', ResourceId=resource_id, ScalableDimension=dimension
    ).get('ScalingPolicies', []):
        try:
            aas.delete_scaling_policy(
                ServiceNamespace='dynamodb',
                ResourceId=resource_id,
                ScalableDimension=dimension,
                PolicyName=pol['PolicyName'],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ObjectNotFoundException":
                raise
    try:
        aas.deregister_scalable_target(
            ServiceNamespace='dynamodb', ResourceId=resource_id, ScalableDimension=dimension
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ObjectNotFoundException":
            raise


def _delete_replica_and_wait(ddb, name, region, timeout_s=600):
    """Teardown: the base table cannot be deleted while it still holds the replica it sourced,
    so the replica removal is awaited; raise at the deadline."""
    try:
        ddb.update_table(TableName=name, ReplicaUpdates=[{'Delete': {'RegionName': region}}])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            table = ddb.describe_table(TableName=name)['Table']
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if table['TableStatus'] == 'ACTIVE' and not any(
                r['RegionName'] == region for r in table.get('Replicas', [])):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f'replica {region} of {name} not removed within {timeout_s}s: '
                f'{table["TableStatus"]} {table.get("Replicas")!r}')
        time.sleep(2)


def _delete_table(ddb, name, timeout_s=300):
    """Teardown: retry DeleteTable while the table is still being updated; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An UpdateTableReplicaAutoScaling read-capacity policy on a replica is applied and reflected
    by DescribeTableReplicaAutoScaling with its min/max units and target value.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    # The API needs a real global-table replica, and a PROVISIONED table can only gain one once
    # its write capacity is auto-scaled, so that is registered first.
    second_region = _other_region(ctx.region)

    name = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5},
        Tags=[{'Key': 'sim2real', 'Value': 'replica-autoscaling-policy-applied'}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    role_arn = _autoscaling_role(ctx)

    write_dim = 'dynamodb:table:WriteCapacityUnits'
    ctx.on_cleanup(lambda: _cleanup_aas_target(aas, f'table/{name}', write_dim))

    def _register_write_autoscaling():
        return aas.register_scalable_target(
            ServiceNamespace='dynamodb',
            ResourceId=f'table/{name}',
            ScalableDimension=write_dim,
            MinCapacity=1,
            MaxCapacity=10,
            RoleARN=role_arn,
        )

    # IAM role propagation lag: retry the registration itself.
    reg_result = _poll_until(
        lambda: _error_response(_register_write_autoscaling),
        lambda err: err is None,
        timeout_s=60,
        interval_s=5.0,
        description="Application Auto Scaling registers the table's write capacity",
    )
    assert reg_result is None, reg_result

    # DynamoDB only treats write capacity as "AutoScaled" (letting a replica be
    # added) once an actual scaling POLICY is attached.
    def _apply_write_policy():
        return aas.put_scaling_policy(
            PolicyName=ctx.unique_name('sim2real-behav-write-scale-'),
            ServiceNamespace='dynamodb',
            ResourceId=f'table/{name}',
            ScalableDimension=write_dim,
            PolicyType='TargetTrackingScaling',
            TargetTrackingScalingPolicyConfiguration={
                'TargetValue': 70.0,
                'PredefinedMetricSpecification': {'PredefinedMetricType': 'DynamoDBWriteCapacityUtilization'},
            },
        )

    policy_result = _poll_until(
        lambda: _error_response(_apply_write_policy),
        lambda err: err is None,
        timeout_s=30,
        interval_s=5.0,
        description='Application Auto Scaling write-capacity scaling policy attached',
    )
    assert policy_result is None, policy_result

    # A replica Create issued right as the table reaches ACTIVE can transiently fail with an
    # AccessDeniedException about the security token while replication setup settles.
    def _create_replica():
        try:
            ddb.update_table(TableName=name, ReplicaUpdates=[{'Create': {'RegionName': second_region}}])
        except ClientError as exc:
            transient = exc.response.get('Error', {}).get('Code') == 'AccessDeniedException' and (
                'security token' in str(exc).lower()
            )
            return exc.response if not transient else None
        return 'created'

    create_result = _poll_until(
        _create_replica,
        lambda r: r is not None,
        timeout_s=90,
        interval_s=5.0,
        description='UpdateTable ReplicaUpdates Create accepted past transient replication-setup lag',
    )
    assert create_result == 'created', create_result
    ctx.on_cleanup(lambda: _delete_replica_and_wait(ddb, name, second_region))
    _wait_table_active(ddb, name, timeout_s=240)

    baseline = ddb.describe_table_replica_auto_scaling(TableName=name)['TableAutoScalingDescription']
    assert baseline['TableName'] == name, baseline
    regions_seen = {r['RegionName'] for r in baseline['Replicas']}
    assert {ctx.region, second_region} <= regions_seen, baseline

    policy_name = ctx.unique_name('sim2real-behav-scale-pol-')

    def _apply():
        return ddb.update_table_replica_auto_scaling(
            TableName=name,
            ReplicaUpdates=[
                {
                    'RegionName': second_region,
                    'ReplicaProvisionedReadCapacityAutoScalingUpdate': {
                        'MinimumUnits': 1,
                        'MaximumUnits': 10,
                        'AutoScalingRoleArn': role_arn,
                        'ScalingPolicyUpdate': {
                            'PolicyName': policy_name,
                            'TargetTrackingScalingPolicyConfiguration': {'TargetValue': 60.0},
                        },
                    },
                }
            ],
        )

    # A freshly-created IAM role can take a few seconds to propagate before
    # Application Auto Scaling can assume it -- retry the whole mutating call.
    result = _poll_until(
        lambda: _error_response(_apply),
        lambda err: err is None,
        timeout_s=60,
        interval_s=5.0,
        description='UpdateTableReplicaAutoScaling accepted',
    )
    assert result is None, result

    described = _poll_until(
        lambda: ddb.describe_table_replica_auto_scaling(TableName=name)['TableAutoScalingDescription'],
        lambda d: any(
            r['RegionName'] == second_region
            and r.get('ReplicaProvisionedReadCapacityAutoScalingSettings', {}).get('ScalingPolicies')
            for r in d['Replicas']
        ),
        timeout_s=60,
        interval_s=3.0,
        description='autoscaling policy reflected via DescribeTableReplicaAutoScaling',
    )
    replica = next(r for r in described['Replicas'] if r['RegionName'] == second_region)
    settings = replica['ReplicaProvisionedReadCapacityAutoScalingSettings']
    assert settings['MinimumUnits'] == 1, settings
    assert settings['MaximumUnits'] == 10, settings
    policies = settings['ScalingPolicies']
    applied = next((p for p in policies if p['PolicyName'] == policy_name), None)
    assert applied is not None, policies
    assert applied['TargetTrackingScalingPolicyConfiguration']['TargetValue'] == 60.0, applied


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
