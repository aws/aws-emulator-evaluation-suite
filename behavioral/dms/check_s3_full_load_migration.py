"""s3-full-load-migration."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "s3-full-load-migration"
GROUP = 'migration'
SERVICES = ['dms']

# The rows this migration is supposed to move, authored here so the assertion at the far end
# compares against a payload this check put in rather than against whatever the bucket held.
_ROWS = [("1", "Alice", "Engineering"), ("2", "Bob", "Sales"), ("3", "Carla", "Finance")]
_CSV = ("".join(",".join(r) + "\n" for r in _ROWS)).encode()

# S3 as a DMS SOURCE has no catalog, so the table shape travels as an external table definition.
_EXTERNAL_TABLE_DEFINITION = {
    "TableCount": "1",
    "Tables": [
        {
            "TableName": "employee",
            "TablePath": "hr/employee/",
            "TableOwner": "hr",
            "TableColumns": [
                {"ColumnName": "id", "ColumnType": "INT8", "ColumnNullable": "false",
                 "ColumnIsPk": "true"},
                {"ColumnName": "name", "ColumnType": "STRING", "ColumnLength": "64"},
                {"ColumnName": "dept", "ColumnType": "STRING", "ColumnLength": "64"},
            ],
            "TableColumnsTotal": "3",
        }
    ],
}

_TABLE_MAPPINGS = {
    "rules": [
        {
            "rule-type": "selection",
            "rule-id": "1",
            "rule-name": "1",
            "object-locator": {"schema-name": "hr", "table-name": "employee"},
            "rule-action": "include",
        }
    ]
}

_DMS_VPC_ROLE = 'dms-vpc-role'  # AWS fixes this name; classic replication instances require it.
_DMS_VPC_POLICY = 'arn:aws:iam::aws:policy/service-role/AmazonDMSVPCManagementRole'
_DMS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "dms.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _ensure_dms_vpc_role(iam) -> None:
    """Create the fixed-name service role DMS needs to manage ENIs in our VPC, if absent.

    The name is not ours to randomize — DMS looks it up by that exact string — so this is
    create-if-absent and deliberately NOT registered for teardown: deleting an account-global
    prerequisite out from under a sibling run is worse than leaving it.
    """
    try:
        iam.get_role(RoleName=_DMS_VPC_ROLE)
        return
    except iam.exceptions.NoSuchEntityException:
        pass
    iam.create_role(RoleName=_DMS_VPC_ROLE, AssumeRolePolicyDocument=json.dumps(_DMS_TRUST))
    iam.attach_role_policy(RoleName=_DMS_VPC_ROLE, PolicyArn=_DMS_VPC_POLICY)


def _instance_status(dms, ri_id: str) -> str | None:
    resp = dms.describe_replication_instances(
        Filters=[{'Name': 'replication-instance-id', 'Values': [ri_id]}]
    )
    insts = resp['ReplicationInstances']
    return insts[0]['ReplicationInstanceStatus'] if insts else None


def _task(dms, task_arn: str) -> dict:
    return dms.describe_replication_tasks(
        Filters=[{'Name': 'replication-task-arn', 'Values': [task_arn]}]
    )['ReplicationTasks'][0]


def _await(describe, accept: set[str], budget_s: float, what: str, poll_s: float = 15.0) -> dict:
    """Poll ``describe`` until its ``status`` is in ``accept``, or fail. Never skips: a state
    machine that does not arrive is a fidelity failure, not an inconclusive run."""
    deadline = time.time() + budget_s
    seen: list[str] = []
    while time.time() < deadline:
        cur = describe()
        status = cur['status']
        if not seen or seen[-1] != status:
            seen.append(status)
        if status in accept:
            return cur
        assert status not in ('failed', 'deleting', 'failed-move'), (
            f"{what} entered terminal state {status!r} (saw {seen}), expected one of "
            f"{sorted(accept)}"
        )
        time.sleep(poll_s)
    raise AssertionError(f"{what} never reached {sorted(accept)} within {budget_s:.0f}s (saw {seen})")


# The not-found codes of the deletes and describes below: the resource is already gone.
_GONE_CODES = ("ResourceNotFoundFault", "NoSuchEntity", "NoSuchBucket",
               "InvalidSubnetID.NotFound", "InvalidVpcID.NotFound")
# A delete refused while a dependent resource is still being released.
_BUSY_CODES = ("InvalidResourceStateFault", "DependencyViolation")


def _code(exc) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _gone(describe, budget_s: float, what: str, poll_s: float = 2.0) -> None:
    """Wait until ``describe`` reports the resource absent (None, or a not-found code); raise if
    it is still there at the deadline."""
    from botocore.exceptions import ClientError

    deadline = time.time() + budget_s
    while time.time() < deadline:
        try:
            if describe() is None:
                return
        except ClientError as exc:
            if _code(exc) in _GONE_CODES:
                return
            raise
        time.sleep(poll_s)
    raise AssertionError(f"{what} still exists {budget_s:.0f}s after its delete")


def _teardown_step(what: str, fn, budget_s: float = 0.0, poll_s: float = 2.0) -> None:
    """Issue one teardown delete: done when it succeeds or the resource is already gone; retry a
    delete refused while a dependency is still being released to ``budget_s``; raise the rest."""
    from botocore.exceptions import ClientError

    deadline = time.time() + budget_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in _GONE_CODES:
                return
            if _code(exc) not in _BUSY_CODES or time.time() >= deadline:
                raise
            time.sleep(poll_s)


def _cap(ctx, budget_s: float) -> float:
    """``budget_s``, cut to the time the run has left so a slow delete fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, max(1.0, left - 10.0))


def _delete_vpce(ec2, vpce_id: str) -> None:
    """DeleteVpcEndpoints reports per-endpoint failures in ``Unsuccessful``; raise on any but not-found."""
    failed = [u for u in ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]).get("Unsuccessful", [])
              if u.get("Error", {}).get("Code") not in ("InvalidVpcEndpoint.NotFound",
                                                         "InvalidVpcEndpointId.NotFound")]
    if failed:
        raise AssertionError(f"DeleteVpcEndpoints({vpce_id}) failed: {failed}")


def _empty_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator('list_object_versions')
    for page in paginator.paginate(Bucket=bucket):
        victims = [{'Key': o['Key'], 'VersionId': o['VersionId']}
                   for o in page.get('Versions', []) + page.get('DeleteMarkers', [])]
        if victims:
            s3.delete_objects(Bucket=bucket, Delete={'Objects': victims})
    s3.delete_bucket(Bucket=bucket)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A full-load task reads three CSV rows from an S3 source, writes exactly those bytes to the S3
    target, stops with FULL_LOAD_ONLY_FINISHED, and reports table statistics that match the rows."""
    dms = ctx.client("dms")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    region = ctx.region

    _ensure_dms_vpc_role(iam)

    src_bucket = ctx.unique_name("sim2real-behav-dms-src-")
    tgt_bucket = ctx.unique_name("sim2real-behav-dms-tgt-")
    for bucket in (src_bucket, tgt_bucket):
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={'LocationConstraint': region})
        ctx.on_cleanup(lambda b=bucket: _teardown_step(f"bucket {b}", lambda: _empty_bucket(s3, b)))

    # The role DMS assumes to reach both buckets. Scoped to the two buckets this check made.
    role_name = ctx.unique_name("sim2real-behav-dmsrole-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_DMS_TRUST)
    )['Role']['Arn']
    ctx.on_cleanup(lambda: _teardown_step(f"role {role_name}", lambda: iam.delete_role(RoleName=role_name)))
    iam.put_role_policy(
        RoleName=role_name, PolicyName='s3-access',
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{b}{suffix}"
                             for b in (src_bucket, tgt_bucket) for suffix in ("", "/*")],
            }],
        }),
    )
    ctx.on_cleanup(lambda: _teardown_step(
        f"role policy s3-access on {role_name}",
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName='s3-access')))

    # The payload. LOAD001.csv under <BucketFolder>/<schema>/<table>/ is where an S3 source
    # expects a full-load file.
    src_key = 'srcdata/hr/employee/LOAD001.csv'
    s3.put_object(Bucket=src_bucket, Key=src_key, Body=_CSV)

    # A VPC of our own: two subnets in two AZs (DMS refuses one) plus an S3 gateway endpoint,
    # so the instance reaches S3 with no internet path and no reliance on a default VPC.
    # Tagged with the run's unique name so a leaked VPC can be identified and removed; the
    # regional VPC quota is small.
    vpc_name = ctx.unique_name("sim2real-behav-dms-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock='10.31.0.0/16',
        TagSpecifications=[{'ResourceType': 'vpc',
                            'Tags': [{'Key': 'Name', 'Value': vpc_name}]}],
    )['Vpc']['VpcId']
    ctx.on_cleanup(lambda: _teardown_step(f"vpc {vpc_id}", lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    zones = [z['ZoneName'] for z in ec2.describe_availability_zones(
        Filters=[{'Name': 'state', 'Values': ['available']},
                 {'Name': 'opt-in-status', 'Values': ['opt-in-not-required']}]
    )['AvailabilityZones']][:2]
    assert len(zones) == 2, f"region {region} offered {zones}, need two availability zones"
    subnet_ids = []
    for i, zone in enumerate(zones):
        sn = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f'10.31.{i + 1}.0/24', AvailabilityZone=zone,
            TagSpecifications=[{'ResourceType': 'subnet',
                                'Tags': [{'Key': 'Name', 'Value': f'{vpc_name}-{i + 1}'}]}],
        )['Subnet']['SubnetId']
        ctx.on_cleanup(lambda s=sn: _teardown_step(
            f"subnet {s}", lambda: _delete_net(ec2, "delete_subnet", SubnetId=s)))
        subnet_ids.append(sn)

    route_tables = ec2.describe_route_tables(
        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
    )['RouteTables']
    main_rt = next(rt['RouteTableId'] for rt in route_tables
                   if any(a.get('Main') for a in rt['Associations']))
    vpce_id = ec2.create_vpc_endpoint(
        VpcId=vpc_id, ServiceName=f'com.amazonaws.{region}.s3',
        VpcEndpointType='Gateway', RouteTableIds=[main_rt],
    )['VpcEndpoint']['VpcEndpointId']
    ctx.on_cleanup(lambda: _teardown_step(f"s3 gateway endpoint {vpce_id}", lambda: _delete_vpce(ec2, vpce_id)))

    sng = ctx.unique_name("sim2real-behav-dms-sng-")
    # A just-created dms-vpc-role is refused as "not configured properly" until IAM propagates it.
    sng_deadline = time.time() + _cap(ctx, 120.0)
    while True:
        try:
            dms.create_replication_subnet_group(
                ReplicationSubnetGroupIdentifier=sng,
                ReplicationSubnetGroupDescription='sim2real full-load fidelity check',
                SubnetIds=subnet_ids,
            )
            break
        except dms.exceptions.AccessDeniedFault as exc:
            if "is not configured properly" not in str(exc) or time.time() >= sng_deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _teardown_step(
        f"subnet group {sng}",
        lambda: dms.delete_replication_subnet_group(ReplicationSubnetGroupIdentifier=sng),
        budget_s=120))

    ri_id = ctx.unique_name("sim2real-behav-dms-ri-")
    ri_arn = dms.create_replication_instance(
        ReplicationInstanceIdentifier=ri_id,
        ReplicationInstanceClass='dms.c5.large',
        AllocatedStorage=5,
        ReplicationSubnetGroupIdentifier=sng,
        MultiAZ=False,
        PubliclyAccessible=False,
    )['ReplicationInstance']['ReplicationInstanceArn']

    # Fire-and-forget on purpose: a replication instance takes ~400s to disappear, so the ordered
    # teardown that waits for it runs at the end of the body; these registrations are the
    # failure-path backstop and only retry a delete refused while a dependency is released.
    ctx.on_cleanup(lambda: _teardown_step(
        f"replication instance {ri_id}",
        lambda: dms.delete_replication_instance(ReplicationInstanceArn=ri_arn),
        budget_s=180))

    created = _await(lambda: {'status': _instance_status(dms, ri_id) or 'gone'},
                     {"available"}, budget_s=1200, what=f"replication instance {ri_id}",
                     poll_s=20)
    assert created['status'] == 'available'

    src_ep = dms.create_endpoint(
        EndpointIdentifier=ctx.unique_name("sim2real-behav-dms-src-ep-"),
        EndpointType='source', EngineName='s3',
        S3Settings={
            'ServiceAccessRoleArn': role_arn, 'BucketName': src_bucket,
            'BucketFolder': 'srcdata', 'CsvDelimiter': ',', 'CsvRowDelimiter': '\\n',
            'ExternalTableDefinition': json.dumps(_EXTERNAL_TABLE_DEFINITION),
        },
    )['Endpoint']['EndpointArn']
    ctx.on_cleanup(lambda: _teardown_step("source endpoint", lambda: dms.delete_endpoint(EndpointArn=src_ep),
                                          budget_s=180))

    tgt_ep = dms.create_endpoint(
        EndpointIdentifier=ctx.unique_name("sim2real-behav-dms-tgt-ep-"),
        EndpointType='target', EngineName='s3',
        S3Settings={'ServiceAccessRoleArn': role_arn, 'BucketName': tgt_bucket,
                    'BucketFolder': 'tgtdata'},
    )['Endpoint']['EndpointArn']
    ctx.on_cleanup(lambda: _teardown_step("target endpoint", lambda: dms.delete_endpoint(EndpointArn=tgt_ep),
                                          budget_s=180))

    task_id = ctx.unique_name("sim2real-behav-dms-task-")
    task_arn = dms.create_replication_task(
        ReplicationTaskIdentifier=task_id,
        SourceEndpointArn=src_ep, TargetEndpointArn=tgt_ep,
        ReplicationInstanceArn=ri_arn,
        MigrationType='full-load',
        TableMappings=json.dumps(_TABLE_MAPPINGS),
    )['ReplicationTask']['ReplicationTaskArn']

    ctx.on_cleanup(lambda: _teardown_step(
        f"replication task {task_id}", lambda: dms.delete_replication_task(ReplicationTaskArn=task_arn)))

    ready = _await(lambda: {'status': _task(dms, task_arn)['Status']},
                   {"ready"}, budget_s=240, what=f"replication task {task_id}", poll_s=10)
    assert ready['status'] == 'ready'

    dms.start_replication_task(ReplicationTaskArn=task_arn,
                              StartReplicationTaskType='start-replication')

    # A full-load-only task does not sit in a 'load complete' state: it STOPS, and the reason
    # carries the completion. Asserting the reason is what distinguishes a finished load from a
    # task somebody stopped.
    done = _await(lambda: {'status': _task(dms, task_arn)['Status'], 'raw': _task(dms, task_arn)},
                  {"stopped"}, budget_s=480, what=f"replication task {task_id} run", poll_s=15)
    final = done['raw']
    assert final['StopReason'] == 'Stop Reason FULL_LOAD_ONLY_FINISHED', (
        f"task stopped with StopReason {final.get('StopReason')!r}, expected the full-load "
        f"completion reason"
    )
    stats = final['ReplicationTaskStats']
    assert stats['FullLoadProgressPercent'] == 100, (
        f"task reported FullLoadProgressPercent {stats['FullLoadProgressPercent']!r} after "
        f"stopping, expected 100"
    )
    assert (stats['TablesLoaded'], stats['TablesErrored']) == (1, 0), (
        f"task loaded {stats['TablesLoaded']} table(s) with {stats['TablesErrored']} errored, "
        f"expected exactly 1 loaded and 0 errored"
    )

    # The data plane: what actually landed in the target bucket.
    listed = s3.list_objects_v2(Bucket=tgt_bucket, Prefix='tgtdata/hr/employee/')
    keys = [o['Key'] for o in listed.get('Contents', [])]
    assert keys == ['tgtdata/hr/employee/LOAD00000001.csv'], (
        f"target bucket holds {keys!r} under the migrated table's prefix, expected exactly "
        f"one full-load file named LOAD00000001.csv"
    )
    landed = s3.get_object(Bucket=tgt_bucket, Key=keys[0])['Body'].read()
    assert landed == _CSV, (
        f"migrated object body is {landed!r}, expected the {len(_ROWS)} source rows {_CSV!r}"
    )

    # ...and that the task's own accounting agrees with it.
    table_stats = dms.describe_table_statistics(ReplicationTaskArn=task_arn)['TableStatistics']
    assert len(table_stats) == 1, (
        f"task reported statistics for {len(table_stats)} tables, expected 1"
    )
    row = table_stats[0]
    assert (row['SchemaName'], row['TableName']) == ('hr', 'employee'), (
        f"statistics name the table {row['SchemaName']!r}.{row['TableName']!r}, expected "
        f"'hr'.'employee'"
    )
    assert row['FullLoadRows'] == len(_ROWS), (
        f"statistics report FullLoadRows {row['FullLoadRows']!r}, but this check put "
        f"{len(_ROWS)} rows at the source"
    )
    assert row['FullLoadErrorRows'] == 0, (
        f"statistics report {row['FullLoadErrorRows']!r} errored rows, expected 0"
    )
    assert row['TableState'] == 'Table completed', (
        f"statistics report TableState {row['TableState']!r}, expected 'Table completed'"
    )

    # ===== teardown, in the body on purpose =====
    # Every resource above is also registered with ctx.on_cleanup as the failure-path backstop.
    # The replication instance takes ~400s to disappear and the VPC cannot be deleted until it
    # does, so the ordered, waiting teardown runs here; the registered cleanups then find it gone.
    _teardown_step(f"replication task {task_id}",
                   lambda: dms.delete_replication_task(ReplicationTaskArn=task_arn))
    _gone(lambda: _task(dms, task_arn), budget_s=_cap(ctx, 180), what=f"replication task {task_id}")
    for name, arn in (("source endpoint", src_ep), ("target endpoint", tgt_ep)):
        _teardown_step(name, lambda a=arn: dms.delete_endpoint(EndpointArn=a))
    _teardown_step(f"replication instance {ri_id}",
                   lambda: dms.delete_replication_instance(ReplicationInstanceArn=ri_arn),
                   budget_s=_cap(ctx, 120))
    _gone(lambda: _instance_status(dms, ri_id), budget_s=_cap(ctx, 600),
          what=f"replication instance {ri_id}")
    _teardown_step(f"subnet group {sng}",
                   lambda: dms.delete_replication_subnet_group(
                       ReplicationSubnetGroupIdentifier=sng),
                   budget_s=_cap(ctx, 120))
    _teardown_step(f"s3 gateway endpoint {vpce_id}", lambda: _delete_vpce(ec2, vpce_id))
    for sn in subnet_ids:
        # The instance's ENIs are released asynchronously after it disappears, so a subnet delete
        # can be refused for a while after the instance is gone.
        _teardown_step(f"subnet {sn}", lambda s=sn: ec2.delete_subnet(SubnetId=s), budget_s=_cap(ctx, 180))
    _teardown_step(f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id), budget_s=_cap(ctx, 180))
    _teardown_step(f"role policy s3-access on {role_name}",
                   lambda: iam.delete_role_policy(RoleName=role_name, PolicyName='s3-access'))
    _teardown_step(f"role {role_name}", lambda: iam.delete_role(RoleName=role_name))
    for bucket in (src_bucket, tgt_bucket):
        _teardown_step(f"bucket {bucket}", lambda b=bucket: _empty_bucket(s3, b))


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that would leak the
# VPC. So wait (bounded) for the resource's ENIs to go, retry DependencyViolation
# inside the same window, and raise a final failure naming the ENIs still attached. The window is
# shared by all of one check's network deletes and fits the 900s cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
