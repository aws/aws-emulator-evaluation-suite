"""stop-replication-task-rejected-for-a-ready-or-stopped-task."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-replication-task-rejected-for-a-ready-or-stopped-task"
GROUP = "task-lifecycle"
SERVICES = ["dms", "ec2", "iam", "s3"]

_ROWS = [("1", "Alice", "Engineering"), ("2", "Bob", "Sales"), ("3", "Carla", "Finance")]
_CSV = ("".join(",".join(r) + "\n" for r in _ROWS)).encode()

_EXTERNAL_TABLE_DEFINITION = {
    "TableCount": "1",
    "Tables": [
        {
            "TableName": "employee",
            "TablePath": "hr/employee/",
            "TableOwner": "hr",
            "TableColumns": [
                {
                    "ColumnName": "id",
                    "ColumnType": "INT8",
                    "ColumnNullable": "false",
                    "ColumnIsPk": "true",
                },
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

_DMS_VPC_ROLE = "dms-vpc-role"  # AWS fixes this name; classic replication instances require it.
_DMS_VPC_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonDMSVPCManagementRole"
_DMS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "dms.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _delete_dms_vpc_role(iam) -> None:
    """Detach the managed policy and delete the fixed-name role this run created."""
    attached = [
        p["PolicyArn"]
        for p in iam.list_attached_role_policies(RoleName=_DMS_VPC_ROLE)["AttachedPolicies"]
    ]
    for arn in attached:
        iam.detach_role_policy(RoleName=_DMS_VPC_ROLE, PolicyArn=arn)
    iam.delete_role(RoleName=_DMS_VPC_ROLE)


def _ensure_dms_vpc_role(ctx, iam) -> str:
    """The ARN of the fixed-name service role DMS needs to manage ENIs in our VPC.

    The role is read first: an existing one is used and left as it is; one this run creates is
    deleted again in its teardown, so the account ends as it started.
    """
    try:
        return iam.get_role(RoleName=_DMS_VPC_ROLE)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        pass
    arn = iam.create_role(RoleName=_DMS_VPC_ROLE, AssumeRolePolicyDocument=json.dumps(_DMS_TRUST))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: _delete_dms_vpc_role(iam))
    iam.attach_role_policy(RoleName=_DMS_VPC_ROLE, PolicyArn=_DMS_VPC_POLICY)
    return arn


def _instance_status(dms, ri_id: str) -> str | None:
    resp = dms.describe_replication_instances(
        Filters=[{"Name": "replication-instance-id", "Values": [ri_id]}]
    )
    insts = resp["ReplicationInstances"]
    return insts[0]["ReplicationInstanceStatus"] if insts else None


def _task(dms, task_arn: str) -> dict:
    return dms.describe_replication_tasks(
        Filters=[{"Name": "replication-task-arn", "Values": [task_arn]}]
    )["ReplicationTasks"][0]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await(
    ctx, describe, status_of, accept: set[str], budget_s: float, what: str, poll_s: float = 15.0
):
    """Poll ``describe`` (one call per attempt) until ``status_of`` its result is in ``accept``,
    or fail; a spent run budget raises TimeoutError instead."""
    budget_s = _budget_s(ctx, budget_s)
    deadline = time.monotonic() + budget_s
    seen: list[str] = []
    while True:
        cur = describe()
        status = status_of(cur)
        if not seen or seen[-1] != status:
            seen.append(status)
        if status in accept:
            return cur
        assert status not in ("failed", "deleting", "failed-move"), (
            f"{what} entered terminal state {status!r} (saw {seen}), expected one of "
            f"{sorted(accept)}"
        )
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what} never reached {sorted(accept)} within {budget_s:.0f}s (saw {seen})"
            )
        time.sleep(poll_s)


_GONE_CODES = (
    "ResourceNotFoundFault",
    "NoSuchEntity",
    "NoSuchBucket",
    "InvalidSubnetID.NotFound",
    "InvalidVpcID.NotFound",
)
_BUSY_CODES = ("InvalidResourceStateFault", "DependencyViolation")


def _code(exc) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _gone(ctx, describe, budget_s: float, what: str, poll_s: float = 2.0) -> None:
    budget_s = _budget_s(ctx, budget_s)
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        try:
            if describe() is None:
                return
        except ClientError as exc:
            if _code(exc) in _GONE_CODES:
                return
            raise
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    raise AssertionError(f"{what} still exists {budget_s:.0f}s after its delete")


def _teardown_step(what: str, fn, budget_s: float = 0.0, poll_s: float = 2.0) -> None:
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


def _restart_status(task: dict, first_full_load_start) -> str:
    """The task's status, except that the first run's own "stopped" reads as "restarting" until a
    full load newer than the first one has started."""
    started = (task.get("ReplicationTaskStats") or {}).get("FullLoadStartDate")
    if task["Status"] == "stopped" and (started is None or started <= first_full_load_start):
        return "restarting"
    return task["Status"]


def _delete_task(dms, task_arn: str, task_id: str) -> None:
    """Delete the replication task, first stopping a run still in flight: DMS refuses to delete
    a starting or running task."""

    def stop_then_delete() -> None:
        if _task(dms, task_arn)["Status"] in ("starting", "running"):
            dms.stop_replication_task(ReplicationTaskArn=task_arn)
        dms.delete_replication_task(ReplicationTaskArn=task_arn)

    _teardown_step(f"replication task {task_id}", stop_then_delete, budget_s=300, poll_s=10)


def _delete_instance(ctx, dms, ri_arn: str, ri_id: str) -> None:
    """Delete the replication instance and wait until it is gone, so its subnet group can go."""
    _teardown_step(
        f"replication instance {ri_id}",
        lambda: dms.delete_replication_instance(ReplicationInstanceArn=ri_arn),
        budget_s=_budget_s(ctx, 120),
    )
    _gone(
        ctx,
        lambda: _instance_status(dms, ri_id),
        budget_s=600,
        what=f"replication instance {ri_id}",
        poll_s=10,
    )


def _delete_vpce(ec2, vpce_id: str) -> None:
    failed = [
        u
        for u in ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]).get("Unsuccessful", [])
        if u.get("Error", {}).get("Code")
        not in ("InvalidVpcEndpoint.NotFound", "InvalidVpcEndpointId.NotFound")
    ]
    if failed:
        raise AssertionError(f"DeleteVpcEndpoints({vpce_id}) failed: {failed}")


def _empty_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        victims = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if victims:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": victims})
    s3.delete_bucket(Bucket=bucket)


def _error(fn) -> tuple:
    """The exact (code, message) real AWS returned, or a failure if it returned success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """StopReplicationTask refuses a ready task and a stopped one with the same exact error,
    and StartReplicationTask reload-target restarts the stopped full-load task and reloads the
    target."""
    dms = ctx.client("dms")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    region = ctx.region

    dms_vpc_role_arn = _ensure_dms_vpc_role(ctx, iam)
    # DMS's refusal while the service role is not yet usable (IAM propagation).
    role_not_ready = (
        "AccessDeniedFault",
        f"The IAM Role {dms_vpc_role_arn} is not configured properly.",
    )

    src_bucket = ctx.unique_name("sim2real-behav-dms-src-")
    tgt_bucket = ctx.unique_name("sim2real-behav-dms-tgt-")
    for bucket in (src_bucket, tgt_bucket):
        # us-east-1 is the one region that refuses an explicit LocationConstraint.
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(
                Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
            )
        ctx.on_cleanup(lambda b=bucket: _teardown_step(f"bucket {b}", lambda: _empty_bucket(s3, b)))

    role_name = ctx.unique_name("sim2real-behav-dmsrole-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_DMS_TRUST))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(
        lambda: _teardown_step(f"role {role_name}", lambda: iam.delete_role(RoleName=role_name))
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:PutObject",
                            "s3:DeleteObject",
                            "s3:ListBucket",
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{b}{suffix}"
                            for b in (src_bucket, tgt_bucket)
                            for suffix in ("", "/*")
                        ],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _teardown_step(
            f"role policy s3-access on {role_name}",
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"),
        )
    )

    src_key = "srcdata/hr/employee/LOAD001.csv"
    s3.put_object(Bucket=src_bucket, Key=src_key, Body=_CSV)

    vpc_name = ctx.unique_name("sim2real-behav-dms-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.32.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _teardown_step(
            f"vpc {vpc_id}", lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        )
    )
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
            ]
        )["AvailabilityZones"]
    ][:2]
    assert len(zones) == 2, f"region {region} offered {zones}, need two availability zones"
    subnet_ids = []
    for i, zone in enumerate(zones):
        sn = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.32.{i + 1}.0/24",
            AvailabilityZone=zone,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": f"{vpc_name}-{i + 1}"}],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda s=sn: _teardown_step(
                f"subnet {s}", lambda: _delete_net(ec2, "delete_subnet", SubnetId=s)
            )
        )
        subnet_ids.append(sn)

    route_tables = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ]
    main_rt = next(
        rt["RouteTableId"] for rt in route_tables if any(a.get("Main") for a in rt["Associations"])
    )
    vpce_id = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{region}.s3",
        VpcEndpointType="Gateway",
        RouteTableIds=[main_rt],
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(
        lambda: _teardown_step(f"s3 gateway endpoint {vpce_id}", lambda: _delete_vpce(ec2, vpce_id))
    )

    sng = ctx.unique_name("sim2real-behav-dms-sng-")
    sng_deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            dms.create_replication_subnet_group(
                ReplicationSubnetGroupIdentifier=sng,
                ReplicationSubnetGroupDescription="sim2real stop/start task lifecycle check",
                SubnetIds=subnet_ids,
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code"),
                err.get("Message"),
            ) != role_not_ready or time.monotonic() >= sng_deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(
        lambda: _teardown_step(
            f"subnet group {sng}",
            lambda: dms.delete_replication_subnet_group(ReplicationSubnetGroupIdentifier=sng),
            budget_s=120,
        )
    )

    ri_id = ctx.unique_name("sim2real-behav-dms-ri-")
    ri_arn = dms.create_replication_instance(
        ReplicationInstanceIdentifier=ri_id,
        ReplicationInstanceClass="dms.c5.large",
        AllocatedStorage=5,
        ReplicationSubnetGroupIdentifier=sng,
        MultiAZ=False,
        PubliclyAccessible=False,
    )["ReplicationInstance"]["ReplicationInstanceArn"]
    ctx.on_cleanup(lambda: _delete_instance(ctx, dms, ri_arn, ri_id))

    # The body's waits together stay within 30 minutes.
    _await(
        ctx,
        lambda: _instance_status(dms, ri_id) or "gone",
        lambda st: st,
        {"available"},
        budget_s=900,
        what=f"replication instance {ri_id}",
        poll_s=20,
    )

    src_ep = dms.create_endpoint(
        EndpointIdentifier=ctx.unique_name("sim2real-behav-dms-src-ep-"),
        EndpointType="source",
        EngineName="s3",
        S3Settings={
            "ServiceAccessRoleArn": role_arn,
            "BucketName": src_bucket,
            "BucketFolder": "srcdata",
            "CsvDelimiter": ",",
            "CsvRowDelimiter": "\\n",
            "ExternalTableDefinition": json.dumps(_EXTERNAL_TABLE_DEFINITION),
        },
    )["Endpoint"]["EndpointArn"]
    ctx.on_cleanup(
        lambda: _teardown_step(
            "source endpoint", lambda: dms.delete_endpoint(EndpointArn=src_ep), budget_s=180
        )
    )

    tgt_ep = dms.create_endpoint(
        EndpointIdentifier=ctx.unique_name("sim2real-behav-dms-tgt-ep-"),
        EndpointType="target",
        EngineName="s3",
        S3Settings={
            "ServiceAccessRoleArn": role_arn,
            "BucketName": tgt_bucket,
            "BucketFolder": "tgtdata",
        },
    )["Endpoint"]["EndpointArn"]
    ctx.on_cleanup(
        lambda: _teardown_step(
            "target endpoint", lambda: dms.delete_endpoint(EndpointArn=tgt_ep), budget_s=180
        )
    )

    task_id = ctx.unique_name("sim2real-behav-dms-task-")
    task_arn = dms.create_replication_task(
        ReplicationTaskIdentifier=task_id,
        SourceEndpointArn=src_ep,
        TargetEndpointArn=tgt_ep,
        ReplicationInstanceArn=ri_arn,
        MigrationType="full-load",
        TableMappings=json.dumps(_TABLE_MAPPINGS),
    )["ReplicationTask"]["ReplicationTaskArn"]
    ctx.on_cleanup(lambda: _delete_task(dms, task_arn, task_id))

    _await(
        ctx,
        lambda: _task(dms, task_arn),
        lambda t: t["Status"],
        {"ready"},
        budget_s=180,
        what=f"replication task {task_id}",
        poll_s=10,
    )

    # Stop refuses a ready task, with a message naming the task's own arn.
    not_running = (
        "InvalidResourceStateFault",
        f"Replication Task: {task_arn} is currently not running.",
    )
    got = _error(lambda: dms.stop_replication_task(ReplicationTaskArn=task_arn))
    assert got == not_running, f"stopping a ready task gave {got!r}, expected {not_running!r}"

    dms.start_replication_task(
        ReplicationTaskArn=task_arn, StartReplicationTaskType="start-replication"
    )

    done = _await(
        ctx,
        lambda: _task(dms, task_arn),
        lambda t: t["Status"],
        {"stopped"},
        budget_s=360,
        what=f"replication task {task_id} first run",
        poll_s=10,
    )
    assert done["StopReason"] == "Stop Reason FULL_LOAD_ONLY_FINISHED", (
        f"first run stopped with StopReason {done.get('StopReason')!r}, expected the "
        f"full-load completion reason"
    )
    first_keys = s3.list_objects_v2(Bucket=tgt_bucket, Prefix="tgtdata/hr/employee/").get(
        "Contents", []
    )
    assert [o["Key"] for o in first_keys] == ["tgtdata/hr/employee/LOAD00000001.csv"], (
        f"first run left {[o['Key'] for o in first_keys]!r} under the table prefix, expected "
        f"exactly one full-load file"
    )
    first_stats = done["ReplicationTaskStats"]
    assert (first_stats["TablesLoaded"], first_stats["TablesErrored"]) == (1, 0), (
        f"first run reported TablesLoaded={first_stats['TablesLoaded']!r} "
        f"TablesErrored={first_stats['TablesErrored']!r}, expected (1, 0)"
    )
    first_full_load_start = first_stats["FullLoadStartDate"]

    # Stop refuses the same way once the task has finished on its own: the rule is about the
    # task's state, not about having never started.
    got = _error(lambda: dms.stop_replication_task(ReplicationTaskArn=task_arn))
    assert got == not_running, f"stopping a stopped task gave {got!r}, expected {not_running!r}"

    # StartReplicationTask restarts a stopped full-load task: reload-target re-runs the full
    # load from scratch. The poll waits for a FullLoadStartDate past the first run's, the evidence
    # that a new load actually executed, not that the stopped task's old result was reused.
    dms.start_replication_task(
        ReplicationTaskArn=task_arn, StartReplicationTaskType="reload-target"
    )

    restarted = _await(
        ctx,
        lambda: _task(dms, task_arn),
        lambda t: _restart_status(t, first_full_load_start),
        {"stopped"},
        budget_s=360,
        what=f"replication task {task_id} restart",
        poll_s=10,
    )
    assert restarted["StopReason"] == "Stop Reason FULL_LOAD_ONLY_FINISHED", (
        f"restarted run stopped with StopReason {restarted.get('StopReason')!r}, expected "
        f"the full-load completion reason"
    )
    second_stats = restarted["ReplicationTaskStats"]
    assert (second_stats["TablesLoaded"], second_stats["TablesErrored"]) == (1, 0), (
        f"restarted run reported TablesLoaded={second_stats['TablesLoaded']!r} "
        f"TablesErrored={second_stats['TablesErrored']!r}, expected (1, 0)"
    )
    second_keys = s3.list_objects_v2(Bucket=tgt_bucket, Prefix="tgtdata/hr/employee/").get(
        "Contents", []
    )
    assert [o["Key"] for o in second_keys] == ["tgtdata/hr/employee/LOAD00000001.csv"], (
        f"after reload-target the table prefix holds {[o['Key'] for o in second_keys]!r}, "
        f"expected the same single full-load file, rewritten"
    )
    reloaded = s3.get_object(Bucket=tgt_bucket, Key="tgtdata/hr/employee/LOAD00000001.csv")[
        "Body"
    ].read()
    assert reloaded == _CSV, (
        f"reload-target's output is {reloaded!r}, expected the same {len(_ROWS)} source rows {_CSV!r}"
    )

    # ===== teardown, in the body on purpose =====
    _teardown_step(
        f"replication task {task_id}",
        lambda: dms.delete_replication_task(ReplicationTaskArn=task_arn),
    )
    _gone(ctx, lambda: _task(dms, task_arn), budget_s=180, what=f"replication task {task_id}")
    for name, arn in (("source endpoint", src_ep), ("target endpoint", tgt_ep)):
        _teardown_step(name, lambda a=arn: dms.delete_endpoint(EndpointArn=a))
    _delete_instance(ctx, dms, ri_arn, ri_id)
    _teardown_step(
        f"subnet group {sng}",
        lambda: dms.delete_replication_subnet_group(ReplicationSubnetGroupIdentifier=sng),
        budget_s=_budget_s(ctx, 120),
    )
    _teardown_step(f"s3 gateway endpoint {vpce_id}", lambda: _delete_vpce(ec2, vpce_id))
    for sn in subnet_ids:
        _teardown_step(
            f"subnet {sn}", lambda s=sn: ec2.delete_subnet(SubnetId=s), budget_s=_budget_s(ctx, 180)
        )
    _teardown_step(
        f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id), budget_s=_budget_s(ctx, 180)
    )
    _teardown_step(
        f"role policy s3-access on {role_name}",
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"),
    )
    _teardown_step(f"role {role_name}", lambda: iam.delete_role(RoleName=role_name))
    for bucket in (src_bucket, tgt_bucket):
        _teardown_step(f"bucket {bucket}", lambda b=bucket: _empty_bucket(s3, b))


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
    flt = [
        {"Name": _NET_ENI_FILTER[k], "Values": [v]}
        for k, v in ident.items()
        if k in _NET_ENI_FILTER
    ]
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
                raise type(exc)(
                    {
                        **exc.response,
                        "Error": {
                            **exc.response.get("Error", {}),
                            "Message": (
                                f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                                f"ENIs still attached: {_net_enis(client, flt)}"
                            ),
                        },
                    },
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
        return []
    return [
        f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}"
        for e in enis
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
