"""enhanced-monitoring-publishes-os-metric-documents-at-its-interval."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enhanced-monitoring-publishes-os-metric-documents-at-its-interval"
GROUP = "logging"
SERVICES = ["rds"]

_DB = "simparitydb"
_USER = "sim2real"
_PASS = "Sim2Real#Pass99"
#: Account-wide, created and owned by RDS. NEVER deleted by this check — other instances in the
#: account publish into it.
_OS_GROUP = "RDSOSMetrics"
#: A valid granularity from the fixed set {0,1,5,10,15,30,60}. 15 is the smallest that leaves room
#: for a two-sided gap assertion without racing the publisher.
_INTERVAL_S = 15
#: Not in the valid set, and not adjustable per account, so the rejection is contract.
_INVALID_INTERVAL_S = 7
_MIN_GAP_S = 5
_MAX_GAP_S = 45
_DOC_BUDGET_S = 900
_ABSENCE_FLOOR_S = 150.0
_ABSENCE_CEILING_S = 420.0
_MONITORING_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": "enhanced-monitoring-delivery"},
]


def _poll_until(probe, pred, *, timeout_s, interval_s, description):
    """Poll probe() until pred(value); RAISE on the deadline, never return the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} was not observed within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, so a target that
    ACCEPTS input real AWS refuses fails as an acceptance, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


#: Codes AWS answers while a dependency of the resource is still being released.
_BUSY_CODES = (
    "DependencyViolation", "DeleteConflict", "InvalidDBInstanceState",
    "InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState",
)


def _retry_delete(fn, *tolerated_codes, timeout_s=900, interval_s=2, what=""):
    """Delete something: done on its not-found codes, retried while a dependency still holds it
    (_BUSY_CODES) to the deadline, and every other error raised."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in tolerated_codes:
                return
            if code not in _BUSY_CODES:
                raise
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{what or fn!r} not deleted, last error {code!r}") from exc
        time.sleep(interval_s)


def _network(ctx):
    """A dedicated VPC with subnets in two AZs and a DB subnet group, built because the account
    may have no default VPC. No internet gateway: the check never connects to the engine."""
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.173.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound", what=f"vpc {vpc_id}"
        )
    )
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    zones = ec2.describe_availability_zones(
        Filters=[
            {"Name": "state", "Values": ["available"]},
            {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
        ]
    )["AvailabilityZones"]
    azs = sorted(z["ZoneName"] for z in zones)
    assert len(azs) >= 2, (
        f"a DB subnet group needs subnets in at least 2 availability zones; {ctx.region} offered "
        f"{azs!r}"
    )

    subnet_ids = []
    for index, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.173.{index}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda s=subnet_id: _retry_delete(
                lambda: _delete_net(ec2, "delete_subnet", SubnetId=s),
                "InvalidSubnetID.NotFound",
                what=f"subnet {s}",
            )
        )
        subnet_ids.append(subnet_id)

    group_name = ctx.unique_name("sim2real-behav-subnets-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=group_name,
        DBSubnetGroupDescription="sim2real enhanced-monitoring subnets",
        SubnetIds=subnet_ids,
        Tags=_TAGS,
    )
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: rds.delete_db_subnet_group(DBSubnetGroupName=group_name),
            "DBSubnetGroupNotFoundFault",
            what=f"db subnet group {group_name}",
        )
    )
    return group_name


def _monitoring_role(ctx):
    """Create-or-adopt the Enhanced Monitoring role RDS assumes to write to CloudWatch Logs."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-rdsmon-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "monitoring.rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="sim2real RDS Enhanced Monitoring",
            Tags=_TAGS,
        )["Role"]["Arn"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityAlreadyExists":
            raise
        arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    def _drop_role() -> None:
        _retry_delete(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_MONITORING_POLICY),
            "NoSuchEntity",
            timeout_s=120,
            what=f"detach {_MONITORING_POLICY} from {role_name}",
        )
        _retry_delete(
            lambda: iam.delete_role(RoleName=role_name),
            "NoSuchEntity",
            timeout_s=300,
            what=f"iam role {role_name}",
        )

    ctx.on_cleanup(_drop_role)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_MONITORING_POLICY)
    attached = [
        p["PolicyArn"]
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
    ]
    assert _MONITORING_POLICY in attached, (
        f"the monitoring role {role_name} must carry {_MONITORING_POLICY}; attached policies are "
        f"{attached!r}"
    )
    return arn


def _create_instance_with_role_propagation(rds, create_kwargs, *, timeout_s=180, interval_s=10):
    """CreateDBInstance, retried while RDS rejects a just-created monitoring role as invalid
    because the IAM attachment has not propagated yet."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.create_db_instance(**create_kwargs)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") == "InvalidParameterValue" and "ENHANCED_MONITORING" in error.get(
                "Message", ""
            ):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(interval_s)
                continue
            raise


def _instance(rds, inst_id):
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return None
        raise


def _delete_instance(rds, inst_id):
    _retry_delete(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
        ),
        "DBInstanceNotFound",
        what=f"db instance {inst_id}",
    )
    _poll_until(
        lambda: _instance(rds, inst_id),
        lambda i: i is None,
        timeout_s=1800,
        interval_s=20,
        description=f"db instance {inst_id} disappearing so its VPC and role can be torn down",
    )


def _monitoring_interval(rds, inst_id):
    inst = _instance(rds, inst_id)
    assert inst is not None, f"db instance {inst_id} vanished while reading MonitoringInterval"
    return inst.get("MonitoringInterval")


def _default_engine_version(rds, engine):
    versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
        "DBEngineVersions", []
    )
    assert versions, f"no default {engine!r} engine version is orderable in {rds.meta.region_name}"
    return versions[0]


def _orderable_class(rds, engine, version):
    classes = set()
    for page in rds.get_paginator("describe_orderable_db_instance_options").paginate(
        Engine=engine, EngineVersion=version
    ):
        for opt in page.get("OrderableDBInstanceOptions", []):
            classes.add(opt["DBInstanceClass"])
    for want in ("db.t4g.micro", "db.t3.micro", "db.t4g.small", "db.t3.small"):
        if want in classes:
            return want
    raise AssertionError(
        f"no small orderable instance class for {engine} {version}; offered {sorted(classes)!r}"
    )


def _os_documents(logs, inst_id, *, since_ms=None):
    """Every Enhanced Monitoring document in RDSOSMetrics that names THIS instance, oldest first.

    Selected by the document's `instanceID` field: stream naming is documented inconsistently."""
    kwargs = {
        "logGroupName": _OS_GROUP,
        "filterPattern": f'{{$.instanceID = "{inst_id}"}}',
    }
    if since_ms is not None:
        kwargs["startTime"] = since_ms
    documents = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(**kwargs):
            for event in page.get("events", []):
                try:
                    documents.append((event["timestamp"], json.loads(event["message"])))
                except (KeyError, ValueError) as exc:
                    raise AssertionError(
                        f"an event in {_OS_GROUP} matched instanceID={inst_id!r} but is not a JSON "
                        f"document: {event!r} ({exc!r})"
                    ) from exc
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise
    return sorted(documents, key=lambda pair: pair[0])


def _drop_own_streams(logs, resource_id):
    """Delete only the streams this check's instance produced inside the SHARED group, scoped by
    its DbiResourceId so no other instance's streams are touched."""
    try:
        page = logs.describe_log_streams(
            logGroupName=_OS_GROUP, logStreamNamePrefix=resource_id
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    for stream in page.get("logStreams", []):
        name = stream.get("logStreamName", "")
        if resource_id and resource_id in name:
            _retry_delete(
                lambda n=name: logs.delete_log_stream(logGroupName=_OS_GROUP, logStreamName=n),
                "ResourceNotFoundException",
                timeout_s=120,
                what=f"log stream {_OS_GROUP}/{name}",
            )


# timing:real-time — metric: 15 s https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Monitoring.OS.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:metrics",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Enhanced Monitoring publishes JSON OS metric documents naming the instance's DbiResourceId
    about one MonitoringInterval apart, stops at interval 0 and resumes when restored; an interval
    of 7 is refused. Ref: docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Monitoring.OS.html"""
    rds = ctx.client("rds")
    logs = ctx.client("logs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    assert account_id.isdigit(), f"caller account id is not numeric: {account_id!r}"

    engine = "postgres"
    version = _default_engine_version(rds, engine)["EngineVersion"]
    klass = _orderable_class(rds, engine, version)
    subnet_group = _network(ctx)
    role_arn = _monitoring_role(ctx)

    inst_id = ctx.unique_name("sim2real-behav-inst-")
    _create_instance_with_role_propagation(
        rds,
        dict(
            DBInstanceIdentifier=inst_id,
            Engine=engine,
            EngineVersion=version,
            DBInstanceClass=klass,
            AllocatedStorage=20,
            MasterUsername=_USER,
            MasterUserPassword=_PASS,
            DBName=_DB,
            DBSubnetGroupName=subnet_group,
            BackupRetentionPeriod=0,
            PubliclyAccessible=False,
            DeletionProtection=False,
            MonitoringInterval=_INTERVAL_S,
            MonitoringRoleArn=role_arn,
            Tags=_TAGS,
        ),
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))

    inst = _poll_until(
        lambda: _instance(rds, inst_id),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=1800,
        interval_s=20,
        description=f"db instance {inst_id} reaching 'available' with Enhanced Monitoring on",
    )
    resource_id = inst.get("DbiResourceId")
    assert resource_id, (
        f"DescribeDBInstances must report a DbiResourceId for {inst_id} — it is what the Enhanced "
        f"Monitoring document has to name; got {inst!r}"
    )
    ctx.on_cleanup(lambda: _drop_own_streams(logs, resource_id))
    assert inst.get("MonitoringInterval") == _INTERVAL_S, (
        f"expected MonitoringInterval {_INTERVAL_S} on {inst_id}, instance reports "
        f"{inst.get('MonitoringInterval')!r}"
    )

    # --- positive control: documents arrive, and their content is derived, not pinned.
    started = time.monotonic()
    documents = _poll_until(
        lambda: _os_documents(logs, inst_id),
        lambda docs: docs is not None and len(docs) >= 2,
        timeout_s=_DOC_BUDGET_S,
        interval_s=20,
        description=(
            f"at least two Enhanced Monitoring documents naming instanceID={inst_id!r} in the "
            f"{_OS_GROUP} log group"
        ),
    )
    latency_s = time.monotonic() - started

    first, second = documents[-2][1], documents[-1][1]
    for label, document in (("first", first), ("second", second)):
        missing = sorted(
            {"engine", "instanceID", "instanceResourceID", "timestamp", "version", "uptime",
             "numVCPUs"}
            - set(document)
        )
        assert not missing, (
            f"the {label} Enhanced Monitoring document for {inst_id} is missing required fields "
            f"{missing!r}; it carried {sorted(document)!r}"
        )
        assert document["instanceID"] == inst_id, (
            f"expected instanceID {inst_id!r} in the {label} document, got "
            f"{document['instanceID']!r}"
        )
        assert document["instanceResourceID"] == resource_id, (
            f"the {label} document must name the DbiResourceId DescribeDBInstances reports for "
            f"{inst_id}: expected {resource_id!r}, document says "
            f"{document['instanceResourceID']!r}"
        )
        assert document["engine"] == "POSTGRES", (
            f"expected engine 'POSTGRES' in the {label} document for a postgres instance, got "
            f"{document['engine']!r}"
        )
        assert document["version"] == 1, (
            f"expected Enhanced Monitoring document version 1 in the {label} document, got "
            f"{document['version']!r}"
        )

    # Two-sided clock: the gap between two consecutive documents must bracket the interval set.
    gap_s = (documents[-1][0] - documents[-2][0]) / 1000.0
    assert _MIN_GAP_S <= gap_s <= _MAX_GAP_S, (
        f"consecutive Enhanced Monitoring documents must be about MonitoringInterval "
        f"({_INTERVAL_S}s) apart: expected a gap in [{_MIN_GAP_S}, {_MAX_GAP_S}]s, measured "
        f"{gap_s:.1f}s between {documents[-2][0]} and {documents[-1][0]}"
    )
    assert second["uptime"] != first["uptime"], (
        f"the host's reported uptime must advance between two documents {gap_s:.1f}s apart; both "
        f"say {first['uptime']!r}"
    )

    # --- always-invalid-input negative on the same wiring: 7 is not in the fixed valid set.
    error = _client_error(
        lambda: rds.modify_db_instance(
            DBInstanceIdentifier=inst_id,
            MonitoringInterval=_INVALID_INTERVAL_S,
            MonitoringRoleArn=role_arn,
            ApplyImmediately=True,
        )
    )
    assert error.get("Code") == "InvalidParameterValue", (
        f"MonitoringInterval={_INVALID_INTERVAL_S} is outside the fixed valid set "
        f"{{0,1,5,10,15,30,60}} and must be refused with InvalidParameterValue; got "
        f"{error.get('Code')!r} / {error.get('Message')!r}"
    )
    expected = "Invalid monitoring interval, please enter a value in [0, 1, 5, 10, 15, 30, 60]"
    assert error.get("Message") == expected, (
        f"expected message {expected!r}, got {error.get('Message')!r}"
    )
    assert _monitoring_interval(rds, inst_id) == _INTERVAL_S, (
        f"the refused MonitoringInterval must leave the instance unchanged: expected "
        f"{_INTERVAL_S}, DescribeDBInstances now reports "
        f"{_monitoring_interval(rds, inst_id)!r}"
    )

    # --- break exactly one thing: turn Enhanced Monitoring off.
    off_at_ms = int(time.time() * 1000)
    rds.modify_db_instance(
        DBInstanceIdentifier=inst_id, MonitoringInterval=0, ApplyImmediately=True
    )
    _poll_until(
        lambda: _monitoring_interval(rds, inst_id),
        lambda value: value == 0,
        timeout_s=900,
        interval_s=15,
        description=f"MonitoringInterval on {inst_id} reaching 0",
    )
    # Documents stamped within three intervals of the switch-off may still be in flight, so the
    # boundary is fixed there: every document after it must be absent.
    settle_ms = off_at_ms + 3 * _INTERVAL_S * 1000

    window_s = min(max(3.0 * latency_s, _ABSENCE_FLOOR_S), _ABSENCE_CEILING_S)
    deadline = (
        time.monotonic() + max(0.0, (settle_ms - time.time() * 1000) / 1000) + window_s
    )
    samples = 0
    while time.monotonic() < deadline:
        leaked = _os_documents(logs, inst_id, since_ms=settle_ms)
        assert leaked == [], (
            f"Enhanced Monitoring kept publishing after MonitoringInterval was set to 0: expected "
            f"no document for {inst_id} newer than {settle_ms}, saw {len(leaked or [])} after "
            f"{time.monotonic() - (deadline - window_s):.0f}s of a {window_s:.0f}s window (the "
            f"enabled interval had needed {latency_s:.0f}s to produce two)"
        )
        samples += 1
        time.sleep(2)
    assert samples >= 3, (
        f"the absence window took too few samples to be meaningful: {samples} over {window_s:.0f}s"
    )

    # --- repair the one broken thing and DEMAND the withheld documents back.
    resume_ms = int(time.time() * 1000)
    rds.modify_db_instance(
        DBInstanceIdentifier=inst_id,
        MonitoringInterval=_INTERVAL_S,
        MonitoringRoleArn=role_arn,
        ApplyImmediately=True,
    )
    _poll_until(
        lambda: _monitoring_interval(rds, inst_id),
        lambda value: value == _INTERVAL_S,
        timeout_s=900,
        interval_s=15,
        description=f"MonitoringInterval on {inst_id} returning to {_INTERVAL_S}",
    )
    resumed = _poll_until(
        lambda: _os_documents(logs, inst_id, since_ms=resume_ms),
        lambda docs: bool(docs),
        timeout_s=_DOC_BUDGET_S,
        interval_s=20,
        description=(
            f"an Enhanced Monitoring document for {inst_id} newer than {resume_ms} — the leg that "
            f"proves the switch-off, not a broken agent or role, withheld the earlier ones"
        ),
    )
    assert resumed[-1][1]["instanceResourceID"] == resource_id, (
        f"the document delivered after monitoring resumed must still name {resource_id!r}; it says "
        f"{resumed[-1][1].get('instanceResourceID')!r}"
    )


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes: resources in the
# VPC delete asynchronously and their ENIs linger, so an immediate delete hits DependencyViolation.
# The bounded window is shared by all of one check's network deletes.
_NET_TEARDOWN_S = 1260.0
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
