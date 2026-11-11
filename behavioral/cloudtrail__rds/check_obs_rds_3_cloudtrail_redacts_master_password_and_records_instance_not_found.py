"""obs-rds-3-cloudtrail-redacts-master-password-and-records-instance-not-found."""

from __future__ import annotations

import datetime
import json
import secrets
import string
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-rds-3-cloudtrail-redacts-master-password-and-records-instance-not-found"
GROUP = "eventing"
SERVICES = ["cloudtrail", "rds"]

_USER = "sim2real"
_EVENT_SOURCE = "rds.amazonaws.com"
#: The literal CloudTrail substitutes for a secret request member such as the DB admin password.
_REDACTED = "HIDDEN_DUE_TO_SECURITY_REASONS"
#: The RDS API error code for an unknown instance identifier (the botocore Error.Code).
_API_NOT_FOUND = "DBInstanceNotFound"
#: What CloudTrail records as errorCode for the same failed call: the fault-shape name, not the
#: API error code the caller saw.
_TRAIL_NOT_FOUND = "DBInstanceNotFoundFault"
_NOT_FOUND_MESSAGE = "DBInstance {instance_id} not found."
#: Ceiling on CloudTrail event-history propagation, which AWS documents as up to ~15 minutes.
_CLOUDTRAIL_WAIT_S = 1200
_POLL_INTERVAL_S = 2
_PAGE_CEILING = 40
_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
    {"Key": "sim2real", "Value": "obs-rds-3-cloudtrail"},
]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, pred, *, timeout_s, interval_s, description, ctx=None):
    """Poll probe() until pred(value); RAISE on the deadline, never return the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(
                f"{description} was not observed within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)


#: Codes a delete returns while a dependency or a transitional state still holds the resource.
_RETRY_DELETE_CODES = (
    "DependencyViolation",
    "InvalidDBInstanceState",
    "InvalidDBSubnetGroupStateFault",
    "InvalidDBSubnetStateFault",
)


def _retry_delete(fn, *tolerated_codes, timeout_s=900, interval_s=2, what=""):
    """Delete something; return on a not-found code in tolerated_codes, retry only the codes in
    _RETRY_DELETE_CODES until the deadline, and raise every other error."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in tolerated_codes:
                return
            if code not in _RETRY_DELETE_CODES:
                raise
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{what or fn!r} not deleted, last error {code!r}") from exc
        time.sleep(interval_s)


def _error(fn):
    """(code, message) of the AWS error raised by fn(), RAISING if the call unexpectedly SUCCEEDS."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be REJECTED but succeeded, returning {resp!r}")


def _password():
    """A fresh random DB admin password per run. Letters and digits only: RDS rejects / @ " and
    space. Random so the 'plaintext appears nowhere' assertion is about THIS run's secret."""
    alphabet = string.ascii_letters + string.digits
    return "S2r" + "".join(secrets.choice(alphabet) for _ in range(29))


def _network(ctx):
    """A dedicated VPC with private subnets in two AZs and a DB subnet group, built rather than
    discovered, as the account may have no default VPC. No internet gateway."""
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.173.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound", what=f"vpc {vpc_id}"))
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
        ctx.on_cleanup(lambda s=subnet_id: _retry_delete(
            lambda: _delete_net(ec2, "delete_subnet", SubnetId=s), "InvalidSubnetID.NotFound",
            what=f"subnet {s}"))
        subnet_ids.append(subnet_id)

    group_name = ctx.unique_name("sim2real-xsvc-subnets-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=group_name,
        DBSubnetGroupDescription="sim2real cloudtrail redaction check",
        SubnetIds=subnet_ids,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: rds.delete_db_subnet_group(DBSubnetGroupName=group_name),
        "DBSubnetGroupNotFoundFault", what=f"db subnet group {group_name}"))
    return group_name


def _instance(rds, inst_id):
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return None
        raise


def _delete_instance(rds, inst_id):
    """Delete, retrying while the instance is still in a state that refuses deletion (it is
    usually still 'creating' here), then wait for it to be gone so the subnet group and VPC
    behind it can be torn down."""
    _retry_delete(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True),
        "DBInstanceNotFound",
        timeout_s=600,
        what=f"db instance {inst_id}",
    )
    try:
        _poll_until(
            lambda: _instance(rds, inst_id),
            lambda i: i is None,
            timeout_s=900,
            interval_s=2,
            description=f"db instance {inst_id} disappearing",
        )
    except AssertionError as exc:
        raise RuntimeError(f"{exc}") from exc


def _default_engine_version(rds, engine):
    versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
        "DBEngineVersions", [])
    assert versions, f"no default {engine!r} engine version is orderable in {rds.meta.region_name}"
    return versions[0]["EngineVersion"]


def _orderable_class(rds, engine, version):
    classes = set()
    for page in rds.get_paginator("describe_orderable_db_instance_options").paginate(
            Engine=engine, EngineVersion=version):
        for opt in page.get("OrderableDBInstanceOptions", []):
            classes.add(opt["DBInstanceClass"])
    for want in ("db.t4g.micro", "db.t3.micro", "db.t4g.small", "db.t3.small"):
        if want in classes:
            return want
    raise AssertionError(
        f"no small orderable instance class for {engine} {version}; offered {sorted(classes)!r}")


def _rds_events_since(ct, start):
    """Every Event-history record with EventSource rds.amazonaws.com since `start`, paged to
    exhaustion (bounded), each paired with its parsed CloudTrailEvent and the raw string."""
    out = []
    kw = {
        "StartTime": start,
        "MaxResults": 50,
        "LookupAttributes": [{"AttributeKey": "EventSource", "AttributeValue": _EVENT_SOURCE}],
    }
    for _ in range(_PAGE_CEILING):
        for attempt in range(6):
            try:
                resp = ct.lookup_events(**kw)
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ThrottlingException" or attempt == 5:
                    raise
                time.sleep(2 + attempt)
        for e in resp.get("Events", []):
            raw = e.get("CloudTrailEvent") or ""
            out.append((json.loads(raw) if raw else {}, raw))
        nxt = resp.get("NextToken")
        if not nxt:
            return out
        kw["NextToken"] = nxt
        time.sleep(0.6)
    return out


def _records(events, name, identifier):
    return [
        (d, raw) for d, raw in events
        if d.get("eventName") == name
        and (d.get("requestParameters") or {}).get("dBInstanceIdentifier") == identifier
    ]


@tags(
    "axis:rejection",
    "concern:eventing",
    "concern:representation",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c5",
)
def run(ctx) -> None:
    """CloudTrail records CreateDBInstance with the random DB admin password redacted to
    HIDDEN_DUE_TO_SECURITY_REASONS, and a DescribeDBInstances on an unknown id as failed with
    errorCode DBInstanceNotFoundFault and a message naming it, unlike the successful control."""
    try:
        rds = ctx.client("rds")
        ct = ctx.client("cloudtrail")
        account_id = ctx.client("sts").get_caller_identity()["Account"]
        assert account_id.isdigit(), f"caller account id is not numeric: {account_id!r}"

        engine = "postgres"
        version = _default_engine_version(rds, engine)
        klass = _orderable_class(rds, engine, version)
        subnet_group = _network(ctx)

        password = _password()
        inst_id = ctx.unique_name("sim2real-xsvc-ct-")
        # A margin before the first recorded call absorbs clock skew between this host and AWS.
        start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)

        created = rds.create_db_instance(
            DBInstanceIdentifier=inst_id,
            Engine=engine,
            EngineVersion=version,
            DBInstanceClass=klass,
            AllocatedStorage=20,
            MasterUsername=_USER,
            MasterUserPassword=password,
            DBSubnetGroupName=subnet_group,
            BackupRetentionPeriod=0,
            PubliclyAccessible=False,
            DeletionProtection=False,
            Tags=_TAGS,
        )["DBInstance"]
        ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))
        assert created.get("DBInstanceIdentifier") == inst_id, (
            f"CreateDBInstance returned identifier {created.get('DBInstanceIdentifier')!r}, "
            f"expected {inst_id!r}")
        assert password not in json.dumps(created, default=str), (
            "CreateDBInstance's own response must not echo the master password")

        # Positive control for the rejection: the identifier this check created IS describable.
        seen = rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"]
        assert [i.get("DBInstanceIdentifier") for i in seen] == [inst_id], (
            f"DescribeDBInstances on the created instance returned "
            f"{[i.get('DBInstanceIdentifier') for i in seen]!r}, expected [{inst_id!r}]")

        missing_id = f"sim2real-nf-{uuid.uuid4().hex}"
        code, api_message = _error(
            lambda: rds.describe_db_instances(DBInstanceIdentifier=missing_id)
        )
        assert code == _API_NOT_FOUND, (
            f"DescribeDBInstances on never-created {missing_id!r} must be rejected with "
            f"{_API_NOT_FOUND!r}; got {code!r}")
        want_message = _NOT_FOUND_MESSAGE.format(instance_id=missing_id)
        assert api_message == want_message, (
            f"DescribeDBInstances on never-created {missing_id!r}: expected message "
            f"{want_message!r}; got {api_message!r}")

        def _snapshot():
            events = _rds_events_since(ct, start)
            return {
                "create": _records(events, "CreateDBInstance", inst_id),
                "describe_ok": _records(events, "DescribeDBInstances", inst_id),
                "describe_missing": _records(events, "DescribeDBInstances", missing_id),
            }

        found = _poll_until(
            _snapshot,
            lambda s: all(s[k] for k in ("create", "describe_ok", "describe_missing")),
            timeout_s=_budget_s(ctx, _CLOUDTRAIL_WAIT_S),
            interval_s=_POLL_INTERVAL_S,
            ctx=ctx,
            description=(
                f"CloudTrail Event history (EventSource {_EVENT_SOURCE}) holding the CreateDBInstance "
                f"and DescribeDBInstances of {inst_id!r} and the DescribeDBInstances of {missing_id!r}"
            ),
        )

        # --- the CreateDBInstance record: right event, right subject, password redacted.
        for rec, raw in found["create"]:
            params = rec.get("requestParameters") or {}
            assert rec.get("eventSource") == _EVENT_SOURCE, (
                f"CreateDBInstance record eventSource is {rec.get('eventSource')!r}")
            assert rec.get("eventName") == "CreateDBInstance", (
                f"record eventName is {rec.get('eventName')!r}")
            assert params.get("dBInstanceIdentifier") == inst_id, (
                f"requestParameters.dBInstanceIdentifier is {params.get('dBInstanceIdentifier')!r}, "
                f"expected {inst_id!r}")
            assert "errorCode" not in rec, (
                f"a SUCCESSFUL CreateDBInstance must carry no errorCode; record has "
                f"{rec.get('errorCode')!r}: {rec.get('errorMessage')!r}")
            assert rec.get("recipientAccountId") == account_id, (
                f"recipientAccountId is {rec.get('recipientAccountId')!r}, expected {account_id!r}")
            assert params.get("masterUserPassword") == _REDACTED, (
                f"requestParameters.masterUserPassword must be the literal {_REDACTED!r}; record has "
                f"{params.get('masterUserPassword')!r}")
            # Redaction is targeted, not blanket: the non-secret sibling is recorded verbatim.
            assert params.get("masterUsername") == _USER, (
                f"requestParameters.masterUsername must be kept verbatim as {_USER!r}; record has "
                f"{params.get('masterUsername')!r}")
            assert password not in raw, (
                "the real master password appears in the CloudTrailEvent string of the "
                f"CreateDBInstance record for {inst_id!r}")

        # --- positive control in the trail: the successful describe has no error fields.
        for rec, raw in found["describe_ok"]:
            assert "errorCode" not in rec and "errorMessage" not in rec, (
                f"DescribeDBInstances on the existing {inst_id!r} succeeded on the API but the trail "
                f"records errorCode={rec.get('errorCode')!r} errorMessage={rec.get('errorMessage')!r}")

        # --- the rejected describe: recorded as failed with the trail's own spelling of the fault.
        for rec, raw in found["describe_missing"]:
            assert rec.get("eventSource") == _EVENT_SOURCE, (
                f"rejected DescribeDBInstances record eventSource is {rec.get('eventSource')!r}")
            assert rec.get("errorCode") == _TRAIL_NOT_FOUND, (
                f"the rejected DescribeDBInstances of {missing_id!r} must be recorded with errorCode "
                f"{_TRAIL_NOT_FOUND!r}; record has {rec.get('errorCode')!r}")
            assert rec.get("errorMessage") == want_message, (
                f"the rejected DescribeDBInstances record errorMessage: expected {want_message!r}; "
                f"got {rec.get('errorMessage')!r}")
            assert rec.get("readOnly") is True, (
                f"DescribeDBInstances is a read-only call; record readOnly is {rec.get('readOnly')!r}")

        # Over-permissiveness guard: no record of this run, of any kind, carries the plaintext.
        for key, recs in found.items():
            for _rec, raw in recs:
                assert password not in raw, f"the master password leaked into a {key} record"

    finally:
        # Teardown runs here, inside the check body: post-check cleanup is bounded at 60 s and
        # cannot wait out an RDS delete.
        ctx.run_cleanups()


# Deletes in this VPC are asynchronous: their ENIs linger, so DeleteSubnet / DeleteSecurityGroup /
# DeleteVpc fail with DependencyViolation. Wait (bounded) for the ENIs, retry inside the window, and
# raise naming any ENIs still attached.
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
