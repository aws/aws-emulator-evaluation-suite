"""xsvc-rds-2-managed-master-secret-under-cmk-rejects-direct-writes."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-rds-2-managed-master-secret-under-cmk-rejects-direct-writes"
GROUP = "service-owned-secret-enforcement"
SERVICES = ["kms", "rds", "secretsmanager"]

_SCENARIO = "rds-managed-secret-cmk"
_USER = "sim2real"
_TAGS = [
    {"Key": "sim2real", "Value": _SCENARIO},
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
]
#: PutSecretValue on an RDS-managed admin user secret: InvalidRequestException, HTTP 400.
_PUT_CODE = "InvalidRequestException"
_PUT_MSG = (
    "This secret is managed by Amazon RDS (service ID: rds), and you must use that service to "
    "update it. For more information, see "
    "https://docs.aws.amazon.com/secretsmanager/latest/userguide/service-linked-secrets.html."
)
#: DeleteSecret(ForceDeleteWithoutRecovery=True): InvalidRequestException, HTTP 400.
_DELETE_CODE = "InvalidRequestException"
_DELETE_MSG = "Operation is not allowed on secret owned by rds"
#: DescribeSecret after DeleteDBInstance removed the managed secret.
_GONE_CODE = "ResourceNotFoundException"
_GONE_MSG = "Secrets Manager can't find the specified secret."
#: What _call reports for a call that SUCCEEDED: a value no error code can equal.
_ACCEPTED = "<call succeeded>"


@tags(
    "axis:rejection",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """An RDS-managed admin secret created under a CMK reports that CMK in RDS and Secrets Manager,
    is owned by rds, readable, refuses PutSecretValue and force DeleteSecret without effect, and is
    removed by DeleteDBInstance."""
    kms = ctx.client("kms")
    rds = ctx.client("rds")
    sm = ctx.client("secretsmanager")
    ec2 = ctx.client("ec2")

    key = kms.create_key(
        Description="sim2real xsvc check: CMK for an RDS-managed master user secret",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": t["Key"], "TagValue": t["Value"]} for t in _TAGS],
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: _schedule_key_deletion(kms, key_id))

    subnet_group = _network(ctx, ec2, rds)
    engine = "postgres"
    version = _default_engine_version(rds, engine)
    klass = _orderable_class(rds, engine, version)

    inst_id = ctx.unique_name("sim2real-xsvc-msec-")
    created = rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        Engine=engine,
        EngineVersion=version,
        DBInstanceClass=klass,
        AllocatedStorage=20,
        MasterUsername=_USER,
        ManageMasterUserPassword=True,
        MasterUserSecretKmsKeyId=key_arn,
        BackupRetentionPeriod=0,
        DBSubnetGroupName=subnet_group,
        PubliclyAccessible=False,
        DeletionProtection=False,
        Tags=_TAGS,
    )["DBInstance"]
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id, wait_s=1200, raise_on_leak=True))
    secret_arn = (created.get("MasterUserSecret") or {}).get("SecretArn")
    assert secret_arn, (
        f"ManageMasterUserPassword=True must return a MasterUserSecret.SecretArn: {created!r}"
    )

    _wait_instance_available(rds, inst_id)
    managed = _poll_until(
        lambda: (_instance(rds, inst_id) or {}).get("MasterUserSecret") or {},
        lambda m: m.get("SecretStatus") == "active",
        timeout_s=600, interval_s=15, description="MasterUserSecret.SecretStatus to be active",
    )
    assert managed.get("SecretArn") == secret_arn, f"MasterUserSecret changed ARN: {managed!r}"
    assert managed.get("KmsKeyId") == key_arn, (
        f"DescribeDBInstances must report MasterUserSecret.KmsKeyId as the CMK {key_arn!r}; "
        f"got {managed.get('KmsKeyId')!r}"
    )

    desc = sm.describe_secret(SecretId=secret_arn)
    assert desc.get("KmsKeyId") == key_arn, (
        f"Secrets Manager must report the managed secret under the same CMK {key_arn!r}; "
        f"DescribeSecret says {desc.get('KmsKeyId')!r}"
    )
    assert desc.get("OwningService") == "rds", (
        f"the managed master user secret must be owned by rds; OwningService="
        f"{desc.get('OwningService')!r}"
    )
    assert desc.get("DeletedDate") is None, f"fresh managed secret already deleted: {desc!r}"

    # --- positive control: the secret is live and decrypts under the CMK ------------------------
    current = sm.get_secret_value(SecretId=secret_arn)
    doc = json.loads(current["SecretString"])
    assert doc.get("username") == _USER and isinstance(doc.get("password"), str) \
        and doc["password"], (
            f"the managed secret must hold the master username {_USER!r} and a password; keys "
            f"{sorted(doc)!r}, username {doc.get('username')!r}"
        )
    versions_before = _all_version_ids(sm, secret_arn)
    assert current["VersionId"] in versions_before, (
        f"AWSCURRENT {current['VersionId']!r} missing from the version list {versions_before!r}"
    )

    # --- (a)+(b) a direct write is refused and mints nothing ------------------------------------
    code, status, msg, result = _call(
        lambda: sm.put_secret_value(SecretId=secret_arn,
                                    SecretString=json.dumps({"username": _USER, "password": "x"}))
    )
    assert code == _PUT_CODE, (
        f"PutSecretValue on an RDS-managed secret must be refused with {_PUT_CODE}; got "
        f"code={code!r} status={status!r} message={msg!r} result={result!r}"
    )
    assert status == 400, f"the PutSecretValue refusal must be HTTP 400, got {status!r}"
    put_msg = msg
    after_put = sm.get_secret_value(SecretId=secret_arn)
    assert after_put["VersionId"] == current["VersionId"], (
        f"the refused PutSecretValue moved AWSCURRENT {current['VersionId']!r} -> "
        f"{after_put['VersionId']!r}"
    )
    assert _all_version_ids(sm, secret_arn) == versions_before, (
        f"the refused PutSecretValue minted a version: {_all_version_ids(sm, secret_arn)!r} vs "
        f"{versions_before!r}"
    )

    # --- (a)+(b) a direct force delete is refused and deletes nothing ---------------------------
    # Only the force delete is refused; a delete with a recovery window is accepted.
    code, status, msg, result = _call(
        lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )
    assert code == _DELETE_CODE, (
        f"DeleteSecret(ForceDeleteWithoutRecovery=True) on an RDS-managed secret must be refused "
        f"with {_DELETE_CODE}; got code={code!r} status={status!r} message={msg!r} "
        f"result={result!r}"
    )
    assert status == 400, f"the DeleteSecret refusal must be HTTP 400, got {status!r}"
    delete_msg = msg
    still = sm.describe_secret(SecretId=secret_arn)
    assert still.get("DeletedDate") is None, (
        f"the refused force delete scheduled a deletion anyway: DeletedDate={still['DeletedDate']!r}"
    )

    # --- (c) the owner's path: DeleteDBInstance removes the managed secret ----------------------
    _delete_instance(rds, inst_id)
    _poll_until(
        lambda: _instance(rds, inst_id),
        lambda i: i is None,
        timeout_s=1200, interval_s=20, description=f"DB instance {inst_id} to be deleted",
    )
    final_code, _, final_msg, _ = _poll_until(
        lambda: _call(lambda: sm.describe_secret(SecretId=secret_arn)),
        lambda r: r[0] != _ACCEPTED,
        timeout_s=600, interval_s=10,
        description="the managed secret to disappear after DeleteDBInstance",
    )
    assert final_code == _GONE_CODE, (
        f"after DeleteDBInstance the managed secret must be gone ({_GONE_CODE}); "
        f"DescribeSecret returned code {final_code!r}: {final_msg!r}"
    )
    # Every refusal's exact message, compared together so one run reports all of them.
    messages = {"DeleteSecret": delete_msg, "DescribeSecret": final_msg, "PutSecretValue": put_msg}
    expected = {"DeleteSecret": _DELETE_MSG, "DescribeSecret": _GONE_MSG, "PutSecretValue": _PUT_MSG}
    wrong = {op: (got, expected[op]) for op, got in messages.items() if got != expected[op]}
    assert (delete_msg, final_msg, put_msg) == (_DELETE_MSG, _GONE_MSG, _PUT_MSG), (
        f"refusal messages differ, as (got, expected): {wrong!r}"
    )


def _call(fn):
    """Call fn() once. Returns (code, http_status, message, result). On an unexpected SUCCESS the
    code is _ACCEPTED and result holds the response -- a value no error code can equal."""
    try:
        return _ACCEPTED, 200, "", fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message", ""), exc.response


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"waited {timeout_s}s for {description}; last saw {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _all_version_ids(sm, secret_id):
    ids = set()
    token = None
    while True:
        kwargs = {"SecretId": secret_id, "IncludeDeprecated": True}
        if token:
            kwargs["NextToken"] = token
        resp = sm.list_secret_version_ids(**kwargs)
        ids.update(v["VersionId"] for v in resp.get("Versions", []))
        token = resp.get("NextToken")
        if not token:
            return ids


def _network(ctx, ec2, rds):
    """A private VPC with two subnets in two DERIVED AZs and a DB subnet group -- never the
    ambient default VPC. Cleanups registered immediately after each create."""
    tag_spec = lambda kind: [{"ResourceType": kind, "Tags": _TAGS}]  # noqa: E731
    vpc_id = ec2.create_vpc(CidrBlock="10.81.0.0/16", TagSpecifications=tag_spec("vpc"))["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id),
                                         gone="InvalidVpcID.NotFound", what=f"vpc {vpc_id}"))
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z.get("ZoneType", "availability-zone") == "availability-zone"
    )
    assert len(zones) >= 2, f"a DB subnet group needs two AZs; {ctx.region} offers {zones!r}"
    subnets = []
    for i, zone in enumerate(zones[:2]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.81.{i}.0/24", AvailabilityZone=zone,
            TagSpecifications=tag_spec("subnet"),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _retry_delete(
            lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid), gone="InvalidSubnetID.NotFound",
            what=f"subnet {sid}"))
        subnets.append(sid)
    name = ctx.unique_name("sim2real-xsvc-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name, DBSubnetGroupDescription="sim2real xsvc kms/rds/sm check",
        SubnetIds=subnets, Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name),
        gone="DBSubnetGroupNotFoundFault", what=f"db subnet group {name}"))
    return name


def _retry_delete(fn, *, gone, what, timeout_s=600):
    """ctx.on_cleanup swallows exceptions, so a dependency still draining would leak silently."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == gone:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"could not delete {what}: {exc}") from exc
        time.sleep(15)


def _default_engine_version(rds, engine):
    versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
        "DBEngineVersions", []
    )
    assert versions, f"no default {engine!r} engine version is orderable in this region"
    return versions[0]["EngineVersion"]


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
    raise AssertionError(f"no small orderable class for {engine} {version}: {sorted(classes)!r}")


def _instance(rds, inst_id):
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return None
        raise


def _wait_instance_available(rds, inst_id, *, timeout_s=1080):
    inst = _poll_until(
        lambda: _instance(rds, inst_id),
        lambda i: i is None or i.get("DBInstanceStatus") in ("available", "failed"),
        timeout_s=timeout_s, interval_s=15, description=f"DB instance {inst_id} to be available",
    )
    assert inst is not None, f"DB instance {inst_id} vanished while waiting for 'available'"
    assert inst["DBInstanceStatus"] == "available", (
        f"DB instance {inst_id} ended in {inst['DBInstanceStatus']!r}, not 'available'"
    )
    return inst


def _delete_instance(rds, inst_id, *, wait_s=0, raise_on_leak=False):
    """Issue the delete (tolerating an instance already deleting), then optionally wait for it to
    be gone so the subnet group behind it can be deleted; a wait that runs out raises only with
    ``raise_on_leak``. RDS removes the managed secret itself."""
    deadline = time.monotonic() + 600
    while True:
        try:
            rds.delete_db_instance(
                DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DBInstanceNotFound":
                return
            inst = _instance(rds, inst_id)
            if inst is None:
                return
            if inst.get("DBInstanceStatus") == "deleting":
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f"could not delete DB instance {inst_id}: {exc}") from exc
            time.sleep(2)
    if wait_s:
        end = time.monotonic() + wait_s
        while _instance(rds, inst_id) is not None:
            if time.monotonic() >= end:
                if raise_on_leak:
                    raise RuntimeError(f"DB instance {inst_id} still present {wait_s}s after delete")
                return
            time.sleep(2)


def _schedule_key_deletion(kms, key_id):
    """7 days is the AWS minimum pending window; the key is reported as a leftover."""
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "KMSInvalidStateException":
            raise RuntimeError(f"schedule_key_deletion({key_id}) failed: {exc}") from exc


# Resources in the VPC delete asynchronously and leave ENIs behind, so network deletes wait for
# those ENIs and retry DependencyViolation within one bounded window shared by the check.
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
