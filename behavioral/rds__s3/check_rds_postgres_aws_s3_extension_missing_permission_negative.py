"""rds-postgres-aws-s3-extension-missing-permission-negative."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-postgres-aws-s3-extension-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:native", "plane:data")
def run(ctx) -> None:
    """aws_s3.table_import_from_s3 fails and imports nothing when the instance's role lacks s3:GetObject."""
    try:
        import psycopg  # noqa: F401
    except ImportError:
        raise AssertionError(
            "the psycopg driver is not available to drive the native PostgreSQL protocol for "
            "this check (the psql CLI fallback lives in the sibling positive-path check); "
            "install psycopg to close this gap"
        )
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _create_bucket(ctx)
    key = "imports/rows.csv"
    s3.put_object(Bucket=bucket, Key=key, Body=b"1,alpha\n2,beta\n3,gamma\n")

    # break exactly one thing: the role is associated but is granted only s3:ListBucket, not
    # s3:GetObject, so it can enumerate the bucket but can't read the object's bytes
    role_name, role_arn = _create_s3_import_role(ctx, bucket, actions=["s3:ListBucket"])
    sg_id = _create_db_security_group(ctx, 5432)
    instance = _create_postgres_instance(ctx, sg_id)
    _add_role_to_instance(ctx, instance["id"], role_arn)

    raised = False
    error_text = ""
    try:
        _postgres_import_from_s3(ctx, instance["host"], instance["port"], instance["password"], bucket, key)
    except psycopg.Error as exc:
        raised = True
        error_text = str(exc)
    assert raised, "table_import_from_s3 must fail when the role lacks s3:GetObject"
    lowered = error_text.lower()
    # Real RDS Postgres does not surface S3's own "access denied"/403 text through the aws_s3
    # extension; it wraps every unusable-credential case (missing permission included) in its
    # own message naming the feature association.
    assert "s3import" in lowered and "credentials" in lowered and "accessed" in lowered, (
        f"expected the aws_s3 credentials-inaccessible error naming the s3Import feature, got: {error_text!r}"
    )
    assert _row_count(ctx, instance["host"], instance["port"], instance["password"]) == 0, "no rows should have been imported"

    # positive control in the same file: widen the same role's policy to include s3:GetObject, retry
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=f"{role_name}-policy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "S3Import",
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )
    row_count = _import_with_retry(ctx, instance["host"], instance["port"], instance["password"], bucket, key)
    assert row_count == 3, f"positive control expected 3 rows imported, got {row_count}"


def _poll_until(probe, predicate, *, timeout_s=1200.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _empty_bucket(s3, name):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": objs})


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-pgimport-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # S3's CreateBucket rejects an explicit LocationConstraint for us-east-1 (its own
        # default region); this is a genuine API quirk, not a hardcoded target region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        _empty_bucket(s3, name)
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_s3_import_role(ctx, bucket_name, actions):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-pg-s3import-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statement = {
        "Sid": "S3Import",
        "Effect": "Allow",
        "Action": actions,
        "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
    }
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]})
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_name, role_arn


def _create_db_security_group(ctx, port):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to attach an ingress rule for the native DB round-trip")
    vpc_id = vpcs[0]["VpcId"]
    name = ctx.unique_name("sim2real-rds-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real rds behavioral test - temporary DB ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id, IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}]
    )
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return sg_id


def _create_postgres_instance(ctx, sg_id):
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-rds-pg-")
    password = f"Sim2Real{uuid.uuid4().hex[:12]}!"
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2real",
        MasterUserPassword=password,
        VpcSecurityGroupIds=[sg_id],
        PubliclyAccessible=True,
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(rds, DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True))
    inst = _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available",
        timeout_s=1200,
        interval_s=20,
    )
    return {
        "id": instance_id,
        "password": password,
        "host": inst["Endpoint"]["Address"],
        "port": inst["Endpoint"]["Port"],
    }


def _add_role_to_instance(ctx, instance_id, role_arn):
    rds = ctx.client("rds")
    # A just-created IAM role can lag briefly before RDS can assume it; retry the
    # association itself instead of sleeping a guessed duration up front.
    deadline = time.monotonic() + 120.0
    while True:
        try:
            rds.add_role_to_db_instance(DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName="s3Import")
            break
        except ClientError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"add_role_to_db_instance did not succeed within 120s of role creation "
                    f"(IAM propagation); last error: {exc}"
                ) from exc
            time.sleep(2)
    ctx.on_cleanup(lambda: rds.remove_role_from_db_instance(DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName="s3Import"))
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0],
        lambda i: any(r["RoleArn"] == role_arn and r["Status"] == "ACTIVE" for r in i.get("AssociatedRoles", [])),
        timeout_s=300,
        interval_s=10,
    )


def _postgres_import_from_s3(ctx, host, port, password, bucket, key):
    import psycopg  # type: ignore

    host_dial, port_dial = ctx.endpoint_host(host, int(port))
    conn = psycopg.connect(host=host_dial, port=port_dial, user="sim2real", password=password, dbname="postgres", connect_timeout=30, cursor_factory=psycopg.ClientCursor)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS aws_s3 CASCADE")
            cur.execute("CREATE TABLE IF NOT EXISTS t1 (id INT, val TEXT)")
            cur.execute(
                "SELECT aws_s3.table_import_from_s3(%s, %s, %s, %s, %s, %s)",
                ("t1", "", "(format csv)", bucket, key, ctx.region),
            )
            cur.execute("SELECT COUNT(*) FROM t1")
            return cur.fetchone()[0]
    finally:
        conn.close()


def _import_with_retry(ctx, host, port, password, bucket, key, timeout_s=120.0, interval_s=10.0):
    import psycopg  # type: ignore

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return _postgres_import_from_s3(ctx, host, port, password, bucket, key)
        except psycopg.Error as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"table_import_from_s3 did not succeed within {timeout_s}s after granting s3:GetObject "
        f"(IAM policy propagation); last error: {last_exc!r}"
    )


def _row_count(ctx, host, port, password):
    import psycopg  # type: ignore

    host_dial, port_dial = ctx.endpoint_host(host, int(port))
    conn = psycopg.connect(host=host_dial, port=port_dial, user="sim2real", password=password, dbname="postgres", connect_timeout=30, cursor_factory=psycopg.ClientCursor)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS t1 (id INT, val TEXT)")
            cur.execute("SELECT COUNT(*) FROM t1")
            return cur.fetchone()[0]
    finally:
        conn.close()


def _delete_instance_and_wait(rds, **kwargs) -> None:
    """Delete a DB instance and wait until it is gone, so the teardowns after it succeed."""
    rds.delete_db_instance(**kwargs)
    rds.get_waiter("db_instance_deleted").wait(
        DBInstanceIdentifier=kwargs["DBInstanceIdentifier"], WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
