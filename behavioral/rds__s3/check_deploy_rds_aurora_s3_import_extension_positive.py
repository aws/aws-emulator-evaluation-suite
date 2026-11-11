"""deploy-rds-aurora-s3-import-extension-positive."""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-rds-aurora-s3-import-extension-positive"
GROUP = "deployment-order"
SERVICES = ["rds", "s3"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """An Aurora PostgreSQL cluster deployed with an s3Import-associated IAM role lets
    aws_s3.table_import_from_s3 read a real object out of the deployed S3 bucket over the
    native PostgreSQL wire protocol."""
    driver = None
    _using_psql = False
    try:
        import psycopg as driver  # noqa: N813
    except ImportError:
        try:
            import pg8000.native as driver  # noqa: N813
        except ImportError:
            if shutil.which("psql") is not None:
                _using_psql = True
            else:
                raise AssertionError(
                    "no PostgreSQL client driver (psycopg, pg8000) or the psql binary is available in "
                    "this environment; cannot open the native PostgreSQL connection needed to exercise "
                    "aws_s3.table_import_from_s3."
                )
    _using_pg8000 = driver is not None and driver.__name__.startswith("pg8000")

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region to attach a publicly reachable Aurora cluster"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    azs = {s["AvailabilityZone"] for s in subnets}
    if len(azs) < 2:
        raise AssertionError(
            "shared network VPC does not span >=2 AZs; cannot create an RDS DB subnet group"
        )
    subnet_ids = []
    seen_az = set()
    for s in subnets:
        if s["AvailabilityZone"] not in seen_az:
            subnet_ids.append(s["SubnetId"])
            seen_az.add(s["AvailabilityZone"])

    s3 = ctx.client("s3")
    ctx.client("rds")

    cluster_id = _xname(ctx, "aur")
    template = _build_import_stack_template(vpc_id, subnet_ids, cluster_id, ctx.ingress_cidrs())
    password = secrets.token_urlsafe(12)
    stack = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters={"MasterUsername": "dbadmin", "MasterUserPassword": password},
        timeout_s=1500,
    )
    outputs = stack["outputs"]
    bucket = outputs["BucketName"]
    endpoint = outputs["ClusterEndpointAddress"]
    port = int(outputs["ClusterPort"])
    endpoint, port = ctx.endpoint_host(endpoint, port)
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    rows = [(1, "alpha", 10), (2, "beta", 20), (3, "gamma", 30)]
    csv_body = "\n".join(f"{i},{name},{val}" for i, name, val in rows) + "\n"
    key = "import/rows.csv"
    s3.put_object(Bucket=bucket, Key=key, Body=csv_body.encode())

    if _using_psql:
        imported = _import_via_psql(
            ctx, endpoint, port, password, bucket, key, ctx.region
        )
    else:
        imported = _import_via_driver(
            ctx,
            driver,
            _using_pg8000,
            endpoint,
            port,
            password,
            bucket,
            key,
            ctx.region,
        )

    assert imported == rows, (
        f"aws_s3.table_import_from_s3 imported {imported!r}, expected {rows!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=1500,
        interval_s=15.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _import_via_driver(
    ctx,
    driver,
    using_pg8000: bool,
    endpoint: str,
    port: int,
    password: str,
    bucket: str,
    key: str,
    region: str,
) -> list[tuple]:
    def _connect():
        try:
            if using_pg8000:
                return driver.Connection(
                    user="dbadmin",
                    password=password,
                    host=endpoint,
                    port=port,
                    database="postgres",
                    timeout=5,
                )
            return driver.connect(
                host=endpoint,
                port=port,
                dbname="postgres",
                user="dbadmin",
                password=password,
                connect_timeout=5,
                cursor_factory=driver.ClientCursor,
            )
        except Exception:
            return None

    conn = _poll_until(
        _connect,
        lambda c: c is not None,
        timeout_s=300.0,
        interval_s=10.0,
        description="db connect to Aurora endpoint",
    )
    ctx.on_cleanup(conn.close)
    try:
        if using_pg8000:
            conn.run("CREATE EXTENSION IF NOT EXISTS aws_s3 CASCADE;")
            conn.run("CREATE TABLE import_test (id int, name text, val int);")
            conn.run(
                "SELECT aws_s3.table_import_from_s3("
                "'import_test', '', '(format csv)', aws_commons.create_s3_uri(:b, :k, :r));",
                b=bucket,
                k=key,
                r=region,
            )
            return [
                tuple(row)
                for row in conn.run(
                    "SELECT id, name, val FROM import_test ORDER BY id;"
                )
            ]
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("CREATE EXTENSION IF NOT EXISTS aws_s3 CASCADE;")
        cur.execute("CREATE TABLE import_test (id int, name text, val int);")
        cur.execute(
            "SELECT aws_s3.table_import_from_s3("
            "'import_test', '', '(format csv)', aws_commons.create_s3_uri(%s, %s, %s));",
            (bucket, key, region),
        )
        cur.execute("SELECT id, name, val FROM import_test ORDER BY id;")
        return cur.fetchall()
    finally:
        conn.close()


def _import_via_psql(
    ctx, endpoint: str, port: int, password: str, bucket: str, key: str, region: str
) -> list[tuple]:
    psql_bin = shutil.which("psql")
    env = dict(ctx.subprocess_env())
    env["PGPASSWORD"] = password

    def _probe() -> bool:
        result = subprocess.run(
            [
                psql_bin,
                "-h",
                endpoint,
                "-p",
                str(port),
                "-U",
                "dbadmin",
                "-d",
                "postgres",
                "-c",
                "SELECT 1;",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0

    _poll_until(
        _probe,
        lambda ok: ok,
        timeout_s=300.0,
        interval_s=10.0,
        description="db connect to Aurora endpoint",
    )

    sql = (
        "CREATE EXTENSION IF NOT EXISTS aws_s3 CASCADE;"
        "CREATE TABLE import_test (id int, name text, val int);"
        f"SELECT aws_s3.table_import_from_s3('import_test', '', '(format csv)', "
        f"aws_commons.create_s3_uri('{bucket}', '{key}', '{region}'));"
        "SELECT id, name, val FROM import_test ORDER BY id;"
    )
    result = subprocess.run(
        [
            psql_bin,
            "-h",
            endpoint,
            "-p",
            str(port),
            "-U",
            "dbadmin",
            "-d",
            "postgres",
            "-t",
            "-A",
            "-F",
            ",",
            "-c",
            sql,
        ],
        text=True,
        check=True,
        capture_output=True,
        env=env,
        timeout=60,
    )
    # CREATE EXTENSION / CREATE TABLE emit no rows in -t mode; the aws_s3 import summary row has 5
    # fields, so the 3-field lines are unambiguously the final SELECT id, name, val.
    candidate_rows = [
        ln.split(",") for ln in result.stdout.strip().splitlines() if ln.count(",") == 2
    ]
    return [(int(a), b, int(c)) for a, b, c in candidate_rows]


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _build_import_stack_template(
    vpc_id: str, subnet_ids: list[str], cluster_id: str, ingress_cidrs: list[str]
) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "MasterUsername": {"Type": "String", "NoEcho": True},
            "MasterUserPassword": {"Type": "String", "NoEcho": True, "MinLength": 8},
        },
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "DeletionPolicy": "Delete"},
            "ImportRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "rds.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "S3ImportAccess",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject", "s3:ListBucket"],
                                        "Resource": [
                                            {"Fn::GetAtt": ["Bucket", "Arn"]},
                                            {"Fn::Sub": "${Bucket.Arn}/*"},
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "DbSubnetGroup": {
                "Type": "AWS::RDS::DBSubnetGroup",
                "Properties": {
                    "DBSubnetGroupDescription": "sim2real aurora s3 import subnet group",
                    "SubnetIds": subnet_ids,
                },
            },
            "DbSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real aurora s3 import test SG",
                    "VpcId": vpc_id,
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 5432,
                            "ToPort": 5432,
                            "CidrIp": c,
                        }
                        for c in ingress_cidrs
                    ],
                },
            },
            "DbCluster": {
                "Type": "AWS::RDS::DBCluster",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "DBClusterIdentifier": cluster_id,
                    "Engine": "aurora-postgresql",
                    "MasterUsername": {"Ref": "MasterUsername"},
                    "MasterUserPassword": {"Ref": "MasterUserPassword"},
                    "DBSubnetGroupName": {"Ref": "DbSubnetGroup"},
                    "VpcSecurityGroupIds": [{"Ref": "DbSecurityGroup"}],
                    "BackupRetentionPeriod": 1,
                    "AssociatedRoles": [
                        {
                            "RoleArn": {"Fn::GetAtt": ["ImportRole", "Arn"]},
                            "FeatureName": "s3Import",
                        }
                    ],
                },
            },
            "DbInstance": {
                "Type": "AWS::RDS::DBInstance",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "DBClusterIdentifier": {"Ref": "DbCluster"},
                    "Engine": "aurora-postgresql",
                    "DBInstanceClass": "db.t3.medium",
                    "PubliclyAccessible": True,
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "Bucket"}},
            "ImportRoleArn": {"Value": {"Fn::GetAtt": ["ImportRole", "Arn"]}},
            "ClusterEndpointAddress": {
                "Value": {"Fn::GetAtt": ["DbCluster", "Endpoint.Address"]}
            },
            "ClusterPort": {"Value": {"Fn::GetAtt": ["DbCluster", "Endpoint.Port"]}},
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
