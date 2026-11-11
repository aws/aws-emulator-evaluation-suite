"""deploy-cfn-rds-instance-with-s3-import-role-positive."""
from __future__ import annotations

import secrets
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "deploy-cfn-rds-instance-with-s3-import-role-positive"
GROUP = "deployment-order"
SERVICES = ["rds", "s3"]

_DB_PASSWORD = "S2r" + secrets.token_urlsafe(18)
_DB_USER = "admin"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed Aurora MySQL cluster with an associated IAM role and an aws_default_s3_role
    cluster parameter runs a real `LOAD DATA FROM S3` over the MySQL wire protocol and sees the
    imported rows, proving the stack wires RDS to S3 end to end."""
    sql_driver = _detect_sql_driver(ctx)
    if sql_driver is None:
        raise RequiredToolMissing(['pymysql', 'mysql'])

    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account has no shared network VPC to place a publicly-accessible Aurora cluster in")
    vpc_id = vpcs[0]["VpcId"]

    engine_info = rds.describe_db_engine_versions(Engine="aurora-mysql", DefaultOnly=True)["DBEngineVersions"][0]
    param_family = engine_info["DBParameterGroupFamily"]

    cluster_id = _xname(ctx, "auc")
    bucket_logical, role_logical = "ImportBucket", "ImportRole"
    sg_logical, param_group_logical = "ImportSg", "ImportParamGroup"
    cluster_logical, instance_logical = "ImportCluster", "ImportInstance"

    template = _template(
        vpc_id=vpc_id,
        param_family=param_family,
        cluster_id=cluster_id,
        bucket_logical=bucket_logical,
        role_logical=role_logical,
        sg_logical=sg_logical,
        param_group_logical=param_group_logical,
        cluster_logical=cluster_logical,
        instance_logical=instance_logical, ctx=ctx
    )
    result = _deploy_cfn(ctx, json.dumps(template), timeout_s=1800.0)
    outputs = result["outputs"]
    bucket_name = outputs["BucketName"]
    endpoint, port = ctx.endpoint_host(outputs["ClusterEndpoint"], int(outputs["ClusterPort"]))

    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket_name))

    key = "import/data.csv"
    s3.put_object(Bucket=bucket_name, Key=key, Body=b"1,hello\n2,world\n")

    database = "s3_import_check_db"
    table = "s3_import_check"
    conn = sql_driver.connect(endpoint, port)
    try:
        sql_driver.execute(conn, f"CREATE DATABASE {database}")
        sql_driver.execute(conn, f"CREATE TABLE {database}.{table} (id INT, val VARCHAR(50))")
        sql_driver.execute(
            conn,
            f"LOAD DATA FROM S3 's3://{bucket_name}/{key}' INTO TABLE {database}.{table} "
            "FIELDS TERMINATED BY ',' LINES TERMINATED BY '\\n'",
        )
        rows = sql_driver.query(conn, f"SELECT id, val FROM {database}.{table} ORDER BY id")
    finally:
        sql_driver.close(conn)

    assert rows == [("1", "hello"), ("2", "world")] or rows == [(1, "hello"), (2, "world")], (
        f"LOAD DATA FROM S3 did not import the expected rows, got {rows!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _empty_bucket(s3, bucket_name: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


class _PyMySQLDriver:
    """Thin ctx-free wrapper so both driver backends share one call shape."""

    def __init__(self, pymysql_module):
        self._pymysql = pymysql_module

    def connect(self, endpoint: str, port: int):
        return self._pymysql.connect(
            host=endpoint, port=port, user=_DB_USER, password=_DB_PASSWORD,
            connect_timeout=20,
        )

    def execute(self, conn, sql: str) -> None:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()

    def query(self, conn, sql: str):
        with conn.cursor() as cur:
            cur.execute(sql)
            return list(cur.fetchall())

    def close(self, conn) -> None:
        conn.close()


class _CliMySQLDriver:
    """Fallback using the `mysql` CLI binary when pymysql isn't installed."""

    def connect(self, endpoint: str, port: int):
        return endpoint, port  # the CLI is stateless per-invocation; "connection" is the address

    def _run(self, conn, sql: str) -> str:
        endpoint, port = conn
        cmd = [
            "mysql", "-h", endpoint, "-P", str(port), "-u", _DB_USER,
            f"-p{_DB_PASSWORD}", "-N", "-B", "-e", sql,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            raise AssertionError(f"mysql CLI failed: {proc.stderr[-500:]}")
        return proc.stdout

    def execute(self, conn, sql: str) -> None:
        self._run(conn, sql)

    def query(self, conn, sql: str):
        out = self._run(conn, sql)
        rows = []
        for line in out.strip().splitlines():
            if not line:
                continue
            rows.append(tuple(line.split("\t")))
        return rows

    def close(self, conn) -> None:
        pass


def _detect_sql_driver(ctx):
    try:
        import pymysql  # type: ignore

        return _PyMySQLDriver(pymysql)
    except ImportError:
        pass
    if shutil.which("mysql", path=ctx.subprocess_env().get("PATH")):
        return _CliMySQLDriver()
    return None


def _template(*, vpc_id, param_family, cluster_id, bucket_logical, role_logical, sg_logical, param_group_logical, cluster_logical, instance_logical, ctx) -> dict:
    subnet_group = _network_db_subnet_group(ctx, ctx.client('rds'))
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            bucket_logical: {"Type": "AWS::S3::Bucket"},
            role_logical: {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "S3ImportPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                                        "Resource": {"Fn::Sub": "arn:aws:s3:::${" + bucket_logical + "}"},
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject"],
                                        "Resource": {"Fn::Sub": "arn:aws:s3:::${" + bucket_logical + "}/*"},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            sg_logical: {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real Aurora S3-import test access",
                    "VpcId": vpc_id,
                    "SecurityGroupIngress": [
                        {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306, "CidrIp": c}
                        for c in ctx.ingress_cidrs()
                    ],
                },
            },
            param_group_logical: {
                "Type": "AWS::RDS::DBClusterParameterGroup",
                "Properties": {
                    "Description": "sim2real aws_default_s3_role",
                    "Family": param_family,
                    "Parameters": {"aws_default_s3_role": {"Fn::GetAtt": [role_logical, "Arn"]}},
                },
            },
            cluster_logical: {
                "Type": "AWS::RDS::DBCluster",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "DBClusterIdentifier": cluster_id,
                    "Engine": "aurora-mysql",
                    "MasterUsername": _DB_USER,
                    "MasterUserPassword": _DB_PASSWORD,
                    "VpcSecurityGroupIds": [{"Ref": sg_logical}],
                    "DBClusterParameterGroupName": {"Ref": param_group_logical},
                    "AssociatedRoles": [{"RoleArn": {"Fn::GetAtt": [role_logical, "Arn"]}}],
                    "BackupRetentionPeriod": 1,
                    "DBSubnetGroupName": subnet_group,
                },
            },
            instance_logical: {
                "Type": "AWS::RDS::DBInstance",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "Engine": "aurora-mysql",
                    "DBClusterIdentifier": {"Ref": cluster_logical},
                    "DBInstanceClass": "db.t3.medium",
                    "PubliclyAccessible": True,
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": bucket_logical}},
            "ClusterEndpoint": {"Value": {"Fn::GetAtt": [cluster_logical, "Endpoint.Address"]}},
            "ClusterPort": {"Value": {"Fn::GetAtt": [cluster_logical, "Endpoint.Port"]}},
        },
    }


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


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
        timeout_s=900,
        interval_s=15.0,
        description=f"delete stack {stack_name}",
    )


def _failed_resource_reasons(cfn, stack_name: str) -> str:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    failed = [
        f"{e['LogicalResourceId']}({e['ResourceType']}): {e.get('ResourceStatusReason', 'no reason given')}"
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    return "; ".join(failed) if failed else "no failed resource events found"


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=15.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(
            f"Stack {name} ended in {stack['StackStatus']}: {_failed_resource_reasons(cfn, name)}"
        )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


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
