"""deploy-cfn-rds-lambda-secretsmanager-stack-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-rds-lambda-secretsmanager-stack-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack's Aurora Serverless v2 cluster with an RDS-managed secret serves its Lambda function
    over the Data API: CREATE TABLE and an INSERT of one row succeed, and SELECT returns
    'hello-sim2real'."""
    net = _default_vpc_network(ctx)
    stack = _deploy_cfn(
        ctx,
        json.dumps(_template()),
        parameters={
            "SubnetIds": ",".join(net["subnet_ids"]),
            "VpcSecurityGroupId": net["sg_id"],
        },
        timeout_s=1200,
    )
    outputs = stack["outputs"]
    lam = ctx.client("lambda")
    table = _sql_ident(ctx.unique_name("sim2real_xsvc_t"))

    def _invoke(sql: str, parameters: list | None = None) -> dict[str, Any]:
        payload = {"sql": sql, "parameters": parameters or []}
        resp = lam.invoke(FunctionName=outputs["FunctionName"], Payload=json.dumps(payload).encode())
        assert "FunctionError" not in resp, f"lambda invocation raised: {resp}"
        return json.loads(resp["Payload"].read())

    # The cluster is already "available" by CREATE_COMPLETE, but the very first Data API call
    # can still transiently fail while the HTTP endpoint finishes activating; poll for readiness.
    create = _poll_until(
        lambda: _invoke(f"CREATE TABLE IF NOT EXISTS {table} (id int PRIMARY KEY, val text)"),
        lambda r: r.get("ok") is True,
        timeout_s=180,
        interval_s=5.0,
        description="Data API CREATE TABLE via deployed Lambda",
    )
    assert create["ok"] is True, f"CREATE TABLE via Data API did not report ok: {create!r}"

    insert = _invoke(f"INSERT INTO {table} (id, val) VALUES (1, 'hello-sim2real')")
    assert insert["ok"] is True, insert
    assert insert["numberOfRecordsUpdated"] == 1, (
        f"expected exactly 1 row inserted, Data API reported {insert.get('numberOfRecordsUpdated')!r}"
    )

    select = _invoke(f"SELECT val FROM {table} WHERE id = 1")
    assert select["ok"] is True, select
    records = select["records"]
    assert len(records) == 1, f"expected exactly 1 row back for id=1, got {len(records)}: {records!r}"
    assert records[0][0]["stringValue"] == "hello-sim2real", (
        f"expected the inserted value to round-trip, Data API returned {records[0][0]!r}"
    )


def _template() -> dict[str, Any]:
    lambda_code = (
        "import json\n"
        "import os\n"
        "import boto3\n"
        "\n"
        "_client = boto3.client('rds-data')\n"
        "\n"
        "\n"
        "def handler(event, context):\n"
        "    sql = event.get('sql', '')\n"
        "    parameters = event.get('parameters', [])\n"
        "    try:\n"
        "        resp = _client.execute_statement(\n"
        "            resourceArn=os.environ['CLUSTER_ARN'],\n"
        "            secretArn=os.environ['SECRET_ARN'],\n"
        "            database=os.environ.get('DB_NAME', 'postgres'),\n"
        "            sql=sql,\n"
        "            parameters=parameters,\n"
        "        )\n"
        "        return {\n"
        "            'ok': True,\n"
        "            'records': resp.get('records', []),\n"
        "            'numberOfRecordsUpdated': resp.get('numberOfRecordsUpdated'),\n"
        "        }\n"
        "    except Exception as exc:\n"
        "        code = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)\n"
        "        return {'ok': False, 'errorCode': code, 'errorMessage': str(exc)}\n"
    )
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "SubnetIds": {"Type": "CommaDelimitedList"},
            "VpcSecurityGroupId": {"Type": "String"},
        },
        "Resources": {
            "DBSubnetGroup": {
                "Type": "AWS::RDS::DBSubnetGroup",
                "Properties": {
                    "DBSubnetGroupDescription": "sim2real xsvc subnet group",
                    "SubnetIds": {"Ref": "SubnetIds"},
                },
            },
            "DBCluster": {
                "Type": "AWS::RDS::DBCluster",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "Engine": "aurora-postgresql",
                    "DBClusterIdentifier": {"Fn::Sub": "${AWS::StackName}-c"},
                    "MasterUsername": "dbadmin",
                    "ManageMasterUserPassword": True,
                    "EnableHttpEndpoint": True,
                    "DBSubnetGroupName": {"Ref": "DBSubnetGroup"},
                    "VpcSecurityGroupIds": [{"Ref": "VpcSecurityGroupId"}],
                    "ServerlessV2ScalingConfiguration": {"MinCapacity": 0.5, "MaxCapacity": 2},
                    "StorageEncrypted": True,
                    "DeletionProtection": False,
                    "BackupRetentionPeriod": 1,
                },
            },
            "DBInstance": {
                "Type": "AWS::RDS::DBInstance",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "DBInstanceIdentifier": {"Fn::Sub": "${AWS::StackName}-i"},
                    "Engine": "aurora-postgresql",
                    "DBInstanceClass": "db.serverless",
                    "DBClusterIdentifier": {"Ref": "DBCluster"},
                    "PubliclyAccessible": False,
                },
            },
            "LambdaExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "DataApiAccess",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "rds-data:ExecuteStatement",
                                            "rds-data:BatchExecuteStatement",
                                        ],
                                        "Resource": {"Fn::GetAtt": ["DBCluster", "DBClusterArn"]},
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": "secretsmanager:GetSecretValue",
                                        "Resource": {
                                            "Fn::GetAtt": ["DBCluster", "MasterUserSecret.SecretArn"]
                                        },
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "LambdaFunction": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["DBInstance"],
                "Properties": {
                    "FunctionName": {"Fn::Sub": "${AWS::StackName}-fn"},
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecutionRole", "Arn"]},
                    "Timeout": 30,
                    "MemorySize": 256,
                    "Environment": {
                        "Variables": {
                            "CLUSTER_ARN": {"Fn::GetAtt": ["DBCluster", "DBClusterArn"]},
                            "SECRET_ARN": {"Fn::GetAtt": ["DBCluster", "MasterUserSecret.SecretArn"]},
                            "DB_NAME": "postgres",
                        }
                    },
                    "Code": {"ZipFile": lambda_code},
                },
            },
        },
        "Outputs": {
            "ClusterArn": {"Value": {"Fn::GetAtt": ["DBCluster", "DBClusterArn"]}},
            "SecretArn": {"Value": {"Fn::GetAtt": ["DBCluster", "MasterUserSecret.SecretArn"]}},
            "FunctionName": {"Value": {"Ref": "LambdaFunction"}},
        },
    }


def _sql_ident(name: str) -> str:
    return name.replace("-", "_")


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


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
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=1200,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


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
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _default_vpc_network(ctx) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError(
            "account/region has fewer than 2 availability zones with subnets, which an RDS "
            "DB subnet group requires"
        )
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("VPC has no default security group to attach to the RDS cluster")
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids[:3], "sg_id": sgs[0]["GroupId"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
