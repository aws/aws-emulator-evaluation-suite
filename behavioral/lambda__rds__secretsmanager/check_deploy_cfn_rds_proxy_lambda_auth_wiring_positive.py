"""deploy-cfn-rds-proxy-lambda-auth-wiring-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-rds-proxy-lambda-auth-wiring-positive"
GROUP = "resource-binding"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack's RDS Proxy authenticates with the cluster's RDS-managed secret (AuthScheme SECRETS),
    its targets are the cluster and an AVAILABLE instance, and a Lambda reading the same secret
    gets 'dbadmin'."""
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
    rds = ctx.client("rds")

    proxy = rds.describe_db_proxies(DBProxyName=outputs["DBProxyName"])["DBProxies"][0]
    auth = proxy["Auth"][0]
    assert auth["SecretArn"] == outputs["SecretArn"], (
        f"proxy auth SecretArn {auth['SecretArn']!r} != cluster's RDS-managed secret "
        f"{outputs['SecretArn']!r}"
    )
    assert auth["AuthScheme"] == "SECRETS", f"expected AuthScheme SECRETS, got {auth['AuthScheme']!r}"

    # A cluster-tracking target group reports two distinct Targets entries: a TRACKED_CLUSTER
    # pseudo-target (binds the group to the cluster, never carries TargetHealth) and the
    # underlying RDS_INSTANCE target (carries the real health state machine, REGISTERING ->
    # UNAVAILABLE -> AVAILABLE). Health lives on the instance entry, not index 0.
    targets = _poll_until(
        lambda: rds.describe_db_proxy_targets(DBProxyName=outputs["DBProxyName"])["Targets"],
        lambda ts: any(
            t.get("Type") == "RDS_INSTANCE" and t.get("TargetHealth", {}).get("State") == "AVAILABLE"
            for t in ts
        ),
        timeout_s=600,
        interval_s=10.0,
        description="RDS Proxy target reaching AVAILABLE health",
    )
    by_type = {t["Type"]: t for t in targets}
    assert "TRACKED_CLUSTER" in by_type, f"no TRACKED_CLUSTER entry in proxy targets {targets!r}"
    assert "RDS_INSTANCE" in by_type, f"no RDS_INSTANCE entry in proxy targets {targets!r}"
    cluster_target = by_type["TRACKED_CLUSTER"]
    instance_target = by_type["RDS_INSTANCE"]
    assert cluster_target["RdsResourceId"] == outputs["ClusterIdentifier"], (
        f"proxy target RdsResourceId {cluster_target['RdsResourceId']!r} != deployed cluster "
        f"{outputs['ClusterIdentifier']!r}"
    )
    assert instance_target["TargetHealth"]["State"] == "AVAILABLE", (
        f"expected RDS_INSTANCE target health AVAILABLE, got {instance_target['TargetHealth']!r}"
    )

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=outputs["FunctionName"])
    assert "FunctionError" not in resp, resp
    body = json.loads(resp["Payload"].read())
    assert body["username"] == "dbadmin", (
        f"Lambda-retrieved secret username {body['username']!r} != cluster MasterUsername 'dbadmin'"
    )


def _template() -> dict[str, Any]:
    lambda_code = (
        "import json\n"
        "import os\n"
        "import boto3\n"
        "\n"
        "_sm = boto3.client('secretsmanager')\n"
        "\n"
        "\n"
        "def handler(event, context):\n"
        "    secret = _sm.get_secret_value(SecretId=os.environ['SECRET_ARN'])\n"
        "    data = json.loads(secret['SecretString'])\n"
        "    return {'username': data['username']}\n"
    )
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "SubnetIds": {"Type": "CommaDelimitedList"},
            "VpcSecurityGroupId": {"Type": "String"},
        },
        "Resources": {
            "SelfIngress": {
                "Type": "AWS::EC2::SecurityGroupIngress",
                "Properties": {
                    "GroupId": {"Ref": "VpcSecurityGroupId"},
                    "SourceSecurityGroupId": {"Ref": "VpcSecurityGroupId"},
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                },
            },
            "DBSubnetGroup": {
                "Type": "AWS::RDS::DBSubnetGroup",
                "Properties": {
                    "DBSubnetGroupDescription": "sim2real xsvc proxy subnet group",
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
            "ProxyRole": {
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
                            "PolicyName": "ProxySecretAccess",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "secretsmanager:GetSecretValue",
                                        "Resource": {
                                            "Fn::GetAtt": ["DBCluster", "MasterUserSecret.SecretArn"]
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "DBProxy": {
                "Type": "AWS::RDS::DBProxy",
                "DependsOn": ["DBInstance", "SelfIngress"],
                "Properties": {
                    "DBProxyName": {"Fn::Sub": "${AWS::StackName}-proxy"},
                    "EngineFamily": "POSTGRESQL",
                    "RoleArn": {"Fn::GetAtt": ["ProxyRole", "Arn"]},
                    "VpcSubnetIds": {"Ref": "SubnetIds"},
                    "VpcSecurityGroupIds": [{"Ref": "VpcSecurityGroupId"}],
                    "RequireTLS": False,
                    "Auth": [
                        {
                            "AuthScheme": "SECRETS",
                            "IAMAuth": "DISABLED",
                            "SecretArn": {"Fn::GetAtt": ["DBCluster", "MasterUserSecret.SecretArn"]},
                        }
                    ],
                },
            },
            "DBProxyTargetGroup": {
                "Type": "AWS::RDS::DBProxyTargetGroup",
                "DependsOn": ["DBInstance"],
                "Properties": {
                    "DBProxyName": {"Ref": "DBProxy"},
                    "TargetGroupName": "default",
                    "DBClusterIdentifiers": [{"Ref": "DBCluster"}],
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
                            "PolicyName": "SecretReadAccess",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "secretsmanager:GetSecretValue",
                                        "Resource": {
                                            "Fn::GetAtt": ["DBCluster", "MasterUserSecret.SecretArn"]
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "LambdaFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": {"Fn::Sub": "${AWS::StackName}-fn"},
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecutionRole", "Arn"]},
                    "Timeout": 15,
                    "Environment": {
                        "Variables": {
                            "SECRET_ARN": {"Fn::GetAtt": ["DBCluster", "MasterUserSecret.SecretArn"]}
                        }
                    },
                    "Code": {"ZipFile": lambda_code},
                },
            },
        },
        "Outputs": {
            "DBProxyName": {"Value": {"Ref": "DBProxy"}},
            "ClusterIdentifier": {"Value": {"Ref": "DBCluster"}},
            "SecretArn": {"Value": {"Fn::GetAtt": ["DBCluster", "MasterUserSecret.SecretArn"]}},
            "FunctionName": {"Value": {"Ref": "LambdaFunction"}},
        },
    }


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
            "DB subnet group and RDS Proxy both require"
        )
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("VPC has no default security group to attach to the RDS cluster/proxy")
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids[:3], "sg_id": sgs[0]["GroupId"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
