"""deploy-db-cluster-cfn-parameter-group-enforcement."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-db-cluster-cfn-parameter-group-enforcement"
GROUP = "deploy"
SERVICES = ["rds"]

_PARAM_NAME = "statement_timeout"
_PARAM_VALUE = "60000"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-rds-cfn"},
]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed Aurora PostgreSQL cluster names the stack's DBClusterParameterGroup,
    and that group reports statement_timeout=60000 with Source=user; the running engine's value is
    not read."""
    rds = ctx.client("rds")
    vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    subnet_ids = [s["SubnetId"] for s in az_subnets]

    versions = rds.describe_db_engine_versions(Engine="aurora-postgresql", DefaultOnly=True)[
        "DBEngineVersions"
    ]
    if not versions:
        raise AssertionError(
            "no default aurora-postgresql engine version available in this account/region"
        )
    engine_version = versions[0]["EngineVersion"]
    family = versions[0]["DBParameterGroupFamily"]

    user = "s2radmin"
    password = _master_password()

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
            "MasterUsername": {"Type": "String", "NoEcho": True},
            "MasterPassword": {"Type": "String", "NoEcho": True},
        },
        "Resources": {
            "DBSubnetGroup": {
                "Type": "AWS::RDS::DBSubnetGroup",
                "Properties": {
                    "DBSubnetGroupDescription": "sim2real behavioral cluster parameter group test",
                    "SubnetIds": {"Ref": "SubnetIds"},
                    "Tags": _MANAGED_TAGS,
                },
            },
            "DBClusterParameterGroup": {
                "Type": "AWS::RDS::DBClusterParameterGroup",
                "Properties": {
                    "Description": "sim2real behavioral test cluster parameter group",
                    "Family": family,
                    "Parameters": {_PARAM_NAME: _PARAM_VALUE},
                    "Tags": _MANAGED_TAGS,
                },
            },
            "DBCluster": {
                "Type": "AWS::RDS::DBCluster",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "Engine": "aurora-postgresql",
                    "EngineVersion": engine_version,
                    "MasterUsername": {"Ref": "MasterUsername"},
                    "MasterUserPassword": {"Ref": "MasterPassword"},
                    "DBClusterParameterGroupName": {"Ref": "DBClusterParameterGroup"},
                    "DBSubnetGroupName": {"Ref": "DBSubnetGroup"},
                    "BackupRetentionPeriod": 1,
                    "Tags": _MANAGED_TAGS,
                },
            },
            "DBInstance": {
                "Type": "AWS::RDS::DBInstance",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "Engine": "aurora-postgresql",
                    "DBInstanceClass": "db.t4g.medium",
                    "DBClusterIdentifier": {"Ref": "DBCluster"},
                    "DBSubnetGroupName": {"Ref": "DBSubnetGroup"},
                    "Tags": _MANAGED_TAGS,
                },
            },
        },
        "Outputs": {
            "DBClusterIdentifier": {"Value": {"Ref": "DBCluster"}},
            "DBClusterParameterGroupName": {"Value": {"Ref": "DBClusterParameterGroup"}},
        },
    }

    outputs = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters=[
            {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(subnet_ids)},
            {"ParameterKey": "MasterUsername", "ParameterValue": user},
            {"ParameterKey": "MasterPassword", "ParameterValue": password},
        ],
        timeout_s=2700,
    )

    cluster_id = outputs["DBClusterIdentifier"]
    pg_name = outputs["DBClusterParameterGroupName"]

    cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert cluster["Status"] == "available", f"expected available cluster, got {cluster['Status']!r}"
    assert cluster["DBClusterParameterGroup"] == pg_name, (
        "running cluster is not actually associated with the CFN-created parameter group: "
        f"{cluster['DBClusterParameterGroup']!r} != {pg_name!r}"
    )

    # describe_db_cluster_parameters is paginated (a param group can list hundreds of engine
    # defaults) — page through ALL of them, else a single unpaginated call can miss our one
    # explicitly-set parameter and produce a false "not applied" failure.
    params: list[dict] = []
    paginator = rds.get_paginator("describe_db_cluster_parameters")
    for page in paginator.paginate(DBClusterParameterGroupName=pg_name):
        params.extend(page["Parameters"])
    matches = [p for p in params if p["ParameterName"] == _PARAM_NAME]
    assert matches, (
        f"{_PARAM_NAME} not found in parameter group {pg_name} across {len(params)} parameters"
    )
    param = matches[0]
    assert param["ParameterValue"] == _PARAM_VALUE, (
        f"expected {_PARAM_NAME}={_PARAM_VALUE}, got {param.get('ParameterValue')!r}"
    )
    assert param["Source"] == "user", (
        f"expected Source='user' (explicitly applied via the CFN parameter group), got "
        f"{param.get('Source')!r} — the parameter group's custom value was never actually applied"
    )


# ===== helpers =====

def _master_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Sim2Real1" + "".join(secrets.choice(alphabet) for _ in range(12))


def _pick_azs_with_subnets(ctx, count: int = 2) -> tuple[str, list[dict]]:
    """Return (vpc_id, [subnet, ...]) covering `count` distinct AZs, for a DBSubnetGroup."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, dict] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) < count:
        raise AssertionError(
            f"VPC {vpc_id} has subnets in only {len(by_az)} AZ(s); need >= {count} for an RDS subnet group"
        )
    return vpc_id, list(by_az.values())[:count]


def _deploy_cfn(ctx, template_body: str, parameters: list[dict[str, str]] | None = None,
                 timeout_s: int = 2400) -> dict[str, str]:
    """Create a CloudFormation stack, poll to CREATE_COMPLETE, return its Outputs. Registers
    stack-delete cleanup (waits for DELETE_COMPLETE)."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-rds-cfn-")
    kwargs: dict[str, Any] = {"StackName": stack_name, "TemplateBody": template_body}
    if parameters:
        kwargs["Parameters"] = parameters

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 750})

    cfn.create_stack(**kwargs)
    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + timeout_s
    while True:
        desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = desc["StackStatus"]
        if status == "CREATE_COMPLETE":
            return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
        if status.endswith("FAILED") or "ROLLBACK" in status:
            events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            reasons = [
                e.get("ResourceStatusReason", "")
                for e in events
                if "FAILED" in e.get("ResourceStatus", "")
            ]
            raise AssertionError(f"stack {stack_name} entered {status}: {reasons}")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {stack_name} did not reach CREATE_COMPLETE within {timeout_s}s "
                f"(status={status})"
            )
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
