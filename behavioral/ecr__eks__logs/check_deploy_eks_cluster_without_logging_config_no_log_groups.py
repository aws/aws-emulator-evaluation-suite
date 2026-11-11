"""deploy-eks-cluster-without-logging-config-no-log-groups."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eks-cluster-without-logging-config-no-log-groups"
GROUP = "iac-provisioning"
SERVICES = ["ecr", "eks", "logs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """A CloudFormation EKS cluster with no Logging block (all control-plane logs disabled) creates
    no /aws/eks/<cluster>/cluster log group; enabling one log type with UpdateClusterConfig on the
    same cluster then makes it appear."""
    subnet_ids = _vpc_subnets(ctx)
    cluster_name = _xname(ctx, "eksnolog")
    role_name = _xname(ctx, "eksrole")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"}},
            "Resources": {
                "ClusterRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "eks.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
                        ],
                    },
                },
                "Cluster": {
                    "Type": "AWS::EKS::Cluster",
                    "Properties": {
                        "Name": cluster_name,
                        "RoleArn": {"Fn::GetAtt": ["ClusterRole", "Arn"]},
                        "ResourcesVpcConfig": {
                            "SubnetIds": {"Ref": "SubnetIds"},
                            "EndpointPublicAccess": True,
                        },
                        # deliberately NO "Logging" property: real AWS defaults every
                        # control-plane log type to disabled when it is omitted.
                    },
                },
            },
        }
    )

    _deploy_cfn(
        ctx,
        template,
        parameters={"SubnetIds": ",".join(subnet_ids)},
        timeout_s=1200.0,
    )

    logs = ctx.client("logs")
    log_group_name = f"/aws/eks/{cluster_name}/cluster"

    def _group_exists() -> bool:
        resp = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
        return any(g["logGroupName"] == log_group_name for g in resp.get("logGroups", []))

    # 240s is long enough that a log group created late is still caught.
    _assert_absent_for(
        _group_exists,
        duration_s=240.0,
        interval_s=20.0,
        description=(
            f"log group {log_group_name} exists even though the cluster's template had no "
            "Logging block configured"
        ),
    )

    eks = ctx.client("eks")
    update = eks.update_cluster_config(
        name=cluster_name,
        logging={"clusterLogging": [{"types": ["api"], "enabled": True}]},
    )
    update_id = update["update"]["id"]

    def _update_status() -> str:
        return eks.describe_update(name=cluster_name, updateId=update_id)["update"]["status"]

    status = _poll_until(
        _update_status,
        lambda s: s in {"Successful", "Failed", "Cancelled"},
        timeout_s=180.0,
        interval_s=5.0,
        description=f"UpdateClusterConfig {update_id} completion",
    )
    assert status == "Successful", f"enabling api logging ended in status {status!r}"

    _poll_until(
        _group_exists,
        lambda ok: ok,
        timeout_s=300.0,
        interval_s=10.0,
        description=f"CloudWatch log group {log_group_name} creation after enabling api logging",
    )

    def _api_stream_present() -> bool:
        resp = logs.describe_log_streams(
            logGroupName=log_group_name, logStreamNamePrefix="kube-apiserver-", limit=1
        )
        return bool(resp.get("logStreams"))

    _poll_until(
        _api_stream_present,
        lambda ok: ok,
        timeout_s=180.0,
        interval_s=10.0,
        description="kube-apiserver- log stream appearing after enabling api logging",
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
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


def _assert_absent_for(probe, *, duration_s, interval_s, description):
    """Poll probe() across duration_s, failing the instant it turns truthy (never at the end)."""
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        assert not probe(), description
        time.sleep(interval_s)


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=1500,
        interval_s=5.0,
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
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
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


def _tag_spec(resource_type: str, name: str) -> dict[str, Any]:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _safe_delete(fn, attempts: int = 6, delay_s: float = 15.0) -> None:
    for attempt in range(attempts):
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("DependencyViolation", "InvalidParameterValue") and attempt < attempts - 1:
                time.sleep(delay_s)
                continue
            return
        except Exception:
            return


def _create_vpc_and_subnets(ctx) -> dict[str, Any]:
    """A dedicated VPC with subnets in 2 AZs (EKS requires >=2)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"{_XSVC_PREFIX}eksnolog-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock="10.43.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])[
        "Vpc"
    ]["VpcId"]

    def _cleanup_vpc() -> None:
        _safe_delete(lambda: ec2.delete_vpc(VpcId=vpc_id))

    ctx.on_cleanup(_cleanup_vpc)
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.43.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-subnet-{i}")],
        )["Subnet"]["SubnetId"]

        def _cleanup_subnet(sid: str = subnet_id) -> None:
            _safe_delete(lambda: ec2.delete_subnet(SubnetId=sid))

        ctx.on_cleanup(_cleanup_subnet)
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _vpc_subnets(ctx) -> list[str]:
    """Subnets across >=2 AZs from the shared network, or a dedicated VPC when none exists;
    reusing the shared network avoids VpcLimitExceeded under concurrent runs."""
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:3]
    return _create_vpc_and_subnets(ctx)["subnet_ids"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
