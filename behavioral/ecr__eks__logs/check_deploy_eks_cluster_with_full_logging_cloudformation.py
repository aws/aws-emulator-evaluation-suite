"""deploy-eks-cluster-with-full-logging-cloudformation."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eks-cluster-with-full-logging-cloudformation"
GROUP = "iac-provisioning"
SERVICES = ["ecr", "eks", "logs"]

_LOG_TYPES = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
_STREAM_PREFIXES = {
    "api": "kube-apiserver-",
    "audit": "kube-apiserver-audit-",
    "authenticator": "authenticator-",
    "controllerManager": "kube-controller-manager-",
    "scheduler": "kube-scheduler-",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation EKS cluster with all five control-plane log types enabled writes a log
    stream for each of api, audit, authenticator, controllerManager and scheduler to
    /aws/eks/<cluster>/cluster."""
    cluster_name = _xname(ctx, "ekslog")
    role_name = _xname(ctx, "eksrole")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {
                        "CidrBlock": "10.42.0.0/16",
                        "EnableDnsSupport": True,
                        "EnableDnsHostnames": True,
                    },
                },
                "SubnetA": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": "10.42.0.0/24",
                        "AvailabilityZone": {
                            "Fn::Select": [0, {"Fn::GetAZs": ""}]
                        },
                    },
                },
                "SubnetB": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": "10.42.1.0/24",
                        "AvailabilityZone": {
                            "Fn::Select": [1, {"Fn::GetAZs": ""}]
                        },
                    },
                },
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
                            "SubnetIds": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                            "EndpointPublicAccess": True,
                        },
                        "Logging": {
                            "ClusterLogging": {
                                "EnabledTypes": [{"Type": t} for t in _LOG_TYPES]
                            }
                        },
                    },
                },
            },
        }
    )

    logs = ctx.client("logs")
    log_group_name = f"/aws/eks/{cluster_name}/cluster"
    # EKS creates the log group itself and leaves it behind when the cluster is deleted. Registered
    # before the stack so it runs after the stack (and the cluster) is gone.
    ctx.on_cleanup(lambda: _delete_log_group(logs, log_group_name))

    _deploy_cfn(
        ctx,
        template,
        timeout_s=1200.0,
    )

    def _group_exists() -> bool:
        resp = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
        return any(g["logGroupName"] == log_group_name for g in resp.get("logGroups", []))

    _poll_until(
        _group_exists,
        lambda ok: ok,
        timeout_s=300.0,
        interval_s=10.0,
        description=f"CloudWatch log group {log_group_name} creation",
    )

    def _streams_present() -> set[str]:
        found: set[str] = set()
        for log_type, prefix in _STREAM_PREFIXES.items():
            resp = logs.describe_log_streams(
                logGroupName=log_group_name, logStreamNamePrefix=prefix, limit=1
            )
            if resp.get("logStreams"):
                found.add(log_type)
        return found

    found_types = _poll_until(
        _streams_present,
        lambda found: found == set(_LOG_TYPES),
        timeout_s=600.0,
        interval_s=15.0,
        description="log streams for all 5 enabled EKS control-plane log types",
    )
    assert found_types == set(_LOG_TYPES), (
        f"missing log stream types: {sorted(set(_LOG_TYPES) - found_types)}"
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


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_log_group(logs, name: str) -> None:
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


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

    final = _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=780,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )
    if final == "DELETE_FAILED":
        raise AssertionError(f"stack {stack_name} ended in DELETE_FAILED")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
