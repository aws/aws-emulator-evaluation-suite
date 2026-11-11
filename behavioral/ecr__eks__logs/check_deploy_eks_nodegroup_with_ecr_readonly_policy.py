"""deploy-eks-nodegroup-with-ecr-readonly-policy."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eks-nodegroup-with-ecr-readonly-policy"
GROUP = "iac-provisioning"
SERVICES = ["ecr", "eks", "logs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:native", "plane:data")
def run(ctx) -> None:
    """An EKS managed node group whose node role has AmazonEC2ContainerRegistryReadOnly lets a pod
    pull its image from a private ECR pull-through cache repository and run to completion."""
    from fidelity_tests_runner import require_tools

    require_tools("kubectl", "aws")

    subnet_ids = _default_vpc_subnets(ctx)
    cluster_name = _xname(ctx, "ekspull")
    cluster_role_name = _xname(ctx, "eksrole")
    node_role_name = _xname(ctx, "noderole")
    nodegroup_name = _xname(ctx, "ng")
    cache_prefix = ctx.unique_name("ptc-").lower()[:30].rstrip("-/")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"}},
            "Resources": {
                "ClusterRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": cluster_role_name,
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
                "NodeRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": node_role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "ec2.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
                            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
                            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
                        ],
                        "Policies": [
                            {
                                "PolicyName": "EcrPullThroughCacheImport",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "ecr:BatchImportUpstreamImage",
                                                "ecr:CreateRepository",
                                            ],
                                            "Resource": {
                                                "Fn::Sub": (
                                                    "arn:${AWS::Partition}:ecr:${AWS::Region}:"
                                                    f"${{AWS::AccountId}}:repository/{cache_prefix}/*"
                                                )
                                            },
                                        }
                                    ],
                                },
                            }
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
                        "AccessConfig": {
                            "AuthenticationMode": "API_AND_CONFIG_MAP",
                            "BootstrapClusterCreatorAdminPermissions": True,
                        },
                    },
                },
                "Nodegroup": {
                    "Type": "AWS::EKS::Nodegroup",
                    "Properties": {
                        "ClusterName": {"Ref": "Cluster"},
                        "NodegroupName": nodegroup_name,
                        "NodeRole": {"Fn::GetAtt": ["NodeRole", "Arn"]},
                        "Subnets": {"Ref": "SubnetIds"},
                        "ScalingConfig": {"MinSize": 1, "MaxSize": 1, "DesiredSize": 1},
                        "InstanceTypes": ["t3.medium"],
                        "AmiType": "AL2023_x86_64_STANDARD",
                    },
                },
                "PullThroughCache": {
                    "Type": "AWS::ECR::PullThroughCacheRule",
                    "Properties": {
                        "EcrRepositoryPrefix": cache_prefix,
                        "UpstreamRegistryUrl": "public.ecr.aws",
                    },
                },
            },
        }
    )

    _deploy_cfn(
        ctx,
        template,
        parameters={"SubnetIds": ",".join(subnet_ids)},
        timeout_s=1800.0,
    )

    # The pull-through repository exists only after the first pull, so the registry host is the
    # proxy endpoint ECR returns for this account rather than a host built from the region.
    proxy = ctx.client("ecr").get_authorization_token()["authorizationData"][0]["proxyEndpoint"]
    registry = proxy.split("://", 1)[-1].rstrip("/")
    image_uri = f"{registry}/{cache_prefix}/amazonlinux/amazonlinux:latest"
    mirrored_repo_name = f"{cache_prefix}/amazonlinux/amazonlinux"

    def _delete_mirrored_repo() -> None:
        ecr = ctx.client("ecr")
        try:
            repo_arn = ecr.describe_repositories(repositoryNames=[mirrored_repo_name])[
                "repositories"
            ][0]["repositoryArn"]
            ecr.tag_resource(resourceArn=repo_arn, tags=_xsvc_tags_kv())
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
                raise
        try:
            ecr.delete_repository(repositoryName=mirrored_repo_name, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
                raise

    ctx.on_cleanup(_delete_mirrored_repo)

    env = ctx.subprocess_env()
    kube_dir = Path(tempfile.mkdtemp(prefix="sim2real-xsvc-kubeconfig-"))
    ctx.on_cleanup(lambda: shutil.rmtree(kube_dir, ignore_errors=True))
    kubeconfig = kube_dir / "config"

    _run(
        [
            "aws", "eks", "update-kubeconfig",
            "--name", cluster_name,
            "--region", ctx.region,
            "--kubeconfig", str(kubeconfig),
        ],
        env=env,
        timeout_s=60,
    )

    def _node_ready() -> bool:
        proc = _run(
            ["kubectl", "--kubeconfig", str(kubeconfig), "get", "nodes", "-o", "json"],
            env=env,
            timeout_s=30,
            check=False,
        )
        if proc.returncode != 0:
            return False
        try:
            nodes = json.loads(proc.stdout).get("items", [])
        except (json.JSONDecodeError, ValueError):
            return False
        for node in nodes:
            for cond in node.get("status", {}).get("conditions", []):
                if cond.get("type") == "Ready" and cond.get("status") == "True":
                    return True
        return False

    _poll_until(
        _node_ready,
        lambda ok: ok,
        timeout_s=420.0,
        interval_s=15.0,
        description="EKS worker node reaching Ready",
    )

    pod_name = ctx.unique_name("ecr-pull-test-").lower()
    pod_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": "default"},
        "spec": {
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "ecr-pull-test",
                    "image": image_uri,
                    "command": ["sh", "-c", "echo pulled-ok"],
                }
            ],
        },
    }

    def _delete_pod() -> None:
        subprocess.run(
            ["kubectl", "--kubeconfig", str(kubeconfig), "delete", "pod", pod_name,
             "-n", "default", "--ignore-not-found", "--wait=false"],
            env=env, capture_output=True, timeout=30,
        )

    ctx.on_cleanup(_delete_pod)

    apply = subprocess.run(
        ["kubectl", "--kubeconfig", str(kubeconfig), "apply", "-f", "-"],
        input=json.dumps(pod_manifest),
        env=env, capture_output=True, text=True, timeout=30,
    )
    if apply.returncode != 0:
        raise AssertionError(f"kubectl apply of test pod failed: {apply.stderr[-500:]}")

    def _pod_phase() -> str:
        proc = _run(
            ["kubectl", "--kubeconfig", str(kubeconfig), "get", "pod", pod_name,
             "-n", "default", "-o", "jsonpath={.status.phase}"],
            env=env, timeout_s=30, check=False,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""

    phase = _poll_until(
        _pod_phase,
        lambda p: p in {"Succeeded", "Failed"},
        timeout_s=900.0,
        interval_s=10.0,
        description=f"pod {pod_name} reaching a terminal phase",
    )
    assert phase == "Succeeded", (
        f"pod {pod_name} ended in phase {phase!r} instead of Succeeded -- the node role's "
        "AmazonEC2ContainerRegistryReadOnly permissions did not enable a real ECR image pull"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _run(cmd, *, env, timeout_s=60.0, check=True) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout_s)
    if check and proc.returncode != 0:
        raise AssertionError(f"command {cmd!r} failed: {proc.stderr[-500:]}")
    return proc


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


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup).

    The bound covers an EKS cluster and its nodegroup, which take many minutes to delete."""
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


def _default_vpc_subnets(ctx) -> list[str]:
    """At least 2 subnet IDs in distinct AZs of the run's shared network (EKS requires >=2 AZs)."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region - cannot locate ready-made subnets to "
            "provision the EKS control plane ENIs and worker nodes without also building a VPC"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            "shared network VPC has subnets in fewer than 2 Availability Zones - EKS requires "
            "subnets spanning >= 2 AZs"
        )
    return list(by_az.values())[:3]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
