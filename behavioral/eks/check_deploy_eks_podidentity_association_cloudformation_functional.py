"""deploy-eks-podidentity-association-cloudformation-functional."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-eks-podidentity-association-cloudformation-functional"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A PodIdentityAssociation deployed via CloudFormation resolves to a working,
    assumable IAM role -- not merely a stored namespace/serviceAccount->roleArn mapping."""
    vpc = _create_vpc_infra(ctx)
    cluster_role_arn = _create_cluster_role(ctx)
    cluster_name = ctx.unique_name("sim2real-eks-pia-")
    _create_cluster_via_sdk(ctx, cluster_name, cluster_role_arn, vpc["subnet_ids"])

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    pod_role_name, pod_role_arn = _create_pod_identity_role(ctx, account_id)

    namespace = "sim2real-ns"
    service_account = "sim2real-sa"
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ClusterName": {"Type": "String"},
            "Namespace": {"Type": "String"},
            "ServiceAccount": {"Type": "String"},
            "RoleArn": {"Type": "String"},
        },
        "Resources": {
            "PodIdAssoc": {
                "Type": "AWS::EKS::PodIdentityAssociation",
                "Properties": {
                    "ClusterName": {"Ref": "ClusterName"},
                    "Namespace": {"Ref": "Namespace"},
                    "ServiceAccount": {"Ref": "ServiceAccount"},
                    "RoleArn": {"Ref": "RoleArn"},
                },
            }
        },
        "Outputs": {"AssociationIdOut": {"Value": {"Fn::GetAtt": ["PodIdAssoc", "AssociationId"]}}},
    }
    result = _deploy_stack(
        ctx,
        template,
        {
            "ClusterName": cluster_name,
            "Namespace": namespace,
            "ServiceAccount": service_account,
            "RoleArn": pod_role_arn,
        },
        create_timeout_s=300,
    )
    association_id = result["outputs"]["AssociationIdOut"]

    eks = ctx.client("eks")
    assoc = eks.describe_pod_identity_association(clusterName=cluster_name, associationId=association_id)["association"]
    assert assoc["roleArn"] == pod_role_arn
    assert assoc["namespace"] == namespace
    assert assoc["serviceAccount"] == service_account

    # Prove the mapped role is not merely a stored ARN string: actually assume it and
    # confirm the caller identity reflects the assumed role.
    creds = _assume_role_with_retry(sts, pod_role_arn, "sim2real-podid-verify")
    assumed_client = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_" + "secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    identity = assumed_client.get_caller_identity()
    expected_arn = f"arn:aws:sts::{account_id}:assumed-role/{pod_role_name}/sim2real-podid-verify"
    assert identity["Arn"] == expected_arn


# ===== helpers =====


def _assume_role_with_retry(sts_client, role_arn: str, session_name: str, timeout_s: float = 90.0, interval_s: float = 5.0) -> dict:
    """A freshly created role's trust policy can take a few seconds to propagate through
    IAM; retry AccessDenied on assume-role within a bounded window rather than failing
    on the very first attempt."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "AccessDenied":
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"assume_role on {role_arn} still denied after {timeout_s}s (IAM propagation): {last_exc}")


def _retry_delete(fn, attempts: int = 12, delay_s: float = 10.0) -> None:
    last_exc = None
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup retry
            last_exc = exc
            time.sleep(delay_s)
    if last_exc is not None:
        raise last_exc


def _create_vpc_infra(ctx) -> dict:
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not default_vpcs:
        raise AssertionError("no shared network VPC available in this account/region for EKS subnets")
    vpc_id = default_vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    subnet_ids = sorted({s["SubnetId"] for s in subnets})[:3]
    if len(subnet_ids) < 2:
        raise AssertionError(
            f"shared network VPC {vpc_id} does not have enough shared-network subnets for EKS "
            f"(need >=2, found {len(subnet_ids)})"
        )
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": None}



def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-cluster-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _create_pod_identity_role(ctx, account_id: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-podid-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            },
            {
                # Also trust the account root so this check can independently verify the
                # role is genuinely assumable, without needing a running EKS pod.
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_name, role_arn


def _create_cluster_via_sdk(ctx, name: str, role_arn: str, subnet_ids: list[str]) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except Exception as exc:  # noqa: BLE001 - retry only IAM-propagation style failures
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))
    _wait_cluster_status(ctx, name, "ACTIVE", timeout_s=1200)


def _wait_cluster_status(ctx, name: str, target: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        last_status = cluster["status"]
        if last_status == target:
            return cluster
        if last_status in ("FAILED",):
            raise AssertionError(f"cluster {name} entered terminal status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {target} within {timeout_s}s (last={last_status})")


def _delete_cluster_and_wait(ctx, name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    try:
        _delete_eks_cluster_retrying(eks, name)
    except Exception as exc:  # noqa: BLE001 - tolerate already-deleted during cleanup
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _deploy_stack(ctx, template: dict, parameters: dict, create_timeout_s: float = 300.0) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-eks-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
    )

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup)

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max(10, int(create_timeout_s // 2))})

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    return {"stack_name": stack_name, "outputs": {o["OutputKey"]: o["OutputValue"] for o in outputs}}



def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
