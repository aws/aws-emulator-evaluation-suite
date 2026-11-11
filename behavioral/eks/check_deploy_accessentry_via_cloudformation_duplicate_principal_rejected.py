"""deploy-accessentry-via-cloudformation-duplicate-principal-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-accessentry-via-cloudformation-duplicate-principal-rejected"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a CloudFormation stack creates an AccessEntry, a direct CreateAccessEntry for the same
    clusterName/principalArn is rejected with ResourceInUseException; the original entry's grant
    is untouched and still queryable (positive control)."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")
    cfn = ctx.client("cloudformation")

    subnet_ids = _get_default_subnets(ctx, ec2, count=2)
    cluster_role_arn = _create_iam_role(
        ctx, iam, "eks.amazonaws.com", ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]
    )

    cluster_name = ctx.unique_name("sim2real-eks-aedup-")
    _create_cluster(ctx, eks, cluster_name, cluster_role_arn, subnet_ids)
    _wait_cluster_active(eks, cluster_name)

    principal_arn = _create_iam_role(ctx, iam, "ec2.amazonaws.com", [])
    _wait_principal_arn_recognized(eks, cluster_name, principal_arn)

    stack_name = ctx.unique_name("sim2real-eks-aedup-stack-")
    policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "AccessEntry": {
                "Type": "AWS::EKS::AccessEntry",
                "Properties": {
                    "ClusterName": cluster_name,
                    "PrincipalArn": principal_arn,
                    "AccessPolicies": [
                        {"PolicyArn": policy_arn, "AccessScope": {"Type": "cluster"}}
                    ],
                },
            }
        },
    }

    def _delete_stack():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    ctx.on_cleanup(_delete_stack)

    stack = _create_stack_with_retry(cfn, stack_name, template)
    assert stack["StackStatus"] == "CREATE_COMPLETE"

    before = eks.describe_access_entry(clusterName=cluster_name, principalArn=principal_arn)["accessEntry"]

    # Break exactly one thing: try to create ANOTHER access entry for the same
    # clusterName/principalArn pair that CloudFormation already provisioned.
    code, message = _error(
        lambda: eks.create_access_entry(clusterName=cluster_name, principalArn=principal_arn)
    )
    assert code == "ResourceInUseException", code
    assert message == "The specified access entry resource is already in use on this cluster.", message

    # Effect absent: the original entry is untouched (not overwritten/duplicated).
    after = eks.describe_access_entry(clusterName=cluster_name, principalArn=principal_arn)["accessEntry"]
    assert after["modifiedAt"] == before["modifiedAt"]
    assert after["createdAt"] == before["createdAt"]

    # Positive control: the CFN-deployed grant is still fully functional.
    policies = eks.list_associated_access_policies(clusterName=cluster_name, principalArn=principal_arn)[
        "associatedAccessPolicies"
    ]
    assert policy_arn in [p["policyArn"] for p in policies]


def _create_stack_with_retry(cfn, stack_name, template, timeout=180):
    """CloudFormation's EKS handler is not retried and may still hit a host where the principal
    has not converged; delete the failed stack and resubmit within a bounded deadline."""
    import re

    deadline = time.monotonic() + timeout
    last_reason = None
    while True:
        cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
        try:
            cfn.get_waiter("stack_create_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
            )
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except Exception:
            events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            reason = ""
            for e in events:
                if e["LogicalResourceId"] == "AccessEntry" and e.get("ResourceStatusReason"):
                    reason = e["ResourceStatusReason"]
                    break
            msg_match = re.search(r'message:\s*"([^"]+)"', reason)
            last_reason = msg_match.group(1) if msg_match else (reason[:200] or "unknown")
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
            )
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"stack create never succeeded within {timeout}s (IAM propagation?): {last_reason}"
                )


def _error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _get_default_subnets(ctx, ec2, count=2):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to provision an EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < count:
        raise AssertionError("shared network lacks enough AZ-distinct subnets for an EKS cluster")
    return subnet_ids[:count]


def _create_iam_role(ctx, iam, trust_service, managed_policy_arns):
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    for arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    def _cleanup():
        for arn in managed_policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_cluster(ctx, eks, cluster_name, role_arn, subnet_ids):
    def _cleanup():
        eks.delete_cluster(name=cluster_name)
        _wait_cluster_deleted(eks, cluster_name)

    ctx.on_cleanup(_cleanup)
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                accessConfig={"authenticationMode": "API_AND_CONFIG_MAP"},
            )
            return
        except ClientError as exc:  # pragma: no cover - transient IAM propagation
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreateCluster never succeeded (role propagation?): {last_err}")


def _wait_cluster_active(eks, cluster_name):
    eks.get_waiter("cluster_active").wait(
        name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )


def _wait_cluster_deleted(eks, cluster_name):
    eks.get_waiter("cluster_deleted").wait(
        name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )


def _wait_principal_arn_recognized(eks, cluster_name, principal_arn, timeout=180):
    """EKS validates PrincipalArn against IAM (eventually consistent); prove a just-created role
    is recognized via a real create+delete before passing it to the unretried CreateStack."""
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_access_entry(clusterName=cluster_name, principalArn=principal_arn)
            eks.delete_access_entry(clusterName=cluster_name, principalArn=principal_arn)
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(2)
    raise AssertionError(f"principalArn never recognized by EKS (IAM propagation?): {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
