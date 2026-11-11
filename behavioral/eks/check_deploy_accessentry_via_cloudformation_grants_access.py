"""deploy-accessentry-via-cloudformation-grants-access."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-accessentry-via-cloudformation-grants-access"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AWS::EKS::AccessEntry created through CloudFormation is immediately
    queryable and its associated access policy grant is enforced, verified via
    DescribeAccessEntry and ListAssociatedAccessPolicies."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")
    cfn = ctx.client("cloudformation")

    subnet_ids = _create_eks_vpc_subnets(ctx, ec2)
    cluster_role_arn = _create_iam_role(
        ctx, iam, "eks.amazonaws.com", ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]
    )

    cluster_name = ctx.unique_name("sim2real-eks-ae-")
    _create_cluster(ctx, eks, cluster_name, cluster_role_arn, subnet_ids, auth_mode="API_AND_CONFIG_MAP")
    _wait_cluster_active(eks, cluster_name)

    # A distinct IAM role acts as the principal the access entry grants access to.
    principal_arn = _create_iam_role(
        ctx, iam, "ec2.amazonaws.com", []
    )
    _wait_principal_arn_recognized(eks, cluster_name, principal_arn)

    stack_name = ctx.unique_name("sim2real-eks-ae-stack-")
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

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )

    ctx.on_cleanup(_delete_stack)

    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except Exception:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        import re

        reason = ""
        for e in events:
            if e["LogicalResourceId"] == "AccessEntry" and e.get("ResourceStatusReason"):
                reason = e["ResourceStatusReason"]
                break
        msg_match = re.search(r'message:\s*"([^"]+)"', reason)
        code_match = re.search(r"HandlerErrorCode:\s*(\S+)", reason)
        short = (msg_match.group(1) if msg_match else reason[:200])
        code = code_match.group(1) if code_match else "?"
        raise AssertionError(f"AccessEntry stack create failed [{code}]: {short}")

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {stack['StackStatus']}"
    )

    described = eks.describe_access_entry(clusterName=cluster_name, principalArn=principal_arn)["accessEntry"]
    assert described["principalArn"] == principal_arn, (
        f"expected access entry principalArn {principal_arn!r}, got {described['principalArn']!r}"
    )

    policies = eks.list_associated_access_policies(clusterName=cluster_name, principalArn=principal_arn)[
        "associatedAccessPolicies"
    ]
    policy_arns = [p["policyArn"] for p in policies]
    assert policy_arn in policy_arns, (
        f"expected {policy_arn!r} among associated access policies, got {policy_arns!r}"
    )

    # Deploy artifacts must prove teardown, not just perform it: delete the stack now
    # (ctx.on_cleanup's copy is an idempotent safety net if this raises first) and assert
    # the access entry it created is genuinely gone via an independent read.
    _delete_stack()
    gone_code, gone_message = _error(
        lambda: eks.describe_access_entry(clusterName=cluster_name, principalArn=principal_arn)
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected access entry to be gone after stack deletion, got {gone_code!r}"
    )
    assert gone_message == "The requested resource does not exist.", gone_message


def _error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _create_eks_vpc_subnets(ctx, ec2, count=2):
    # Never depend on an ambient default VPC (a freshly provisioned account may not have
    # one) -- provision a dedicated VPC and AZ-distinct subnets instead. But VpcLimitExceeded
    # is a real, raisable, per-account quota (not a fidelity contract), so an account
    # that is already at its VPC quota adopts the account's existing default VPC instead of
    # failing outright -- create-or-adopt, never a bare assumption either way.
    tag_spec = lambda resource_type, name: [  # noqa: E731
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real-managed", "Value": "true"}],
        }
    ]
    try:
        vpc_id = ec2.create_vpc(
            CidrBlock="10.92.0.0/16",
            TagSpecifications=tag_spec("vpc", ctx.unique_name("sim2real-eks-ae-vpc-")),
        )["Vpc"]["VpcId"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "VpcLimitExceeded":
            raise
        return _get_default_subnets(ec2, count=count, ctx=ctx)

    # The EKS cluster that will live in this VPC leaves ENIs attached to its subnets for a
    # short grace period after DeleteCluster's own waiter reports done, so a same-instant
    # DeleteVpc/DeleteSubnet can race a DependencyViolation -- retry within a bounded window
    # rather than leaking the VPC.
    ctx.on_cleanup(lambda: _retry_dependency_violation(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:count]]
    if len(azs) < count:
        raise AssertionError(f"region has fewer than {count} availability zones for an EKS cluster")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.92.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=tag_spec("subnet", ctx.unique_name(f"sim2real-eks-ae-subnet{i}-")),
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(
            lambda sid=subnet_id: _retry_dependency_violation(lambda: ec2.delete_subnet(SubnetId=sid))
        )
    return subnet_ids


def _get_default_subnets(ec2, count=2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "account is at its VPC quota and has no shared network VPC to fall back to for an EKS cluster"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < count:
        raise AssertionError("shared network lacks enough AZ-distinct subnets for an EKS cluster")
    return subnet_ids[:count]


def _retry_dependency_violation(fn, timeout_s=120, interval_s=5):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"delete still blocked by DependencyViolation after {timeout_s}s: {last_err}")


def _create_iam_role(ctx, iam, trust_service, managed_policy_arns):
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )["Role"]
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


def _create_cluster(ctx, eks, cluster_name, role_arn, subnet_ids, auth_mode="API_AND_CONFIG_MAP"):
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
                accessConfig={"authenticationMode": auth_mode},
                tags={"sim2real-managed": "true"},
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


def _wait_principal_arn_recognized(eks, cluster_name, principal_arn, timeout=90):
    """IAM principals are eventually consistent cross-service: EKS validates the
    PrincipalArn against IAM at AccessEntry-creation time, and a role created
    moments ago by this same check may not yet be visible to that validation.
    Prove the ARN is recognized with a real create+delete before handing the
    (unretried) CloudFormation create_stack the same ARN."""
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_access_entry(clusterName=cluster_name, principalArn=principal_arn)
            eks.delete_access_entry(clusterName=cluster_name, principalArn=principal_arn)
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"principalArn never recognized by EKS (IAM propagation?): {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
