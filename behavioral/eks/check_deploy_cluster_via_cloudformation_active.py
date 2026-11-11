"""deploy-cluster-via-cloudformation-active."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cluster-via-cloudformation-active"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::EKS::Cluster is ACTIVE and usable (DescribeCluster,
    ListNodegroups) at CREATE_COMPLETE, and deleting the stack makes the cluster genuinely gone."""
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    eks = ctx.client("eks")

    subnet_ids = _get_default_subnets(ctx, ec2, count=2)

    cluster_name = ctx.unique_name("sim2real-eks-cfn-")
    stack_name = ctx.unique_name("sim2real-eks-cfn-stack-")
    tag_value = ctx.unique_name("sim2real-eks-cfn-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ClusterRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
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
                    "ResourcesVpcConfig": {"SubnetIds": subnet_ids},
                },
            },
        },
    }

    def _delete_stack(max_attempts=1350):
        # DeleteStack on an already-deleted stack succeeds, so any error here is a real failure.
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": tag_value}],
    )

    # The teardown wait fits the 1800 s cleanup budget; an EKS cluster stack deletes well within it.
    ctx.on_cleanup(lambda: _delete_stack(max_attempts=840))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1350}
    )

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"expected stack status CREATE_COMPLETE, got {stack['StackStatus']}"
    )

    described = eks.describe_cluster(name=cluster_name)["cluster"]
    assert described["status"] == "ACTIVE", (
        f"cluster not ACTIVE immediately after stack CREATE_COMPLETE: {described['status']}"
    )
    assert described["name"] == cluster_name, (
        f"expected cluster name {cluster_name!r}, got {described['name']!r}"
    )
    assert described["endpoint"].startswith("https://"), (
        f"expected an https endpoint, got {described['endpoint']!r}"
    )
    assert described["certificateAuthority"]["data"], (
        "expected a non-empty certificateAuthority.data on an ACTIVE cluster"
    )

    nodegroups = eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]
    assert nodegroups == [], f"expected no nodegroups on a fresh cluster, got {nodegroups}"

    # Deleting the stack must make the cluster gone, not merely absent from the
    # stack's own resource list: an independent read at the destination (EKS, not
    # CFN) must report the specific not-found code, and the cluster must drop out
    # of ListClusters too.
    _delete_stack()

    try:
        eks.describe_cluster(name=cluster_name)
        raise AssertionError(
            f"expected DescribeCluster to fail with ResourceNotFoundException for "
            f"{cluster_name!r} after stack deletion, but it still succeeded"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for a deleted cluster, got {code!r}"
        )
        message = err.response["Error"].get("Message", "")
        assert message == f"No cluster found for name: {cluster_name}.", message

    remaining_names: list[str] = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = eks.list_clusters(**kwargs)
        remaining_names.extend(resp.get("clusters", []))
        token = resp.get("nextToken")
        if not token:
            break
    assert cluster_name not in remaining_names, (
        f"expected {cluster_name!r} to be absent from ListClusters after stack deletion"
    )


# ===== helpers =====
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
