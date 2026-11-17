"""deploy-cfn-cluster-auto-mode-compute-network-storage-config."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-cluster-auto-mode-compute-network-storage-config"
GROUP = "deploy"
SERVICES = ["cloudformation", "eks"]

_CREATE_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)
_DELETE_TERMINAL = frozenset({"DELETE_COMPLETE", "DELETE_FAILED"})
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
_PAIRING_REJECTED = (
    "When Compute Config nodeRoleArn is not null or empty, nodePool value(s) must be provided. "
    "(Service: Eks, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _not_found(cluster_name):
    return ("ResourceNotFoundException", f"No cluster found for name: {cluster_name}.")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _stack_status(cf, stack_id):
    """The stack's status read by StackId; the exact not-found pair reads as DELETE_COMPLETE."""
    try:
        return cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
            "ValidationError",
            f"Stack with id {stack_id} does not exist",
        ):
            return "DELETE_COMPLETE"
        raise


def _wait_stack(ctx, cf, stack_id, terminal, timeout_s, interval_s=15.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = _stack_status(cf, stack_id)
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"stack {stack_id}: the run budget ended first; not graded")
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(interval_s)


def _delete_stack(ctx, cf, stack_id):
    """Delete the stack whatever state it is in, and raise unless it reaches DELETE_COMPLETE."""
    if _stack_status(cf, stack_id) == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(ctx, cf, stack_id, _DELETE_TERMINAL, timeout_s=1500.0)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def _stack_outputs(cf, stack_id):
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _stack_events(cf, stack_id):
    return list(
        cf.get_paginator("describe_stack_events")
        .paginate(StackName=stack_id)
        .build_full_result()["StackEvents"]
    )[::-1]


def _failed_reason(events, logical_id):
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(rows) == 1, f"expected one CREATE_FAILED row for {logical_id}, got {rows!r}"
    return rows[0]


def _masked(text):
    """``text`` masking only Request ID, RequestToken and SDK Attempt Count."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    return text


def _handler_reason(reason):
    """``(masked message, HandlerErrorCode)`` of a registry-handler failure reason."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return _masked(m["message"]), m["code"]


def _expect_error(fn, code, message):
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _template(cluster_name, subnets, service_cidr, *, node_role_arn=None):
    """One cluster role (and, when ``node_role_arn`` is given, one node role) plus an
    AWS::EKS::Cluster enabling EKS Auto Mode's compute, network and storage capabilities.

    With ``node_role_arn`` set and ``NodePools`` empty, EKS refuses the combination; otherwise it
    deploys with no default node pool, so Auto Mode is on but no EC2 Managed Instance launches.
    """
    resources = {
        "ClusterRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "eks.amazonaws.com"},
                            "Action": ["sts:AssumeRole", "sts:TagSession"],
                        }
                    ],
                },
                "ManagedPolicyArns": [
                    {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonEKSClusterPolicy"},
                    {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonEKSComputePolicy"},
                    {
                        "Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonEKSBlockStoragePolicyV2"
                    },
                    {
                        "Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonEKSLoadBalancingPolicy"
                    },
                    {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonEKSNetworkingPolicy"},
                ],
            },
        },
        "EksCluster": {
            "Type": "AWS::EKS::Cluster",
            "Properties": {
                "Name": cluster_name,
                "RoleArn": {"Fn::GetAtt": ["ClusterRole", "Arn"]},
                "ResourcesVpcConfig": {
                    "SubnetIds": subnets,
                    "EndpointPublicAccess": False,
                    "EndpointPrivateAccess": True,
                },
                "AccessConfig": {"AuthenticationMode": "API"},
                "ComputeConfig": {"Enabled": True, "NodePools": []},
                "KubernetesNetworkConfig": {
                    "ElasticLoadBalancing": {"Enabled": True},
                    "IpFamily": "ipv4",
                    "ServiceIpv4Cidr": service_cidr,
                },
                "StorageConfig": {"BlockStorage": {"Enabled": True}},
            },
        },
    }
    outputs = {
        "ClusterArn": {"Value": {"Fn::GetAtt": ["EksCluster", "Arn"]}},
        "ClusterSecurityGroupId": {
            "Value": {"Fn::GetAtt": ["EksCluster", "ClusterSecurityGroupId"]}
        },
        "ClusterOidcIssuerUrl": {"Value": {"Fn::GetAtt": ["EksCluster", "OpenIdConnectIssuerUrl"]}},
        "ClusterRoleArn": {"Value": {"Fn::GetAtt": ["ClusterRole", "Arn"]}},
    }
    if node_role_arn == "SELF":
        resources["NodeRole"] = {
            "Type": "AWS::IAM::Role",
            "Properties": {
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
                    {
                        "Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonEKSWorkerNodeMinimalPolicy"
                    },
                    {
                        "Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly"
                    },
                ],
            },
        }
        resources["EksCluster"]["Properties"]["ComputeConfig"]["NodeRoleArn"] = {
            "Fn::GetAtt": ["NodeRole", "Arn"]
        }
    return json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs}
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EKS::Cluster whose ComputeConfig sets NodeRoleArn without NodePools
    is rejected and the cluster never exists, while the same private-endpoint Auto Mode template
    without NodeRoleArn deploys and DescribeCluster echoes back the exact values it set."""
    cf = ctx.client("cloudformation")
    eks = ctx.client("eks")
    subnets = ctx.network().subnet_ids[:2]
    assert len(subnets) == 2, f"the run's network has subnets in fewer than two AZs: {subnets!r}"

    service_cidr = "10.95.0.0/16"

    # Positive control: EKS Auto Mode enabled with no NodeRoleArn/NodePools conflict.
    good_cluster = ctx.unique_name("sim2real-eks-automode-")
    good_stack = ctx.unique_name("sim2real-eks-automode-stack-")
    good_id = cf.create_stack(
        StackName=good_stack,
        TemplateBody=_template(good_cluster, subnets, service_cidr),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": good_stack}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cf, good_id))

    status = _wait_stack(ctx, cf, good_id, _CREATE_TERMINAL, timeout_s=1500.0)
    if status != "CREATE_COMPLETE":
        reason = _failed_reason(_stack_events(cf, good_id), "EksCluster")
        raise AssertionError(f"control stack ended {status!r}: {reason!r}")

    out = _stack_outputs(cf, good_id)
    cluster = eks.describe_cluster(name=good_cluster)["cluster"]
    assert cluster["status"] == "ACTIVE", f"unexpected status {cluster['status']!r}"
    partition = good_id.split(":", 2)[1]
    want_arn = f"arn:{partition}:eks:{ctx.region}:{ctx.account}:cluster/{good_cluster}"
    assert (cluster["arn"], out["ClusterArn"]) == (want_arn, want_arn), (
        f"DescribeCluster arn {cluster['arn']!r} and GetAtt Arn {out['ClusterArn']!r}, "
        f"expected {want_arn!r}"
    )
    vpc_cfg = cluster["resourcesVpcConfig"]
    got_access = (vpc_cfg["endpointPublicAccess"], vpc_cfg["endpointPrivateAccess"])
    assert got_access == (False, True), f"endpoint access {got_access!r}, expected (False, True)"
    assert (
        cluster["resourcesVpcConfig"]["clusterSecurityGroupId"] == out["ClusterSecurityGroupId"]
    ), (cluster["resourcesVpcConfig"]["clusterSecurityGroupId"], out["ClusterSecurityGroupId"])
    assert cluster["identity"]["oidc"]["issuer"] == out["ClusterOidcIssuerUrl"], (
        cluster["identity"]["oidc"]["issuer"],
        out["ClusterOidcIssuerUrl"],
    )
    assert cluster["roleArn"] == out["ClusterRoleArn"], (cluster["roleArn"], out["ClusterRoleArn"])

    compute = cluster["computeConfig"]
    assert compute["enabled"] is True, compute
    assert compute["nodePools"] == [], compute
    assert "nodeRoleArn" not in compute, compute

    net_cfg = cluster["kubernetesNetworkConfig"]
    assert net_cfg["elasticLoadBalancing"]["enabled"] is True, net_cfg
    assert net_cfg["ipFamily"] == "ipv4", net_cfg
    assert net_cfg["serviceIpv4Cidr"] == service_cidr, net_cfg

    storage = cluster["storageConfig"]
    assert storage["blockStorage"]["enabled"] is True, storage

    _delete_stack(ctx, cf, good_id)
    expect_gone = _not_found(good_cluster)
    _expect_error(lambda: eks.describe_cluster(name=good_cluster), *expect_gone)

    # Negative: NodeRoleArn without NodePools is refused, and no cluster is ever created.
    bad_cluster = ctx.unique_name("sim2real-eks-automode-bad-")
    bad_stack = ctx.unique_name("sim2real-eks-automode-badstack-")
    bad_id = cf.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(bad_cluster, subnets, service_cidr, node_role_arn="SELF"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": bad_stack}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cf, bad_id))

    status = _wait_stack(ctx, cf, bad_id, _CREATE_TERMINAL, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = _handler_reason(_failed_reason(_stack_events(cf, bad_id), "EksCluster"))
    assert got == _PAIRING_REJECTED, f"handler reason {got!r}, expected {_PAIRING_REJECTED!r}"

    not_found = _not_found(bad_cluster)
    _expect_error(lambda: eks.describe_cluster(name=bad_cluster), *not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
