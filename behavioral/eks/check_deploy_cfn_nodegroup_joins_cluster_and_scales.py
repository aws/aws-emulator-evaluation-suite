"""deploy-cfn-nodegroup-joins-cluster-and-scales."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-nodegroup-joins-cluster-and-scales"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A nodegroup deployed via CloudFormation (AWS::EKS::Nodegroup) reaches ACTIVE with
    its scalingConfig matching the template, and becomes visible to ListNodegroups /
    DescribeNodegroup on the parent cluster."""
    eks = ctx.client("eks")
    # Node role is created before the cluster (not right before it is needed) so that the
    # ~minutes-long cluster-ACTIVE poll below is what buys IAM propagation time for it, by
    # construction, rather than a blind sleep immediately before the CFN deploy that uses it.
    node_role_arn = _create_node_role(ctx)
    cluster = _create_active_cluster(ctx)

    nodegroup_name = ctx.unique_name("sim2real-eks-cfnng-")
    scaling = {"MinSize": 1, "MaxSize": 2, "DesiredSize": 1}
    template = json.dumps(
        {
            "Parameters": {
                "ClusterName": {"Type": "String"},
                "NodegroupName": {"Type": "String"},
                "NodeRole": {"Type": "String"},
                "SubnetIds": {"Type": "CommaDelimitedList"},
            },
            "Resources": {
                "MyNodegroup": {
                    "Type": "AWS::EKS::Nodegroup",
                    "Properties": {
                        "ClusterName": {"Ref": "ClusterName"},
                        "NodegroupName": {"Ref": "NodegroupName"},
                        "NodeRole": {"Ref": "NodeRole"},
                        "Subnets": {"Ref": "SubnetIds"},
                        "ScalingConfig": scaling,
                        "Tags": {"sim2real": "true"},
                    },
                }
            },
        }
    )
    _deploy_cfn(
        ctx,
        template,
        parameters={
            "ClusterName": cluster["name"],
            "NodegroupName": nodegroup_name,
            "NodeRole": node_role_arn,
            "SubnetIds": ",".join(cluster["subnet_ids"]),
        },
    )

    desc = eks.describe_nodegroup(clusterName=cluster["name"], nodegroupName=nodegroup_name)["nodegroup"]
    assert desc["status"] == "ACTIVE", f"nodegroup {nodegroup_name} status is {desc['status']!r}, not ACTIVE"
    assert desc["scalingConfig"] == {"minSize": 1, "maxSize": 2, "desiredSize": 1}, desc["scalingConfig"]

    listed = eks.list_nodegroups(clusterName=cluster["name"])["nodegroups"]
    assert nodegroup_name in listed, f"{nodegroup_name} not present in ListNodegroups: {listed}"

    # --- overly-permissive boundary: CreateNodegroup must reject an internally
    # inconsistent scalingConfig (desiredSize outside [minSize, maxSize]) rather than
    # silently accepting it, and must not create a nodegroup in the process.
    bad_name = ctx.unique_name("sim2real-eks-badng-")
    code, message = _error(
        lambda: eks.create_nodegroup(
            clusterName=cluster["name"],
            nodegroupName=bad_name,
            nodeRole=node_role_arn,
            subnets=cluster["subnet_ids"],
            scalingConfig={"minSize": 1, "maxSize": 2, "desiredSize": 5},
        )
    )
    assert code == "InvalidParameterException", code
    assert message == "desiredSize can't be greater than maxSize", message
    remaining_names = eks.list_nodegroups(clusterName=cluster["name"])["nodegroups"]
    assert bad_name not in remaining_names, remaining_names


def _error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last}")


def _default_subnets(ctx, min_azs=2):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    ids = list(by_az.values())
    if len(ids) < min_azs:
        raise AssertionError(
            "account/region has no shared network VPC with >=2 AZ subnets required for EKS "
            "cluster/nodegroup creation; provision one to close this gap"
        )
    return ids[:min_azs]


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_node_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-noderole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    policies = [
        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    ]
    for p in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=p)

    def _cleanup():
        for p in policies:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_cluster_with_retry(eks, kwargs, *, timeout_s=120.0, interval_s=10.0):
    """IAM is eventually consistent: a role created moments ago can make CreateCluster
    fail with InvalidParameterException until it propagates. Retry that specific error
    on a bounded deadline instead of guessing a fixed sleep up front."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(**kwargs)
            return
        except Exception as exc:  # noqa: BLE001 - retry only IAM-propagation style failures
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code != "InvalidParameterException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateCluster kept failing (role propagation?): {last_exc}")


def _create_active_cluster(ctx, extra_kwargs=None):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnet_ids = _default_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    kwargs = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        tags={"sim2real": "true"},
    )
    if extra_kwargs:
        kwargs.update(extra_kwargs)
    _create_cluster_with_retry(eks, kwargs)
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200.0,
        interval_s=20.0,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster did not reach ACTIVE: {cluster['status']}")
    return {"name": name, "arn": cluster["arn"], "role_arn": role_arn, "subnet_ids": subnet_ids}


def _deploy_cfn(ctx, template_body, parameters=None, capabilities=None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-eks-stack-")
    kwargs = {"StackName": stack_name, "TemplateBody": template_body, "Tags": [{"Key": "sim2real", "Value": "true"}]}
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cfn.create_stack(**kwargs)

    def _cleanup():
        try:
            cfn.delete_stack(StackName=stack_name)
            waiter = cfn.get_waiter("stack_delete_complete")
            waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED", "ROLLBACK_FAILED"),
        timeout_s=1200.0,
        interval_s=20.0,
    )
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE: {status}")
    return stack_name



def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network.

    DeleteCluster is refused while an update, node group or add-on operation still runs; that
    ResourceInUseException is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
