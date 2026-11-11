"""deploy-cfn-cluster-active-and-usable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-cluster-active-and-usable"
GROUP = "deploy"
SERVICES = ["eks"]

_ROLE_PROPAGATION_DEADLINE_S = 120.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A cluster deployed via CloudFormation (AWS::EKS::Cluster) reaches ACTIVE and
    behaviorally accepts a real CreateAddon call afterward - proving the underlying
    resource, not just the stack, is functional."""
    eks = ctx.client("eks")
    ctx.client("cloudformation")

    role_arn = _create_cluster_role(ctx)

    cluster_name = ctx.unique_name("sim2real-eks-cfncl-")
    template = json.dumps(
        {
            "Parameters": {
                "ClusterName": {"Type": "String"},
                "RoleArn": {"Type": "String"},
            },
            "Resources": {
                "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.62.0.0/16"}},
                "SubnetA": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": "10.62.0.0/24",
                        "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    },
                },
                "SubnetB": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": "10.62.1.0/24",
                        "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]},
                    },
                },
                "MyCluster": {
                    "Type": "AWS::EKS::Cluster",
                    "Properties": {
                        "Name": {"Ref": "ClusterName"},
                        "RoleArn": {"Ref": "RoleArn"},
                        "ResourcesVpcConfig": {"SubnetIds": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}]},
                        "Tags": [{"Key": "sim2real", "Value": "1"}],
                    },
                },
            },
        }
    )
    _deploy_cfn(
        ctx,
        template,
        parameters={"ClusterName": cluster_name, "RoleArn": role_arn},
    )

    cluster = eks.describe_cluster(name=cluster_name)["cluster"]
    assert cluster["status"] == "ACTIVE", f"unexpected status {cluster['status']!r}"
    assert cluster["arn"].endswith(f"cluster/{cluster_name}")

    # Now prove the underlying resource actually functions, not just the stack.
    addon_name = "vpc-cni"
    eks.create_addon(clusterName=cluster_name, addonName=addon_name, tags={"sim2real": "1"})
    ctx.on_cleanup(lambda: eks.delete_addon(clusterName=cluster_name, addonName=addon_name))

    addon = _poll_until(
        lambda: eks.describe_addon(clusterName=cluster_name, addonName=addon_name)["addon"],
        lambda a: a["status"] in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert addon["status"] in ("ACTIVE", "DEGRADED"), f"addon did not become usable: {addon['status']}"
    listed = eks.list_addons(clusterName=cluster_name)["addons"]
    assert addon_name in listed


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last}")


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
        Tags=[{"Key": "sim2real", "Value": "1"}],
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


def _stack_failure_reason(cfn, stack_name):
    try:
        stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    except ClientError:
        return None
    reasons = [stack.get("StackStatusReason") or ""]
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons.extend(
            e.get("ResourceStatusReason", "") for e in events if (e.get("ResourceStatus") or "").endswith("FAILED")
        )
    except ClientError:
        pass
    return " | ".join(r for r in reasons if r)


def _deploy_cfn(ctx, template_body, parameters=None, capabilities=None):
    """Create the stack. A brand-new IAM role's trust/attach can still be propagating
    when EKS validates RoleArn during CreateCluster, so a role-related stack failure is
    retried - with a fresh stack, since a FAILED/ROLLBACK_COMPLETE stack must be deleted
    before its name can be reused - within a bounded propagation window. Never an
    unconditional sleep before the first attempt."""
    cfn = ctx.client("cloudformation")
    retry_deadline = time.monotonic() + _ROLE_PROPAGATION_DEADLINE_S

    while True:
        stack_name = ctx.unique_name("sim2real-eks-stack-")
        kwargs = {"StackName": stack_name, "TemplateBody": template_body}
        if parameters:
            kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
        if capabilities:
            kwargs["Capabilities"] = capabilities
        cfn.create_stack(**kwargs)

        def _cleanup(name=stack_name):
            try:
                cfn.delete_stack(StackName=name)
                waiter = cfn.get_waiter("stack_delete_complete")
                waiter.wait(StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})
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
        if status == "CREATE_COMPLETE":
            return stack_name

        reason = _stack_failure_reason(cfn, stack_name) or ""
        if "role" in reason.lower() and time.monotonic() < retry_deadline:
            time.sleep(5.0)
            continue
        raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE: {status} ({reason})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
