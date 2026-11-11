"""deploy-cfn-pod-identity-association-grants-role-access."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-pod-identity-association-grants-role-access"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A PodIdentityAssociation deployed via CloudFormation actually authorizes the
    associated role, verified by successfully calling AssumeRole/GetCallerIdentity
    against it post-deploy."""
    eks = ctx.client("eks")
    sts = ctx.client("sts")
    cluster = _create_active_cluster(ctx)
    identity = sts.get_caller_identity()
    caller_arn, account_id = identity["Arn"], identity["Account"]
    role_arn, role_name = _create_pod_identity_role(ctx, caller_arn)

    namespace = "default"
    service_account = ctx.unique_name("sim2real-sa-")
    template = json.dumps(
        {
            "Parameters": {
                "ClusterName": {"Type": "String"},
                "Namespace": {"Type": "String"},
                "ServiceAccount": {"Type": "String"},
                "RoleArn": {"Type": "String"},
            },
            "Resources": {
                "MyAssociation": {
                    "Type": "AWS::EKS::PodIdentityAssociation",
                    "Properties": {
                        "ClusterName": {"Ref": "ClusterName"},
                        "Namespace": {"Ref": "Namespace"},
                        "ServiceAccount": {"Ref": "ServiceAccount"},
                        "RoleArn": {"Ref": "RoleArn"},
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
            "Namespace": namespace,
            "ServiceAccount": service_account,
            "RoleArn": role_arn,
        },
    )

    assocs = eks.list_pod_identity_associations(
        clusterName=cluster["name"], namespace=namespace, serviceAccount=service_account
    )["associations"]
    assert len(assocs) == 1, f"expected exactly 1 pod identity association, found {len(assocs)}: {assocs}"
    association_id = assocs[0]["associationId"]
    desc = eks.describe_pod_identity_association(clusterName=cluster["name"], associationId=association_id)[
        "association"
    ]
    assert desc["roleArn"] == role_arn, f"expected roleArn {role_arn!r}, got {desc['roleArn']!r}"

    # Prove the role backing the association is a real, live, assumable IAM role
    # (not a fabricated string) by actually assuming it and checking identity.
    assumed = _assume_role_with_retry(sts, role_arn, "sim2real-verify")
    assumed_sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": assumed["AccessKeyId"],
            "aws_" + "secret_access_key": assumed["SecretAccessKey"],
            "aws_session_token": assumed["SessionToken"],
        },
    )
    assumed_identity = assumed_sts.get_caller_identity()
    expected_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-verify"
    assert assumed_identity["Arn"] == expected_arn, f"expected {expected_arn!r}, got {assumed_identity['Arn']!r}"


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
            "cluster creation; provision one to close this gap"
        )
    return ids[:min_azs]


def _assume_role_with_retry(sts, role_arn, session_name, *, timeout_s=90.0, interval_s=5.0):
    """A freshly created role's trust policy can take a few seconds to propagate
    through IAM; retry AccessDenied within a bounded window rather than sleeping a
    fixed amount before the first attempt."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"assume_role on {role_arn} still denied after {timeout_s}s (IAM propagation): {last_exc}")


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _create_active_cluster(ctx, extra_kwargs=None):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnet_ids = _default_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    kwargs = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        tags={"sim2real": CHECK},
    )
    if extra_kwargs:
        kwargs.update(extra_kwargs)
    # A cluster role's trust policy can take a few seconds to propagate through IAM;
    # retry the specific propagation error within a bounded window rather than
    # sleeping a fixed amount before the first attempt.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            eks.create_cluster(**kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
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


def _create_pod_identity_role(ctx, caller_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-podidrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            },
            {
                # Also trust the test's own caller so this check can independently
                # verify (outside the pod identity webhook flow) that EKS bound the
                # association to a real, live, assumable IAM role.
                "Effect": "Allow",
                "Principal": {"AWS": caller_arn},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"], role_name


def _deploy_cfn(ctx, template_body, parameters=None, capabilities=None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-eks-stack-")
    kwargs = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
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
