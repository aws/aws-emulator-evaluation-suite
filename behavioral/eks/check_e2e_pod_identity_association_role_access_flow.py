"""e2e-pod-identity-association-role-access-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pod-identity-association-role-access-flow"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:e2e", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Assuming the role of a pod identity association yields a GetCallerIdentity of that
    role, and once the association is deleted EKS keeps no live record granting the
    namespace/service-account access through it."""
    eks = ctx.client("eks")
    sts = ctx.client("sts")
    cluster = _create_active_cluster(ctx)
    caller_arn = sts.get_caller_identity()["Arn"]
    role_arn, role_name = _create_pod_identity_role(ctx, caller_arn)

    namespace = "default"
    service_account = ctx.unique_name("sim2real-sa-")
    created = eks.create_pod_identity_association(
        clusterName=cluster["name"], namespace=namespace, serviceAccount=service_account, roleArn=role_arn
    )["association"]
    association_id = created["associationId"]

    desc = eks.describe_pod_identity_association(clusterName=cluster["name"], associationId=association_id)[
        "association"
    ]
    assert desc["roleArn"] == role_arn, desc["roleArn"]
    assert desc["namespace"] == namespace, desc["namespace"]
    assert desc["serviceAccount"] == service_account, desc["serviceAccount"]

    # The role EKS bound the association to is a real, live, assumable IAM role. A freshly
    # created role's trust policy can take a few seconds to propagate through IAM, so retry
    # AccessDenied within a bounded window rather than sleeping a fixed amount up front.
    def _try_assume():
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-verify")
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                return None
            raise

    assumed = _wait_for(
        _try_assume,
        lambda r: r is not None,
        timeout_s=180.0,
        interval_s=5.0,
        desc="assume pod identity role (IAM propagation)",
    )["Credentials"]
    assumed_sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": assumed["AccessKeyId"],
            "aws_secret_access_key": assumed["SecretAccessKey"],
            "aws_session_token": assumed["SessionToken"],
        },
    )
    identity = assumed_sts.get_caller_identity()
    assert identity["Arn"].endswith(f"assumed-role/{role_name}/sim2real-verify"), identity["Arn"]

    # Delete the association: EKS's own record granting this namespace/service-account
    # access through pod identity must disappear (this is the authoritative signal we
    # can observe without a live pod exercising the webhook injection path).
    eks.delete_pod_identity_association(clusterName=cluster["name"], associationId=association_id)

    code, message = _error(
        lambda: eks.describe_pod_identity_association(clusterName=cluster["name"], associationId=association_id)
    )
    assert code == "ResourceNotFoundException", code
    assert message == f"No service account role association found for ID: {association_id}", message

    remaining = eks.list_pod_identity_associations(
        clusterName=cluster["name"], namespace=namespace, serviceAccount=service_account
    )["associations"]
    assert remaining == [], remaining


def _error(fn):
    """The (code, message) fn() raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last}")


def _wait_for(fn, predicate, *, timeout_s, interval_s, desc=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last!r}")


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


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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
    kwargs = dict(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
    if extra_kwargs:
        kwargs.update(extra_kwargs)

    # A freshly created cluster role's trust policy can take a few seconds to propagate
    # through IAM; retry the specific propagation-lag errors within a bounded window
    # rather than sleeping a fixed amount before the first attempt.
    left = ctx.time_left()
    create_deadline = time.monotonic() + (80.0 if left is None else min(80.0, left))
    while True:
        try:
            eks.create_cluster(**kwargs)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("ClientException", "InvalidParameterException"):
                raise
            if time.monotonic() >= create_deadline:
                raise AssertionError(f"create_cluster never succeeded after IAM propagation retries: {e}") from e
            time.sleep(2)

    ctx.on_cleanup(lambda: eks.delete_cluster(name=name))
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
                "Effect": "Allow",
                "Principal": {"AWS": caller_arn},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"], role_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
