"""cancel-update-wrong-state-blocked."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cancel-update-wrong-state-blocked"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelUpdate on a Successful LoggingUpdate fails InvalidParameterException (only VersionRollback is
    cancellable), unlike an unknown updateId's ResourceNotFoundException; the update stays Successful and a
    fresh update still succeeds."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)
    cluster_key = _cluster_param(eks, "UpdateClusterConfig")

    # Drive a real, terminal update: enable the "api" control-plane log type.
    update_id = eks.update_cluster_config(
        **{cluster_key: cluster_name},
        logging={"clusterLogging": [{"types": ["api"], "enabled": True}]},
    )["update"]["id"]
    status = _wait_for_update_terminal(ctx, cluster_name, update_id)
    assert status == "Successful", f"setup update did not complete successfully: {status}"

    err = _error(lambda: eks.cancel_update(name=cluster_name, updateId=update_id))
    assert err == (
        "InvalidParameterException",
        "Update is not in a cancellable state. Supported update types: VersionRollback",
    ), f"expected InvalidParameterException, got {err}"

    # Distinct boundary: an unknown updateId on the same cluster is a 404, not the
    # unsupported-cancellation InvalidParameterException above.
    unknown_id = ctx.unique_name("sim2real-no-such-update-")
    unknown = _error(lambda: eks.cancel_update(name=cluster_name, updateId=unknown_id))
    assert unknown == ("ResourceNotFoundException", f"Update {unknown_id} not found"), (
        f"expected ResourceNotFoundException, got {unknown}"
    )

    # Effect absent: the update record is still Successful, not Cancelled.
    describe_key = _cluster_param(eks, "DescribeUpdate")
    after = eks.describe_update(**{describe_key: cluster_name}, updateId=update_id)["update"]
    assert after["status"] == "Successful", f"expected Successful, got {after['status']}"

    # Positive control: the update mechanism on this cluster still works -- a fresh,
    # legitimate config update is accepted.
    second_id = eks.update_cluster_config(
        **{cluster_key: cluster_name},
        logging={"clusterLogging": [{"types": ["api"], "enabled": False}]},
    )["update"]["id"]
    assert second_id != update_id, f"expected a new update id, got the same id back: {second_id}"
    second_status = _wait_for_update_terminal(ctx, cluster_name, second_id)
    assert second_status == "Successful", f"expected Successful, got {second_status}"


def _wait_for_update_terminal(ctx, cluster_name: str, update_id: str, timeout_s: float = 10 * 60) -> str:
    eks = ctx.client("eks")
    describe_key = _cluster_param(eks, "DescribeUpdate")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = eks.describe_update(**{describe_key: cluster_name}, updateId=update_id)["update"]["status"]
        if status in ("Successful", "Failed", "Cancelled"):
            return status
        time.sleep(2)
    raise AssertionError(f"update {update_id} never reached a terminal state within {timeout_s}s")


# ===== helpers =====

def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS rejects must not be mistaken for a
    code-mismatch assertion against a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _cluster_param(client, op_name: str) -> str:
    shape = client.meta.service_model.operation_model(op_name).input_shape
    members = shape.members if shape else {}
    for candidate in ("clusterName", "name"):
        if candidate in members:
            return candidate
    raise AssertionError(f"no cluster-name member found for operation {op_name}")


def _default_vpc_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account/region has no shared network VPC to provision a test EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    ids = list(by_az.values())[:3]
    if len(ids) < 2:
        raise AssertionError("shared network lacks subnets in >=2 availability zones")
    return ids


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_active_cluster(ctx, timeout_s: float = 20 * 60) -> str:
    eks = ctx.client("eks")
    subnet_ids = _default_vpc_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    # The just-created role is rejected until IAM propagates it: retry every 2 s up to 72 s,
    # capped by the run's remaining time.
    retry_deadline = time.monotonic() + 72.0
    left = ctx.time_left()
    if left is not None:
        retry_deadline = min(retry_deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidParameterException", "ClientException"):
                raise
            if time.monotonic() >= retry_deadline:
                raise AssertionError(f"create_cluster never succeeded (IAM role propagation?): {exc}") from exc
        time.sleep(2)
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == "ACTIVE":
            return name
        if status == "FAILED":
            raise AssertionError(f"cluster {name} reached FAILED status while provisioning")
        time.sleep(2)
    raise AssertionError(f"cluster {name} did not become ACTIVE within {timeout_s}s")



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
