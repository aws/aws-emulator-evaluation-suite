"""cancel-update-on-terminal-state-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cancel-update-on-terminal-state-rejected"
GROUP = "state-machine"
SERVICES = ["eks"]


_NOT_CANCELLABLE = (
    "InvalidParameterException",
    "Update is not in a cancellable state. Supported update types: VersionRollback",
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelUpdate on a Successful LoggingUpdate fails InvalidParameterException (only VersionRollback
    updates are cancellable); the applied config stays and a fresh update on the cluster still completes."""
    eks = ctx.client("eks")
    cluster = _ensure_active_cluster(ctx)
    name = cluster["name"]

    enable_resp = eks.update_cluster_config(
        name=name, logging={"clusterLogging": [{"types": ["api"], "enabled": True}]}
    )
    enable_update_id = enable_resp["update"]["id"]
    enable_update = _wait_update_terminal(ctx, name, enable_update_id)
    assert enable_update["status"] == "Successful", enable_update

    code = _expect_error(lambda: eks.cancel_update(name=name, updateId=enable_update_id))
    assert code == _NOT_CANCELLABLE, (
        f"expected InvalidParameterException cancelling a completed LoggingUpdate, got {code}"
    )

    logging_after = eks.describe_cluster(name=name)["cluster"]["logging"]
    api_enabled = any(
        "api" in cfg.get("types", []) and cfg.get("enabled")
        for cfg in logging_after.get("clusterLogging", [])
    )
    assert api_enabled, "the already-applied logging change was reverted by the rejected cancel attempt"

    disable_resp = eks.update_cluster_config(
        name=name, logging={"clusterLogging": [{"types": ["api"], "enabled": False}]}
    )
    disable_update = _wait_update_terminal(ctx, name, disable_resp["update"]["id"])
    assert disable_update["status"] == "Successful", disable_update


# ===== helpers =====

def _expect_error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises, because
    an over-permissive target accepting what real AWS refuses must not be mistaken for a
    code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_update_terminal(ctx, cluster_name: str, update_id: str, timeout_s: float = 600.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    update: dict[str, Any] = {}
    while time.monotonic() < deadline:
        update = eks.describe_update(name=cluster_name, updateId=update_id)["update"]
        if update["status"] in ("Successful", "Failed", "Cancelled"):
            return update
        time.sleep(2)
    raise AssertionError(f"update {update_id} did not reach a terminal state within {timeout_s}s")


def _ensure_active_cluster(ctx) -> dict[str, str]:
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    eks = ctx.client("eks")

    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host a test EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:3]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network lacks subnets in >=2 AZs required to create an EKS cluster")

    cluster_name = ctx.unique_name("sim2real-eks-")
    # The just-created role is rejected until IAM propagates it: retry every 2 s up to 80 s,
    # capped by the run's remaining time.
    deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)

    def _cleanup_cluster():
        try:
            eks.delete_cluster(name=cluster_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        deadline = time.monotonic() + 15 * 60
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=cluster_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            time.sleep(15)

    ctx.on_cleanup(_cleanup_cluster)

    deadline = time.monotonic() + 25 * 60
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = eks.describe_cluster(name=cluster_name)["cluster"]
        if desc["status"] == "ACTIVE":
            return {"name": cluster_name, "arn": desc["arn"], "role_arn": role_arn, "version": desc["version"]}
        if desc["status"] == "FAILED":
            raise AssertionError(f"cluster {cluster_name} entered FAILED state while creating: {desc}")
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_name} did not become ACTIVE within timeout: {desc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
