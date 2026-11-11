"""list-associated-access-policies-unknown-entry-not-found."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-associated-access-policies-unknown-entry-not-found"
GROUP = "error-semantics"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAssociatedAccessPolicies for a principal that has no access entry on an
    otherwise-real, existing cluster is rejected with ResourceNotFoundException, while
    the same call for a principal that DOES have an access entry succeeds."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    with_entry_principal = _create_iam_role(ctx, "with-entry")
    without_entry_principal = _create_iam_role(ctx, "no-entry")

    _create_access_entry_with_retry(ctx, cluster_name, with_entry_principal)
    ctx.on_cleanup(
        lambda: eks.delete_access_entry(clusterName=cluster_name, principalArn=with_entry_principal)
    )

    code, message = _error_detail(
        lambda: eks.list_associated_access_policies(
            clusterName=cluster_name, principalArn=without_entry_principal
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = "The requested resource does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    entries = eks.list_access_entries(clusterName=cluster_name)["accessEntries"]
    assert without_entry_principal not in entries, (
        f"expected {without_entry_principal!r} absent from access entries, found in {entries!r}"
    )

    # positive control: the identical call against a principal that DOES have an access
    # entry succeeds (empty policy list, since none has been associated).
    ok = eks.list_associated_access_policies(clusterName=cluster_name, principalArn=with_entry_principal)
    assert ok["associatedAccessPolicies"] == [], (
        f"expected no associated policies, got {ok['associatedAccessPolicies']!r}"
    )
    assert ok["principalArn"] == with_entry_principal, (
        f"expected principalArn {with_entry_principal!r}, got {ok['principalArn']!r}"
    )


def _create_access_entry_with_retry(ctx, cluster_name: str, principal_arn: str) -> None:
    # A freshly created IAM role can take a few seconds to propagate before EKS's
    # access-entry principal validation recognizes it; retry through that window.
    eks = ctx.client("eks")
    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            eks.create_access_entry(clusterName=cluster_name, principalArn=principal_arn)
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"create_access_entry kept failing (likely IAM propagation lag): {last_exc}")


def _error_detail(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last!r}")


def _default_vpc_subnets(ctx, min_subnets: int = 2) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host a test EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < min_subnets:
        raise AssertionError("shared network lacks subnets in enough distinct AZs for an EKS cluster")
    return subnet_ids[:3]


def _create_eks_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup() -> None:
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
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn


def _create_active_cluster(ctx, version: str | None = None) -> str:
    eks = ctx.client("eks")
    subnet_ids = _default_vpc_subnets(ctx)
    role_arn = _create_eks_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    kwargs: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "resourcesVpcConfig": {"subnetIds": subnet_ids},
        # CreateAccessEntry (and thus ListAssociatedAccessPolicies, which this check
        # exercises) requires an authentication mode of API or API_AND_CONFIG_MAP.
        "accessConfig": {"authenticationMode": "API"},
    }
    if version:
        kwargs["version"] = version

    deadline = time.monotonic() + 90.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(**kwargs)
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    else:
        raise AssertionError(f"create_cluster kept failing (likely IAM role trust propagation lag): {last_exc}")

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster}")
    return name


def _create_iam_role(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-principal-{suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))

    def _cleanup() -> None:
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]



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
