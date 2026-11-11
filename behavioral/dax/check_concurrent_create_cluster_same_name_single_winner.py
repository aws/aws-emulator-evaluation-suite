"""concurrent-create-cluster-same-name-single-winner."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-cluster-same-name-single-winner"
GROUP = "concurrency"
SERVICES = ["dax"]

_NODE_TYPE = "dax.t3.small"
_TIMEOUT_S = 1500.0
_RACERS = 5


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """When multiple CreateCluster calls race on the exact same ClusterName, exactly
    one wins and provisions a cluster; every other racer is rejected with
    ClusterAlreadyExistsFault, never with a silent duplicate creation."""
    dax = ctx.client("dax")
    role_arn = _create_dax_service_role(ctx)
    subnet_ids = _default_vpc_subnet_ids(ctx, count=2)
    subnet_group_name = _create_subnet_group(ctx, subnet_ids)
    cluster_name = ctx.unique_name("sim2real-dax-race-")
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_name))

    def _racer(_i):
        # DAX validates IamRoleArn/SubnetGroupName synchronously inside CreateCluster. A role or
        # subnet group created moments earlier may not yet be visible to the DAX control plane,
        # which surfaces as InvalidParameterValueException -- a transient readiness failure, not a
        # losing racer. Retry that specific code, bounded by a deadline, instead of guessing a
        # fixed pre-race sleep window.
        deadline = time.monotonic() + 30.0
        while True:
            try:
                dax.create_cluster(
                    ClusterName=cluster_name,
                    NodeType=_NODE_TYPE,
                    ReplicationFactor=1,
                    IamRoleArn=role_arn,
                    SubnetGroupName=subnet_group_name,
                    Tags=[{"Key": "sim2real", "Value": "true"}],
                )
                return ("ok", None, None)
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code == "InvalidParameterValueException" and time.monotonic() < deadline:
                    time.sleep(2.0)
                    continue
                return ("error", code, err.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        results = list(pool.map(_racer, range(_RACERS)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert len(failures) == _RACERS - 1, f"expected {_RACERS - 1} losing racers, got {len(failures)}: {results}"
    for _status, code, message in failures:
        assert code == "ClusterAlreadyExistsFault", f"expected ClusterAlreadyExistsFault for a losing racer, got {code}"
        assert message == "Cluster with specified name already exists.", (
            f"unexpected message for a losing racer: {message!r}"
        )

    # Exactly one cluster exists under this name -- no silent duplicate.
    matches = dax.describe_clusters(ClusterNames=[cluster_name])["Clusters"]
    assert len(matches) == 1, f"expected exactly one cluster named {cluster_name!r}, got {len(matches)}: {matches}"


def _cluster_gone(dax, cluster_name):
    """Existence probe: True once DescribeClusters reports ClusterNotFoundFault."""
    try:
        dax.describe_clusters(ClusterNames=[cluster_name])
    except ClientError as err:
        return err.response["Error"]["Code"] == "ClusterNotFoundFault"
    return False


def _role_policy_visible(iam, role_name, policy_name):
    """Readiness probe: True once GetRolePolicy returns the inline policy, False on NoSuchEntity."""
    try:
        iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
        return False
    return True


def _describe_cluster(ctx, cluster_name):
    return ctx.client("dax").describe_clusters(ClusterNames=[cluster_name])["Clusters"][0]


def _poll_until(probe, predicate, timeout_s, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _default_vpc_subnet_ids(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for DAX subnet group creation")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if len(subnets) < count:
        raise AssertionError(f"shared network has fewer than {count} subnets available")
    return [s["SubnetId"] for s in subnets[:count]]


def _create_subnet_group(ctx, subnet_ids):
    dax = ctx.client("dax")
    name = ctx.unique_name("sim2real-dax-sng-")
    dax.create_subnet_group(SubnetGroupName=name, SubnetIds=subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_subnet_group(ctx, name))
    return name


def _safe_delete_subnet_group(ctx, name):
    try:
        ctx.client("dax").delete_subnet_group(SubnetGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ServiceLinkedRoleNotFoundFault",
            "SubnetGroupNotFoundFault",
        ):
            raise


def _create_dax_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dax-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "dax.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    access_policy = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}]}
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    iam.put_role_policy(RoleName=role_name, PolicyName="dax-dynamodb-access", PolicyDocument=access_policy)

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="dax-dynamodb-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    # Confirm IAM's own read-after-write consistency for the role and its inline policy before
    # handing the ARN to the race -- a bounded check, not a guess at a fixed propagation window.
    _poll_until(
        lambda: _role_policy_visible(iam, role_name, "dax-dynamodb-access"),
        lambda visible: visible,
        timeout_s=30.0,
        interval_s=2.0,
    )
    return role["Arn"]


def _safe_delete_cluster(ctx, cluster_name, timeout_s=_TIMEOUT_S):
    dax = ctx.client("dax")
    if _cluster_gone(dax, cluster_name):
        return
    try:
        _poll_until(
            lambda: _describe_cluster(ctx, cluster_name),
            lambda c: c["Status"] == "available",
            timeout_s=timeout_s,
        )
    except AssertionError:
        pass
    try:
        dax.delete_cluster(ClusterName=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundFault",
            "ServiceLinkedRoleNotFoundFault",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
