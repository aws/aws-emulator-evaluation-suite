"""untag-missing-tag-key-error."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-missing-tag-key-error"
GROUP = "tagging"
SERVICES = ["dax"]

_NODE_TYPE = "dax.t3.small"
_TIMEOUT_S = 1500.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with an unattached key fails with TagNotFoundFault "Failing request. These tags are not
    present : does-not-exist" and keeps the real tag, while untagging the real key removes it."""
    dax = ctx.client("dax")
    role_arn = _create_dax_service_role(ctx)
    subnet_ids = _default_vpc_subnet_ids(ctx, count=2)
    subnet_group_name = _create_subnet_group(ctx, subnet_ids)
    cluster_name = ctx.unique_name("sim2real-dax-cl-")

    cluster = _create_cluster_with_role_propagation_retry(
        ctx,
        ClusterName=cluster_name,
        NodeType=_NODE_TYPE,
        ReplicationFactor=1,
        IamRoleArn=role_arn,
        SubnetGroupName=subnet_group_name,
    )
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_name))
    cluster_arn = cluster["ClusterArn"]

    _poll_until(
        lambda: _describe_cluster(ctx, cluster_name),
        lambda c: c["Status"] == "available",
        timeout_s=_TIMEOUT_S,
    )

    dax.tag_resource(ResourceName=cluster_arn, Tags=[{"Key": "env", "Value": "sim2real"}])

    code, message = _expect_error(lambda: dax.untag_resource(ResourceName=cluster_arn, TagKeys=["does-not-exist"]))
    assert code == "TagNotFoundFault", f"unexpected code: {code!r}"
    assert message == "Failing request. These tags are not present : does-not-exist", (
        f"unexpected message: {message!r}"
    )

    tags_after_failure = {t["Key"]: t["Value"] for t in dax.list_tags(ResourceName=cluster_arn)["Tags"]}
    assert tags_after_failure.get("env") == "sim2real"

    dax.untag_resource(ResourceName=cluster_arn, TagKeys=["env"])
    tags_final = {t["Key"]: t["Value"] for t in dax.list_tags(ResourceName=cluster_arn)["Tags"]}
    assert "env" not in tags_final


def _expect_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _cluster_gone(dax, cluster_name):
    """Existence probe: True once DescribeClusters reports ClusterNotFoundFault."""
    try:
        dax.describe_clusters(ClusterNames=[cluster_name])
    except ClientError as err:
        return err.response["Error"]["Code"] == "ClusterNotFoundFault"
    return False


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


def _create_cluster_with_role_propagation_retry(ctx, timeout_s=90.0, **kwargs):
    """create_cluster can reject a freshly created IAM role with
    InvalidParameterValueException ("...cannot be assumed...") until the role has
    propagated; retry the create call itself against that specific condition,
    bounded, rather than sleeping blind before the first attempt."""
    dax = ctx.client("dax")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return dax.create_cluster(**kwargs)["Cluster"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "assum" in message.lower():
                last_err = err
                time.sleep(5.0)
                continue
            raise
    raise AssertionError(f"create_cluster never succeeded (role propagation timeout); last error={last_err}")


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]
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
