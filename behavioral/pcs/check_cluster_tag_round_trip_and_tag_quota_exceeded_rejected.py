"""cluster-tag-round-trip-and-tag-quota-exceeded-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-tag-round-trip-and-tag-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["pcs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource, ListTagsForResource and UntagResource round-trip on an ACTIVE cluster; at the 50-tag
    limit one more TagResource gets ServiceQuotaExceededException with its exact message and leaves the
    tags unchanged, and after an untag it succeeds."""
    pcs = ctx.client("pcs")
    subnet_id, security_group_id = _get_default_vpc_networking(ctx)
    cluster_name = ctx.unique_name("sim2real-tagquota").replace("_", "-")

    create_resp = pcs.create_cluster(
        clusterName=cluster_name,
        scheduler={"type": "SLURM", "version": "25.05"},
        size="SMALL",
        networking={"subnetIds": [subnet_id], "securityGroupIds": [security_group_id]},
    )
    cluster_id = create_resp["cluster"]["id"]
    cluster_arn = create_resp["cluster"]["arn"]
    ctx.on_cleanup(lambda: _delete_cluster_best_effort(ctx, cluster_id))

    cluster = _poll_until(
        lambda: pcs.get_cluster(clusterIdentifier=cluster_id)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=2400.0,
        interval_s=20.0,
    )
    assert cluster["status"] == "ACTIVE", f"cluster reached {cluster['status']} instead of ACTIVE"

    # --- basic round trip ---
    pcs.tag_resource(resourceArn=cluster_arn, tags={"sim2real-k1": "v1"})
    tags1 = pcs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert tags1.get("sim2real-k1") == "v1"

    pcs.untag_resource(resourceArn=cluster_arn, tagKeys=["sim2real-k1"])
    tags2 = pcs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert "sim2real-k1" not in tags2

    # --- fill up to the 50-user-tag-per-resource limit, 10 at a time ---
    # Measured on real AWS: TagResource rejects once the resultant PERSISTED set on the
    # resource exceeds 50 user tags ("The resultant tag set must not have more than 50
    # user tags"). That is a distinct, tighter constraint than RequestTagMap's modelled
    # smithy.api#length max=200, which only bounds one call's own tags map.
    total_target = 50
    per_call = 10
    written = 0
    while written < total_target:
        batch = {f"sim2real-fill-{written + i}": "x" for i in range(per_call)}
        pcs.tag_resource(resourceArn=cluster_arn, tags=batch)
        written += per_call

    tags_full = pcs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    fill_tag_count = sum(1 for k in tags_full if k.startswith("sim2real-fill-"))
    assert fill_tag_count == total_target, f"expected {total_target} fill tags, found {fill_tag_count}"

    # --- one more tag beyond the limit is rejected ---
    code = message = None
    try:
        pcs.tag_resource(resourceArn=cluster_arn, tags={"sim2real-overflow": "x"})
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
    assert code == "ServiceQuotaExceededException", f"expected ServiceQuotaExceededException, got {code}"
    expected_message = "The resultant tag set must not have more than 50 user tags."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the overflow tag was never persisted, count is unchanged.
    tags_after_overflow = pcs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert "sim2real-overflow" not in tags_after_overflow
    assert len(tags_after_overflow) == total_target

    # Positive control: freeing a slot makes room for a new tag again.
    pcs.untag_resource(resourceArn=cluster_arn, tagKeys=["sim2real-fill-0"])
    pcs.tag_resource(resourceArn=cluster_arn, tags={"sim2real-overflow": "x"})
    tags_final = pcs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert tags_final.get("sim2real-overflow") == "x"
    assert "sim2real-fill-0" not in tags_final


def _get_default_vpc_networking(ctx) -> tuple[str, str]:
    """(subnet_id, security_group_id) for the run's shared network.

    PCS's CreateCluster rejects networking.securityGroupIds when absent
    (ValidationException: "1 or more required parameters are missing"), even though
    the Smithy model does not mark it `required` -- real AWS enforces it server-side.
    """
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("account has no shared network VPC to source networking for PCS")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError("shared network has no subnets to source for PCS networking config")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError("shared network has no default security group to source for PCS networking config")
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _get_cluster_or_none(pcs, cluster_id):
    try:
        return pcs.get_cluster(clusterIdentifier=cluster_id)["cluster"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _delete_cluster_best_effort(ctx, cluster_id, timeout_s=2400.0, interval_s=20.0) -> None:
    pcs = ctx.client("pcs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = _get_cluster_or_none(pcs, cluster_id)
        if cluster is None:
            return
        if cluster["status"] in ("ACTIVE", "SUSPENDED", "CREATE_FAILED"):
            try:
                pcs.delete_cluster(clusterIdentifier=cluster_id)
            except ClientError as e:
                if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
                    raise
            return
        if cluster["status"] == "DELETING":
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
