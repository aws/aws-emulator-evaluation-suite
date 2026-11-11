"""query-log-config-association-status-transition-delay."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-log-config-association-status-transition-delay"
GROUP = "visibility-timeout-ttl"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateResolverQueryLogConfig returns the association in CREATING, not ACTIVE.

    Polling GetResolverQueryLogConfigAssociation then reports ACTIVE for the same config and VPC.
    """
    r53r = ctx.client("route53resolver")
    ec2 = ctx.client("ec2")
    logs = ctx.client("logs")

    log_group_name = ctx.unique_name("/sim2real/r53r-qlog-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _safe_delete_log_group(logs, log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]

    config_id = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-qlogcfg-")[:64],
        DestinationArn=log_group_arn,
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crqlc-"),
    )["ResolverQueryLogConfig"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_query_log_config(r53r, config_id))
    _poll_until(
        lambda: r53r.get_resolver_query_log_config(ResolverQueryLogConfigId=config_id)["ResolverQueryLogConfig"],
        lambda c: c["Status"] == "CREATED",
        timeout_s=60,
        interval_s=2,
    )

    vpc_id = _create_vpc(ctx, ec2)

    assoc = r53r.associate_resolver_query_log_config(ResolverQueryLogConfigId=config_id, ResourceId=vpc_id)[
        "ResolverQueryLogConfigAssociation"
    ]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: _safe_disassociate(r53r, config_id, vpc_id))

    assert assoc["Status"] == "CREATING", f"expected initial Status=CREATING, got {assoc['Status']!r}"
    assert assoc["ResolverQueryLogConfigId"] == config_id, assoc
    assert assoc["ResourceId"] == vpc_id, assoc

    settled = _poll_until(
        lambda: r53r.get_resolver_query_log_config_association(ResolverQueryLogConfigAssociationId=assoc_id)[
            "ResolverQueryLogConfigAssociation"
        ],
        lambda a: a["Status"] in ("ACTIVE", "FAILED", "ACTION_NEEDED"),
        timeout_s=120,
        interval_s=3,
    )
    assert settled["Status"] == "ACTIVE", f"expected eventual Status=ACTIVE, got {settled['Status']!r}"
    assert settled["ResolverQueryLogConfigId"] == config_id, settled
    assert settled["ResourceId"] == vpc_id, settled


def _safe_delete_log_group(logs, log_group_name):
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except logs.exceptions.ResourceNotFoundException:
        pass


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _create_vpc(ctx, ec2):
    name = ctx.unique_name("sim2real-r53r-vpc-")
    resp = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _safe_disassociate(r53r, config_id, vpc_id):
    """Disassociate and wait until no association remains, so the config and VPC can be deleted."""
    try:
        r53r.disassociate_resolver_query_log_config(ResolverQueryLogConfigId=config_id, ResourceId=vpc_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    _poll_until(
        lambda: r53r.list_resolver_query_log_config_associations(
            Filters=[{"Name": "ResourceId", "Values": [vpc_id]}]
        )["ResolverQueryLogConfigAssociations"],
        lambda items: not items,
        timeout_s=300,
        interval_s=5,
    )


def _safe_delete_query_log_config(r53r, config_id):
    try:
        r53r.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
