"""associate-resolver-query-log-config-nonexistent-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-resolver-query-log-config-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateResolverQueryLogConfig with a query log config id that does not exist
    is rejected with ResourceNotFoundException rather than creating a dangling
    association, while associating a real config for the same VPC succeeds."""
    r53r = ctx.client("route53resolver")
    ec2 = ctx.client("ec2")

    vpc_name = ctx.unique_name("sim2real-r53r-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    fake_config_id = "rqlc-" + "0123456789abcdef0"
    code, message = _error(
        lambda: r53r.associate_resolver_query_log_config(
            ResolverQueryLogConfigId=fake_config_id, ResourceId=vpc_id
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = "[RSLVR-01601] The specified query logging configuration doesn't exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    dangling = _list_associations_for_vpc(r53r, vpc_id)
    assert dangling == [], f"nonexistent config association leaked a dangling association: {dangling}"

    real_config_id = _create_query_log_config(ctx, r53r)
    assoc = r53r.associate_resolver_query_log_config(
        ResolverQueryLogConfigId=real_config_id, ResourceId=vpc_id
    )["ResolverQueryLogConfigAssociation"]
    ctx.on_cleanup(
        lambda: _disassociate_best_effort(r53r, real_config_id, vpc_id)
    )
    assert assoc["Status"] == "CREATING", assoc["Status"]
    assert assoc["ResourceId"] == vpc_id
    assert assoc["ResolverQueryLogConfigId"] == real_config_id

    visible = [a for a in _list_associations_for_vpc(r53r, vpc_id) if a["Id"] == assoc["Id"]]
    assert len(visible) == 1, (
        f"association {assoc['Id']} not visible via an independent list read: {visible}"
    )
    assert visible[0]["ResolverQueryLogConfigId"] == real_config_id
    assert visible[0]["Status"] in ("CREATING", "ACTIVE"), visible[0]["Status"]

    settled = _poll_association(r53r, assoc["Id"])
    assert settled["Status"] == "ACTIVE", (
        f"the real association settled in {settled['Status']!r}, expected ACTIVE: {settled!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), _without_trace_id(err.get("Message"))
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_association(r53r, assoc_id: str, timeout_s: float = 180.0, interval_s: float = 3.0):
    """Read the association until it leaves CREATING; raise when the deadline passes first."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = r53r.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc_id
        )["ResolverQueryLogConfigAssociation"]
        if last["Status"] != "CREATING":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"association {assoc_id} never left CREATING within {timeout_s}s: {last!r}")


def _list_associations_for_vpc(r53r, vpc_id: str):
    out = []
    next_token = None
    while True:
        kwargs = {"Filters": [{"Name": "ResourceId", "Values": [vpc_id]}]}
        if next_token:
            kwargs["NextToken"] = next_token
        page = r53r.list_resolver_query_log_config_associations(**kwargs)
        out.extend(page.get("ResolverQueryLogConfigAssociations", []))
        next_token = page.get("NextToken")
        if not next_token:
            return out


def _create_query_log_config(ctx, r53r):
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("/sim2real/r53r-qlc-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]

    config = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-qlc-"),
        DestinationArn=log_group_arn,
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
    )["ResolverQueryLogConfig"]
    config_id = config["Id"]
    ctx.on_cleanup(lambda: _delete_query_log_config_best_effort(r53r, config_id))
    return config_id


def _delete_query_log_config_best_effort(r53r, config_id: str) -> None:
    try:
        r53r.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id)
    except (r53r.exceptions.ResourceNotFoundException, r53r.exceptions.InvalidRequestException):
        pass


def _disassociate_best_effort(r53r, config_id: str, vpc_id: str) -> None:
    """Disassociate and wait until the association is gone, so the config and VPC can be deleted."""
    try:
        r53r.disassociate_resolver_query_log_config(ResolverQueryLogConfigId=config_id, ResourceId=vpc_id)
    except r53r.exceptions.ResourceNotFoundException:
        return
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if not _list_associations_for_vpc(r53r, vpc_id):
            return
        time.sleep(5)
    raise RuntimeError(
        f"query log config association {config_id}/{vpc_id} never disappeared"
    )


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
