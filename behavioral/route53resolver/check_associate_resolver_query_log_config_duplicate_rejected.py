"""associate-resolver-query-log-config-duplicate-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-resolver-query-log-config-duplicate-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-associating a query log config with a VPC it is already associated with raises
    InvalidRequestException and leaves exactly one association; associating the same
    config with a different, fresh VPC succeeds."""
    r53r = ctx.client("route53resolver")

    log_group_arn = _create_log_group(ctx)
    config_id = _create_query_log_config(ctx, log_group_arn)

    vpc1 = _create_vpc(ctx, "10.81.0.0/16")
    assoc1 = r53r.associate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_id, ResourceId=vpc1
    )["ResolverQueryLogConfigAssociation"]
    assoc1_id = assoc1["Id"]
    ctx.on_cleanup(lambda: _disassociate_and_drain(r53r, config_id, vpc1))
    _wait_for_assoc_status(ctx, assoc1_id, {"ACTIVE"})

    code, message = _error_code(
        lambda: r53r.associate_resolver_query_log_config(
            ResolverQueryLogConfigId=config_id, ResourceId=vpc1
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = (
        "[RSLVR-01303] The specified resource is already associated with the specified query "
        "logging configuration."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    associations = r53r.list_resolver_query_log_config_associations(
        Filters=[{"Name": "ResourceId", "Values": [vpc1]}]
    )["ResolverQueryLogConfigAssociations"]
    assert len(associations) == 1, f"expected exactly 1 association for {vpc1}, got {len(associations)}"

    # Restore: disassociate, then the identical (config, vpc1) call succeeds again --
    # proving the rejection above was specific to the pre-existing association, not to
    # this config or this VPC being permanently unusable together.
    r53r.disassociate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_id, ResourceId=vpc1
    )
    _wait_for_association_count(ctx, config_id, 0)
    assoc1_retry = r53r.associate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_id, ResourceId=vpc1
    )["ResolverQueryLogConfigAssociation"]
    ctx.on_cleanup(lambda: _disassociate_and_drain(r53r, config_id, vpc1))
    final1_retry = _wait_for_assoc_status(ctx, assoc1_retry["Id"], {"ACTIVE"})
    assert final1_retry["ResourceId"] == vpc1

    # Positive control: the same config associated with a different, fresh VPC succeeds.
    vpc2 = _create_vpc(ctx, "10.82.0.0/16")
    assoc2 = r53r.associate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_id, ResourceId=vpc2
    )["ResolverQueryLogConfigAssociation"]
    assoc2_id = assoc2["Id"]
    ctx.on_cleanup(lambda: _disassociate_and_drain(r53r, config_id, vpc2))
    final2 = _wait_for_assoc_status(ctx, assoc2_id, {"ACTIVE"})
    assert final2["ResourceId"] == vpc2


def _error_code(fn):
    """Call fn(); return botocore Error.Code of the ClientError it raises. A call that
    succeeds fails the check: a target accepting what AWS refuses must not read as an
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), _without_trace_id(error.get("Message"))
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _retry_teardown(fn, *, timeout_s=240.0, **kwargs):
    """Teardown call retried while Resolver reports an association still in progress
    (InvalidRequestException); not-found counts as done."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "InvalidRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _disassociate_and_drain(r53r, config_id, resource_id, *, timeout_s=240.0):
    """Disassociate (config, resource) and wait until the association is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            r53r.disassociate_resolver_query_log_config(
                ResolverQueryLogConfigId=config_id, ResourceId=resource_id
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "InvalidRequestException" or time.monotonic() >= deadline:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"association {config_id}/{resource_id} never drained")
        time.sleep(5)


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("/sim2real-behav/r53r-")
    logs.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"][0]["arn"]


def _create_query_log_config(ctx, destination_arn: str) -> str:
    r53r = ctx.client("route53resolver")
    config = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-behav-qlc-"),
        DestinationArn=destination_arn,
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
    )["ResolverQueryLogConfig"]
    config_id = config["Id"]
    ctx.on_cleanup(
        lambda: _retry_teardown(r53r.delete_resolver_query_log_config, ResolverQueryLogConfigId=config_id)
    )
    return config_id


def _create_vpc(ctx, cidr: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _wait_for_association_count(ctx, config_id, expected, timeout_s=120.0):
    r53r = ctx.client("route53resolver")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = r53r.get_resolver_query_log_config(ResolverQueryLogConfigId=config_id)[
            "ResolverQueryLogConfig"
        ]["AssociationCount"]
        if last == expected:
            return last
        time.sleep(2.0)
    raise AssertionError(f"config {config_id} AssociationCount never reached {expected}, last={last}")


def _wait_for_assoc_status(ctx, assoc_id, ok_statuses, timeout_s=60.0):
    r53r = ctx.client("route53resolver")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = r53r.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc_id
        )["ResolverQueryLogConfigAssociation"]
        if last["Status"] in ok_statuses:
            return last
        time.sleep(1.5)
    raise AssertionError(f"association {assoc_id} never reached {ok_statuses}, last={last}")


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
