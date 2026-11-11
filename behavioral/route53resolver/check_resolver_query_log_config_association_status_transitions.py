"""resolver-query-log-config-association-status-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resolver-query-log-config-association-status-transitions"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A query log config association reaches ACTIVE after AssociateResolverQueryLogConfig, and
    after DisassociateResolverQueryLogConfig GetResolverQueryLogConfigAssociation answers
    ResourceNotFoundException.
    """
    ec2 = ctx.client("ec2")
    logs = ctx.client("logs")
    r53r = ctx.client("route53resolver")

    vpc_id = _create_vpc(ctx, ec2, "10.92.0.0/16")

    log_group_name = ctx.unique_name("/sim2real/r53r-qlcassoc-")
    logs.create_log_group(
        logGroupName=log_group_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    destination_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]

    config_id = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-qlcassoc-cfg-")[:64],
        DestinationArn=destination_arn,
        CreatorRequestId=ctx.unique_name("sim2real-qlcassoc-cfg-req-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["ResolverQueryLogConfig"]["Id"]
    ctx.on_cleanup(
        lambda: _safe(lambda: r53r.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id))
    )

    assoc_id = r53r.associate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_id, ResourceId=vpc_id
    )["ResolverQueryLogConfigAssociation"]["Id"]

    status = _poll_until(
        lambda: r53r.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc_id
        )["ResolverQueryLogConfigAssociation"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert status == "ACTIVE", f"association reached {status}, not ACTIVE"

    r53r.disassociate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_id, ResourceId=vpc_id
    )
    _poll_until(
        lambda: _absent(
            lambda: r53r.get_resolver_query_log_config_association(
                ResolverQueryLogConfigAssociationId=assoc_id
            )
        ),
        lambda gone: gone,
        timeout_s=180,
        interval_s=5,
    )
    gone_message = (
        "[RSLVR-01602] The specified query logging configuration association doesn't exist."
    )
    gone_read_code, gone_read_message = _error(
        lambda: r53r.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc_id
        )
    )
    assert (gone_read_code, gone_read_message) == ("ResourceNotFoundException", gone_message), (
        f"expected ResourceNotFoundException {gone_message!r} after disassociate, got {(gone_read_code, gone_read_message)!r}"
    )

    # The association is not just unreadable -- it is unusable. A second disassociate on the
    # same (config, resource) pair has nothing left to act on and must fail the same way.
    redisassociate_code, redisassociate_message = _error(
        lambda: r53r.disassociate_resolver_query_log_config(
            ResolverQueryLogConfigId=config_id, ResourceId=vpc_id
        )
    )
    assert (redisassociate_code, redisassociate_message) == ("ResourceNotFoundException", gone_message), (
        "expected a second disassociate on the now-gone association to raise "
        f"ResourceNotFoundException {gone_message!r}, got {(redisassociate_code, redisassociate_message)!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _absent(fn) -> bool:
    """True once fn() raises ResourceNotFoundException, False while it still succeeds."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise
    return False


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_vpc(ctx, ec2, cidr: str) -> str:
    """A fresh VPC owned by this check, deleted at teardown."""
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))
    return vpc_id


def _delete_vpc(ec2, vpc_id: str, *, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """Retry while an association the check just removed still holds the VPC."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidVpcID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
