"""associate-disassociate-query-log-config."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "associate-disassociate-query-log-config"
GROUP = 'query-log-config'
SERVICES = ['route53resolver']

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

def _try(fn, **kwargs):
    """Delete; True once done or already gone, False while a dependency still holds it."""
    try:
        fn(**kwargs)
        return True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if "NotFound" in code:
            return True
        if code == "DependencyViolation":
            return False
        raise


def _wait_until(probe, timeout_s=120.0, interval_s=2.0):
    """Poll probe() until truthy; raise when the deadline passes first."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    raise AssertionError(f"teardown condition not met within {timeout_s}s")


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _account_id(ctx):
    return ctx.account


def _create_log_group_arn(ctx):
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-r53r-behavioral-")
    logs.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return f"arn:aws:logs:{ctx.region}:{_account_id(ctx)}:log-group:{name}:*"


def _create_test_vpc_with_subnets(ctx, subnet_count=2):
    """Return (vpc_id, [subnet_ids], sg_id) usable for resolver testing.

    Creates a dedicated VPC, its subnets and a security group, each registered
    for teardown, so the check never depends on an account default.
    """
    ec2 = ctx.client("ec2")
    subnet_ids = []
    vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda v=vpc_id: _wait_until(lambda: _try(ec2.delete_vpc, VpcId=v), timeout_s=120)
    )
    try:
        ec2.create_tags(
            Resources=[vpc_id],
            Tags=TAGS_KV + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        )
    except Exception:
        pass

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
            ]
        )["AvailabilityZones"]
    ][:subnet_count]
    if len(azs) < subnet_count:
        raise AssertionError(
            f"region {ctx.region} exposes only {len(azs)} usable AZs, need {subnet_count}"
        )
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.90.{i}.0/24", AvailabilityZone=az
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(
            lambda s=sid: _wait_until(lambda: _try(ec2.delete_subnet, SubnetId=s), timeout_s=120)
        )

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-behav-r53r-sg-"),
        Description="route53resolver behavioral test sg",
    )["GroupId"]
    ctx.on_cleanup(
        lambda s=sg_id: _wait_until(
            lambda: _try(ec2.delete_security_group, GroupId=s), timeout_s=120
        )
    )

    return vpc_id, subnet_ids, sg_id


def _disassoc_qlc(r53, cfg_id, resource_id):
    def _attempt():
        try:
            r53.disassociate_resolver_query_log_config(
                ResolverQueryLogConfigId=cfg_id, ResourceId=resource_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            return (
                r53.get_resolver_query_log_config(ResolverQueryLogConfigId=cfg_id)[
                    "ResolverQueryLogConfig"
                ]["AssociationCount"]
                == 0
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return True

    _wait_until(_attempt, timeout_s=240)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateResolverQueryLogConfig reaches ACTIVE and increments AssociationCount."""
    r53 = ctx.client("route53resolver")
    dest_arn = _create_log_group_arn(ctx)
    cfg_id = r53.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-behav-qlc-"),
        DestinationArn=dest_arn,
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
    )["ResolverQueryLogConfig"]["Id"]
    ctx.on_cleanup(lambda x=cfg_id: r53.delete_resolver_query_log_config(ResolverQueryLogConfigId=x))
    def cfg_status():
        return r53.get_resolver_query_log_config(ResolverQueryLogConfigId=cfg_id)[
            "ResolverQueryLogConfig"
        ]["Status"]

    _poll(cfg_status, lambda s: s == "CREATED", timeout_s=60, interval_s=2)

    vpc_id, _subnets, _sg = _create_test_vpc_with_subnets(ctx, 2)
    assoc = r53.associate_resolver_query_log_config(
        ResolverQueryLogConfigId=cfg_id, ResourceId=vpc_id
    )["ResolverQueryLogConfigAssociation"]
    ctx.on_cleanup(lambda c=cfg_id, rid=vpc_id: _disassoc_qlc(r53, c, rid))
    assert assoc["Status"] in ("CREATING", "ACTIVE"), assoc["Status"]
    assert assoc["ResourceId"] == vpc_id, f"expected ResourceId={vpc_id}, got {assoc['ResourceId']}"

    def assoc_status():
        return r53.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc["Id"]
        )["ResolverQueryLogConfigAssociation"]["Status"]

    _poll(
        assoc_status,
        lambda s: s == "ACTIVE",
        timeout_s=70,
        interval_s=3,
        description="query log config association reaches ACTIVE",
    )

    def association_count():
        return r53.get_resolver_query_log_config(ResolverQueryLogConfigId=cfg_id)[
            "ResolverQueryLogConfig"
        ]["AssociationCount"]

    _poll(
        association_count,
        lambda c: c == 1,
        timeout_s=45,
        interval_s=3,
        description="AssociationCount reaches 1",
    )

    disassoc = r53.disassociate_resolver_query_log_config(
        ResolverQueryLogConfigId=cfg_id, ResourceId=vpc_id
    )["ResolverQueryLogConfigAssociation"]
    assert disassoc["Id"] == assoc["Id"], (
        f"Disassociate must name the association it removes, got {disassoc['Id']!r}"
    )
    assert disassoc["Status"] == "DELETING", (
        f"Disassociate must report Status=DELETING, got {disassoc['Status']}"
    )

    def assoc_gone():
        try:
            r53.get_resolver_query_log_config_association(
                ResolverQueryLogConfigAssociationId=assoc["Id"]
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return True
            raise
        return False

    _poll(
        assoc_gone,
        bool,
        timeout_s=180,
        interval_s=5,
        description="disassociated query log config association becomes independently unresolvable",
    )
    gone_code, gone_message = _error(
        lambda: r53.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc["Id"]
        )
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the disassociated association, got {gone_code!r}"
    )
    expected = "[RSLVR-01602] The specified query logging configuration association doesn't exist."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), _without_trace_id(err.get("Message"))
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
