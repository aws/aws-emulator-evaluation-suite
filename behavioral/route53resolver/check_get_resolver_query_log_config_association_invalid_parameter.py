"""get-resolver-query-log-config-association-invalid-parameter."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resolver-query-log-config-association-invalid-parameter"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResolverQueryLogConfigAssociation with an over-length id returns ValidationException.

    A real association created here stays retrievable with the same call (positive control).
    """
    r53r = ctx.client("route53resolver")

    # Only ids over the max length of 64 hit parameter validation; shorter malformed ids
    # are treated as not-found (ResourceNotFoundException).
    malformed_id = "rqlca-" + ("x" * 100)
    code, message = _error(
        lambda: r53r.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=malformed_id
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        f"1 validation error detected: Value '{malformed_id}' at 'resolverQueryLogConfigAssociationId' "
        "failed to satisfy constraint: Member must have length less than or equal to 64"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


    # Positive control: build a real association and confirm it is retrievable.
    log_group_name = ctx.unique_name("/sim2real-behav/r53r-")
    logs = ctx.client("logs")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]

    config = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-behav-qlc-"),
        DestinationArn=log_group_arn,
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
    )["ResolverQueryLogConfig"]
    config_id = config["Id"]
    ctx.on_cleanup(lambda: r53r.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id))

    vpc_id = _create_vpc(ctx)
    assoc = r53r.associate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_id, ResourceId=vpc_id
    )["ResolverQueryLogConfigAssociation"]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: _disassociate_and_wait(r53r, config_id, vpc_id, assoc_id))

    deadline = time.monotonic() + 180
    while True:
        got = r53r.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc_id
        )["ResolverQueryLogConfigAssociation"]
        if got["Status"] in ("ACTIVE", "FAILED"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"association {assoc_id} still {got['Status']!r} after 180s")
        time.sleep(3)
    assert got["Id"] == assoc_id, f"expected association id {assoc_id!r}, got {got['Id']!r}"
    assert got["ResourceId"] == vpc_id, f"expected resource id {vpc_id!r}, got {got['ResourceId']!r}"
    assert got["Status"] == "ACTIVE", f"expected association status ACTIVE, got {got['Status']!r}"


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


def _disassociate_and_wait(r53r, config_id: str, vpc_id: str, assoc_id: str) -> None:
    """Teardown: disassociate, then wait until the association is gone so the config can be deleted."""
    try:
        r53r.disassociate_resolver_query_log_config(ResolverQueryLogConfigId=config_id, ResourceId=vpc_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            r53r.get_resolver_query_log_config_association(ResolverQueryLogConfigAssociationId=assoc_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"association {assoc_id} still present 180s after disassociate")


def _create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.78.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
