"""associate-resolver-query-log-config-vpc-already-associated-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-resolver-query-log-config-vpc-already-associated-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Associating a second query log config (same destination type) with a VPC that already has
    an active association is rejected and creates no second association. Once the first
    association is removed, the identical call succeeds."""
    r53r = ctx.client("route53resolver")
    logs = ctx.client("logs")
    ctx.client("ec2")

    vpc_id = _create_vpc(ctx)

    log_group_a = ctx.unique_name("sim2real-r53r-lga-")
    log_group_b = ctx.unique_name("sim2real-r53r-lgb-")
    logs.create_log_group(logGroupName=log_group_a)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_a))
    logs.create_log_group(logGroupName=log_group_b)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_b))

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    dest_a = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_a}:*"
    dest_b = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_b}:*"

    config_a = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-r53r-qlc-a-"),
        DestinationArn=dest_a,
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crid-a-"),
    )["ResolverQueryLogConfig"]
    config_a_id = config_a["Id"]
    ctx.on_cleanup(
        lambda: _retry_teardown(r53r.delete_resolver_query_log_config, ResolverQueryLogConfigId=config_a_id)
    )

    config_b = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-r53r-qlc-b-"),
        DestinationArn=dest_b,
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crid-b-"),
    )["ResolverQueryLogConfig"]
    config_b_id = config_b["Id"]
    ctx.on_cleanup(
        lambda: _retry_teardown(r53r.delete_resolver_query_log_config, ResolverQueryLogConfigId=config_b_id)
    )

    # Positive control: associating the VPC with the first config succeeds.
    assoc_a = r53r.associate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_a_id, ResourceId=vpc_id
    )["ResolverQueryLogConfigAssociation"]
    ctx.on_cleanup(lambda: _disassociate_and_drain(r53r, config_a_id, vpc_id))
    assert assoc_a["ResourceId"] == vpc_id, (
        f"expected the positive-control association to name {vpc_id}, got {assoc_a['ResourceId']}"
    )
    _poll_until(
        lambda: r53r.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc_a["Id"]
        )["ResolverQueryLogConfigAssociation"]["Status"],
        lambda status: status not in ("CREATING",),
        timeout_s=60.0,
        interval_s=2.0,
    )

    # Attempting to associate the SAME vpc with a second, different config is rejected.
    code, message = _error_code(
        lambda: r53r.associate_resolver_query_log_config(
            ResolverQueryLogConfigId=config_b_id, ResourceId=vpc_id
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = (
        "[RSLVR-01306] The resource is already associated with a query logging configuration "
        "that is sending query logs to the specified destination type."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no active association was created for config_b against this VPC.
    all_assocs = _list_all_assocs_for_vpc(r53r, vpc_id)
    config_ids = {a["ResolverQueryLogConfigId"] for a in all_assocs}
    assert config_ids == {config_a_id}, f"expected only config_a associated, got {config_ids}"

    # Restore: tear down the first association, then the identical config_b call --
    # which was just rejected -- must now succeed. This proves the refusal tracked the
    # VPC's association state rather than something permanently wrong with config_b.
    r53r.disassociate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_a_id, ResourceId=vpc_id
    )
    _poll_until(
        lambda: {a["ResolverQueryLogConfigId"] for a in _list_all_assocs_for_vpc(r53r, vpc_id)},
        lambda ids: config_a_id not in ids,
        timeout_s=60.0,
        interval_s=2.0,
    )

    assoc_b = r53r.associate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_b_id, ResourceId=vpc_id
    )["ResolverQueryLogConfigAssociation"]
    ctx.on_cleanup(lambda: _disassociate_and_drain(r53r, config_b_id, vpc_id))
    assert assoc_b["ResourceId"] == vpc_id, (
        f"expected the restored association to name {vpc_id}, got {assoc_b['ResourceId']}"
    )
    _poll_until(
        lambda: r53r.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc_b["Id"]
        )["ResolverQueryLogConfigAssociation"]["Status"],
        lambda status: status not in ("CREATING",),
        timeout_s=60.0,
        interval_s=2.0,
    )
    final_ids = {a["ResolverQueryLogConfigId"] for a in _list_all_assocs_for_vpc(r53r, vpc_id)}
    assert final_ids == {config_b_id}, (
        f"expected only config_b associated after the restore, got {final_ids}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple:
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), _without_trace_id(error.get("Message"))
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


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


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-r53r-vpc-")}],
            }
        ],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _list_all_assocs_for_vpc(r53r, vpc_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {}
        if token:
            kwargs["NextToken"] = token
        resp = r53r.list_resolver_query_log_config_associations(**kwargs)
        for a in resp.get("ResolverQueryLogConfigAssociations", []):
            if a.get("ResourceId") == vpc_id:
                out.append(a)
        token = resp.get("NextToken")
        if not token:
            break
    return out


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
