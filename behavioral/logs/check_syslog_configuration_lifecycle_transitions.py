"""syslog-configuration-lifecycle-transitions."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "syslog-configuration-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutSyslogConfiguration creates a syslog config for a log group visible in
    ListSyslogConfigurations; DeleteSyslogConfiguration removes it."""
    start_time = time.monotonic()
    logs = ctx.client("logs")
    log_group_name, log_group_arn = _create_log_group(ctx)
    # The endpoint must belong to the syslog-ingestion PrivateLink service; one for the plain
    # "logs" API service is rejected with InvalidParameterException.
    vpc_endpoint_id = _create_vpc_endpoint(ctx)

    logs.put_syslog_configuration(logGroupIdentifier=log_group_name, vpcEndpointId=vpc_endpoint_id)
    # The happy path deletes the configuration itself; DeleteSyslogConfiguration on an absent
    # configuration is an InvalidParameterException, so the cleanup only deletes one still listed.
    ctx.on_cleanup(
        lambda: _lookup_config(logs, log_group_arn) is None or _safe_call(
            lambda: logs.delete_syslog_configuration(
                logGroupIdentifier=log_group_name, vpcEndpointId=vpc_endpoint_id
            )
        )
    )

    # PutSyslogConfiguration is asynchronous: the new config does not always
    # show up in ListSyslogConfigurations immediately after the call returns
    # on real AWS, so this is a bounded poll rather than an immediate assert.
    # The propagation into ListSyslogConfigurations can take longer than ~4 minutes, so the
    # overall budget is materially larger, reserving a slice for the disappearance poll below plus
    # a safety margin, and still adapting to variable setup latency (creating the endpoint can
    # take ~2 minutes).
    TOTAL_BUDGET_S = 600.0
    DELETE_POLL_RESERVE_S = 60.0
    SAFETY_MARGIN_S = 20.0
    elapsed = time.monotonic() - start_time
    put_poll_timeout = max(
        60.0, TOTAL_BUDGET_S - elapsed - DELETE_POLL_RESERVE_S - SAFETY_MARGIN_S
    )
    found = _poll_until(
        lambda: _lookup_config(logs, log_group_arn),
        lambda c: c is not None,
        timeout_s=put_poll_timeout,
        interval_s=5.0,
    )
    found_arn = _normalize_log_group_id(found.get("logGroupArn"))
    expected_arn = _normalize_log_group_id(log_group_arn)
    assert found_arn == expected_arn, (
        f"expected the listed syslog config's logGroupArn to be {expected_arn!r}, "
        f"got {found_arn!r} (raw={found.get('logGroupArn')!r})"
    )
    assert found.get("vpcEndpointId") == vpc_endpoint_id, (
        f"expected the listed syslog config's vpcEndpointId to be {vpc_endpoint_id!r}, "
        f"got {found.get('vpcEndpointId')!r}"
    )

    logs.delete_syslog_configuration(logGroupIdentifier=log_group_name, vpcEndpointId=vpc_endpoint_id)
    elapsed = time.monotonic() - start_time
    delete_poll_timeout = max(30.0, TOTAL_BUDGET_S - elapsed - SAFETY_MARGIN_S)
    _poll_until(
        lambda: _lookup_config(logs, log_group_arn),
        lambda c: c is None,
        timeout_s=delete_poll_timeout,
        interval_s=5.0,
    )



def _safe_call(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _normalize_log_group_id(value: str | None) -> str | None:
    # DescribeLogGroups ARNs carry a trailing ":*" that the syslog APIs' logGroupArn may not,
    # so the suffix is stripped from both sides before comparing.
    if value and value.endswith(":*"):
        return value[:-2]
    return value


def _lookup_config(logs_client, log_group_arn: str) -> dict | None:
    # This lists every config unfiltered and matches client-side on logGroupArn, the only log
    # group member a returned SyslogConfiguration has.
    target_arn = _normalize_log_group_id(log_group_arn)
    next_token = None
    while True:
        kwargs = {}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = logs_client.list_syslog_configurations(**kwargs)
        for config in resp.get("syslogConfigurations", []):
            if _normalize_log_group_id(config.get("logGroupArn")) == target_arn:
                return config
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _create_log_group(ctx) -> tuple[str, str]:
    logs_client = ctx.client("logs")
    name = ctx.unique_name("sim2real-logs-lg-")
    logs_client.create_log_group(logGroupName=name, tags={"Name": name})
    ctx.on_cleanup(lambda: logs_client.delete_log_group(logGroupName=name))
    arn = logs_client.describe_log_groups(logGroupNamePrefix=name)["logGroups"][0]["arn"]
    return name, arn


def _endpoint_state(ec2_client, endpoint_id: str) -> str | None:
    try:
        resp = ec2_client.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])
    except ClientError as e:
        if e.response["Error"]["Code"] in ("InvalidVpcEndpointId.NotFound", "InvalidVpcEndpointId.Malformed"):
            return None
        raise
    endpoints = resp.get("VpcEndpoints", [])
    if not endpoints:
        return None
    return endpoints[0]["State"]


def _find_syslog_service_name(ec2_client, region: str) -> str:
    """Discover the syslog-ingestion interface-endpoint service name for this region.

    A guessed "com.amazonaws.<region>.logs-syslog" is rejected with InvalidServiceName."""
    candidates: list[str] = []
    paginator = ec2_client.get_paginator("describe_vpc_endpoint_services")
    for page in paginator.paginate(Filters=[{"Name": "service-type", "Values": ["Interface"]}]):
        for detail in page.get("ServiceDetails", []):
            name = detail.get("ServiceName", "")
            if "logs" in name and "syslog" in name.lower():
                candidates.append(name)

    if not candidates:
        raise AssertionError(
            f"no CloudWatch Logs syslog-ingestion VPC endpoint service is available in {region}"
        )

    # Prefer an exact-looking regional match if multiple candidates surface.
    for name in candidates:
        if name.startswith(f"com.amazonaws.{region}."):
            return name
    return candidates[0]


def _create_vpc_endpoint(ctx) -> str:
    """Return the id of a new, available interface VPC endpoint for the logs
    syslog-ingestion service, in a subnet of the run's shared network."""
    ec2 = ctx.client("ec2")
    region = ctx.region
    service_name = _find_syslog_service_name(ec2, region)
    tag_name = ctx.unique_name("sim2real-logs-syslog-net-")

    net = ctx.network()
    vpc_id = net.vpc_id
    offered = set(ec2.describe_vpc_endpoint_services(ServiceNames=[service_name])["ServiceDetails"][0].get("AvailabilityZones", []))
    zones = [az for az in net.availability_zones if az in offered]
    if not zones:
        raise AssertionError(f"{service_name} is offered in none of the shared network's zones {net.availability_zones!r}")
    subnet_id = net.subnets[zones[0]]
    sg_id = ec2.create_security_group(
        GroupName=tag_name,
        Description="sim2real syslog endpoint sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": tag_name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    # PutSyslogConfiguration needs only a valid vpcEndpointId, not DNS resolution; private DNS is
    # off because the shared network holds one private-DNS association per service zone.
    endpoint_id = ec2.create_vpc_endpoint(
        VpcEndpointType="Interface",
        VpcId=vpc_id,
        ServiceName=service_name,
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": [{"Key": "Name", "Value": tag_name}]}],
    )["VpcEndpoint"]["VpcEndpointId"]

    def _cleanup_endpoint() -> None:
        _safe_call(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id]))
        _poll_until(
            lambda: _endpoint_state(ec2, endpoint_id),
            lambda s: s in (None, "deleted"),
            timeout_s=600.0,
            interval_s=5.0,
        )

    ctx.on_cleanup(_cleanup_endpoint)

    # The cleanup poll above runs AFTER the check body returns, so it is not part of this budget.
    _poll_until(
        lambda: _endpoint_state(ec2, endpoint_id),
        lambda s: s == "available",
        timeout_s=240.0,
        interval_s=5.0,
    )
    return endpoint_id


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A resource in this VPC
# deletes asynchronously: its ENIs can still sit in the subnet / security group, so an immediate
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait (bounded) for
# the ENIs to go, retry DependencyViolation in the same window, and raise naming the ENIs still
# attached. Teardown-only: run() never calls this. One window covers a check's network deletes.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
