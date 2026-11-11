"""syslog-configuration-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "syslog-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutSyslogConfiguration creates a syslog ingestion config that ListSyslogConfigurations
    reports for the log group, and DeleteSyslogConfiguration removes it."""
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: logs.delete_log_group(logGroupName=log_group_name)))

    # The endpoint must belong to the syslog-ingestion PrivateLink service; one for the plain
    # CloudWatch Logs API service is rejected with InvalidParameterException.
    vpc_endpoint_id = _create_logs_vpc_endpoint(ctx)
    # DeleteSyslogConfiguration always requires vpcEndpointId, so this cleanup can
    # only be registered once the endpoint exists.
    ctx.on_cleanup(lambda: _delete_syslog_config(logs, log_group_name, vpc_endpoint_id))

    logs.put_syslog_configuration(logGroupIdentifier=log_group_name, vpcEndpointId=vpc_endpoint_id)

    # PutSyslogConfiguration is asynchronous: ListSyslogConfigurations may lag the call.
    found = _poll_until(
        lambda: _find_config(logs, log_group_name, vpc_endpoint_id),
        lambda cfg: cfg is not None,
        timeout_s=120.0,
    )
    assert found["vpcEndpointId"] == vpc_endpoint_id, (
        f"expected the listed syslog configuration for {log_group_name} to report vpcEndpointId "
        f"{vpc_endpoint_id!r}, got {found!r}"
    )

    logs.delete_syslog_configuration(logGroupIdentifier=log_group_name, vpcEndpointId=vpc_endpoint_id)

    _poll_until(
        lambda: _find_config(logs, log_group_name, vpc_endpoint_id),
        lambda cfg: cfg is None,
        timeout_s=120.0,
    )

    error_code, error_message = _error_code(
        lambda: logs.delete_syslog_configuration(
            logGroupIdentifier=log_group_name, vpcEndpointId=vpc_endpoint_id
        )
    )
    assert error_code == "InvalidParameterException", (
        f"expected a second DeleteSyslogConfiguration for the already-deleted config on "
        f"{log_group_name} to fail with InvalidParameterException, got {error_code!r}"
    )
    assert error_message == (
        f"VPC endpoint {vpc_endpoint_id} is not associated with log group {log_group_name}"
    ), f"unexpected already-deleted syslog configuration message: {error_message!r}"




def _find_config(logs_client, log_group_name: str, vpc_endpoint_id: str) -> dict | None:
    next_token = None
    while True:
        kwargs = {"logGroupIdentifier": log_group_name}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = logs_client.list_syslog_configurations(**kwargs)
        for cfg in resp.get("syslogConfigurations", []):
            if cfg.get("vpcEndpointId") == vpc_endpoint_id:
                return cfg
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        code = resp.get("Error", {}).get("Code") if isinstance(resp, dict) else None
        if code is None:
            raise
        return code, resp.get("Error", {}).get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


_NOT_FOUND = (
    "ResourceNotFoundException",
    "InvalidVpcID.NotFound",
    "InvalidSubnetID.NotFound",
    "InvalidGroup.NotFound",
    "InvalidVpcEndpointId.NotFound",
)


def _ignore_notfound(fn) -> None:
    """Run a teardown delete; an already-deleted resource is fine, any other error raises."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        code = resp.get("Error", {}).get("Code") if isinstance(resp, dict) else None
        if code not in _NOT_FOUND:
            raise


def _delete_syslog_config(logs, log_group_name: str, vpc_endpoint_id: str) -> None:
    """Delete the syslog config; one already deleted is refused with InvalidParameterException
    "... is not associated with log group ...", which is fine; any other error raises."""
    try:
        _ignore_notfound(
            lambda: logs.delete_syslog_configuration(
                logGroupIdentifier=log_group_name, vpcEndpointId=vpc_endpoint_id
            )
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") != "InvalidParameterException" or err.get("Message") != (
            f"VPC endpoint {vpc_endpoint_id} is not associated with log group {log_group_name}"
        ):
            raise


def _delete_vpc_endpoint_and_wait(ec2, vpce_id: str) -> None:
    """DeleteVpcEndpoints reports refusals in Unsuccessful rather than raising: an already-gone
    endpoint is fine, any other refusal (or an endpoint not deleted within 180 s) raises."""
    resp: dict = {}
    _ignore_notfound(lambda: resp.update(ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id])))
    for item in resp.get("Unsuccessful", []):
        if item.get("Error", {}).get("Code") not in _NOT_FOUND:
            raise RuntimeError(f"DeleteVpcEndpoints refused {vpce_id}: {item!r}")
    deadline = time.monotonic() + 180.0
    state = None
    while time.monotonic() < deadline:
        found: list = []
        _ignore_notfound(lambda: found.extend(ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"]))
        state = found[0]["State"] if found else "deleted"
        if state.lower() == "deleted":
            return
        time.sleep(2)
    raise RuntimeError(f"VPC endpoint {vpce_id} still {state!r} after 180 s")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_logs_vpc_endpoint(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name("sim2real-behav-vpc-")

    vpc = ec2.create_vpc(
        CidrBlock="10.211.0.0/16", TagSpecifications=[_tag_spec("vpc", vpc_name)]
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    subnet_name = ctx.unique_name("sim2real-behav-subnet-")
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.211.1.0/24",
        TagSpecifications=[_tag_spec("subnet", subnet_name)],
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    sg_name = ctx.unique_name("sim2real-behav-sg-")
    sg = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real behavioral check sg",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", sg_name)],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id)))

    service_name = _find_syslog_vpc_endpoint_service_name(ec2)
    endpoint_name = ctx.unique_name("sim2real-behav-vpce-")
    # Private DNS would require enableDnsSupport/enableDnsHostnames on the VPC; only the
    # vpcEndpointId is needed, so it is disabled.
    endpoint = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=service_name,
        VpcEndpointType="Interface",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
        TagSpecifications=[_tag_spec("vpc-endpoint", endpoint_name)],
    )["VpcEndpoint"]
    vpc_endpoint_id = endpoint["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint_and_wait(ec2, vpc_endpoint_id))

    _wait_for_vpc_endpoint_available(ec2, vpc_endpoint_id)
    return vpc_endpoint_id


def _find_syslog_vpc_endpoint_service_name(ec2) -> str:
    """Discover the syslog-ingestion VPC endpoint service name; it is not documented and may vary
    by partition or region."""
    logs_related: list[str] = []
    paginator = ec2.get_paginator("describe_vpc_endpoint_services")
    for page in paginator.paginate(Filters=[{"Name": "service-type", "Values": ["Interface"]}]):
        for detail in page.get("ServiceDetails", []):
            name = detail.get("ServiceName", "")
            if "logs" in name.lower():
                logs_related.append(name)

    syslog_matches = [name for name in logs_related if "syslog" in name.lower()]
    if syslog_matches:
        return syslog_matches[0]

    raise AssertionError(
        "no dedicated syslog-ingestion VPC endpoint service is available in this "
        f"account/region for CloudWatch Logs (logs-related endpoint services seen: {logs_related})"
    )


def _wait_for_vpc_endpoint_available(ec2, vpc_endpoint_id: str, timeout: float = 300.0) -> None:
    deadline = time.monotonic() + timeout
    last_state = None
    while time.monotonic() < deadline:
        resp = ec2.describe_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id])
        endpoints = resp.get("VpcEndpoints", [])
        if endpoints:
            last_state = endpoints[0].get("State")
            if last_state == "available":
                return
        time.sleep(5)
    raise AssertionError(
        f"VPC endpoint {vpc_endpoint_id} did not become available within {timeout}s "
        f"(last state: {last_state})"
    )


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
        _time.sleep(2)
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
        _time.sleep(2)


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

