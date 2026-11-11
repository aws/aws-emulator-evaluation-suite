"""syslog-configuration-delete-nonexistent-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "syslog-configuration-delete-nonexistent-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSyslogConfiguration is rejected for a log group/endpoint pair with no configuration,
    both never-created and just-deleted, and the log group survives untouched throughout."""
    logs = ctx.client("logs")
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-logs-syslog-nocfg-")
    logs.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))

    vpce_id = _create_syslog_vpc_endpoint(ctx, ec2)

    # vpcEndpointId is not modelled required, but omitting it is a different rejection
    # ("vpcEndpointId is required"), so every delete below supplies a real one.
    baseline = logs.list_syslog_configurations(logGroupIdentifier=name)["syslogConfigurations"]
    assert baseline == [], f"expected no syslog configurations before any Put, got {baseline}"

    not_associated = f"VPC endpoint {vpce_id} is not associated with log group {name}"
    code, message = _error_code(
        lambda: logs.delete_syslog_configuration(logGroupIdentifier=name, vpcEndpointId=vpce_id)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == not_associated, f"unexpected never-configured delete message: {message!r}"

    still_there = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    assert any(g["logGroupName"] == name for g in still_there), (
        f"expected {name} to still exist after the rejected delete, got {still_there}"
    )
    empty_after = logs.list_syslog_configurations(logGroupIdentifier=name)["syslogConfigurations"]
    assert empty_after == [], f"expected no syslog configurations after the rejected delete, got {empty_after}"

    # Positive control: a real configuration deletes, then a second delete is rejected the same way.
    logs.put_syslog_configuration(logGroupIdentifier=name, vpcEndpointId=vpce_id)
    listed = logs.list_syslog_configurations(logGroupIdentifier=name)["syslogConfigurations"]
    assert len(listed) == 1, f"expected exactly one syslog configuration after Put, got {listed}"

    logs.delete_syslog_configuration(logGroupIdentifier=name, vpcEndpointId=vpce_id)
    listed_after_delete = logs.list_syslog_configurations(logGroupIdentifier=name)["syslogConfigurations"]
    assert listed_after_delete == [], (
        f"expected no syslog configurations immediately after the positive-control delete, got {listed_after_delete}"
    )

    code_again, message_again = _error_code(
        lambda: logs.delete_syslog_configuration(logGroupIdentifier=name, vpcEndpointId=vpce_id)
    )
    assert code_again == "InvalidParameterException", (
        f"expected InvalidParameterException deleting an already-deleted syslog configuration, "
        f"got {code_again}"
    )
    assert message_again == not_associated, f"unexpected already-deleted delete message: {message_again!r}"


def _create_syslog_vpc_endpoint(ctx, ec2) -> str:
    """Provision a self-contained VPC and an interface endpoint for the syslog-ingestion service.

    PutSyslogConfiguration rejects an endpoint for the plain CloudWatch Logs API service."""
    vpc_id = ec2.create_vpc(CidrBlock="10.212.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.212.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    sg_name = ctx.unique_name("sim2real-logs-syslog-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name, Description="sim2real behavioral check sg", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    service_name = _find_syslog_vpc_endpoint_service_name(ec2)
    vpc_endpoint_id = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=service_name,
        VpcEndpointType="Interface",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
    )["VpcEndpoint"]["VpcEndpointId"]
    # The subnet/SG/VPC deletes registered above run (LIFO) only after this one, so wait for the
    # endpoint's ENI to actually be gone -- deleting it without waiting leaves a DependencyViolation
    # on every cleanup below it, which ctx.on_cleanup swallows silently.
    ctx.on_cleanup(lambda: _delete_vpc_endpoint_and_wait(ec2, vpc_endpoint_id))

    _wait_for_vpc_endpoint_available(ec2, vpc_endpoint_id)
    return vpc_endpoint_id


def _delete_vpc_endpoint_and_wait(ec2, vpc_endpoint_id: str, timeout: float = 45.0) -> None:
    ec2.delete_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = ec2.describe_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id])
        endpoints = resp.get("VpcEndpoints", [])
        if not endpoints or endpoints[0].get("State") == "deleted":
            return
        time.sleep(3)


def _find_syslog_vpc_endpoint_service_name(ec2) -> str:
    logs_related: list[str] = []
    paginator = ec2.get_paginator("describe_vpc_endpoint_services")
    for page in paginator.paginate(Filters=[{"Name": "service-type", "Values": ["Interface"]}]):
        for detail in page.get("ServiceDetails", []):
            svc_name = detail.get("ServiceName", "")
            if "logs" in svc_name.lower():
                logs_related.append(svc_name)

    syslog_matches = [n for n in logs_related if "syslog" in n.lower()]
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
