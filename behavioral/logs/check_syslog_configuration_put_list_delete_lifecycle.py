"""syslog-configuration-put-list-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "syslog-configuration-put-list-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


def _poll_until(probe, predicate, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _tag_spec(resource_type: str, name: str):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _find_syslog_vpc_endpoint_service_name(ec2) -> str:
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutSyslogConfiguration creates a config visible via ListSyslogConfigurations; Delete removes it."""
    logs = ctx.client("logs")
    ec2 = ctx.client("ec2")

    log_group_name = ctx.unique_name("sim2real-logs-syslog-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0][
        "logGroupArn"
    ]

    tag_name = ctx.unique_name("sim2real-logs-syslog-net-")

    # Reuse the run's shared network/subnet instead of creating a new VPC: accounts have a
    # bounded VPC quota and this check only needs *a* VPC endpoint to attach a syslog config
    # to, not a purpose-built network.
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not default_vpcs:

        raise AssertionError("no shared network VPC available in this account/region to host the endpoint")
    vpc_id = default_vpcs[0]["VpcId"]

    default_subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if not default_subnets:

        raise AssertionError("shared network has no default-for-az subnet to host the endpoint")
    subnet_id = default_subnets[0]["SubnetId"]

    sg_id = ec2.create_security_group(
        GroupName=tag_name,
        Description="sim2real syslog endpoint sg",
        VpcId=vpc_id,
        TagSpecifications=_tag_spec("security-group", tag_name),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))

    # PutSyslogConfiguration validates that vpcEndpointId is backed by the dedicated
    # syslog-ingestion PrivateLink service, not the plain CloudWatch Logs API service
    # endpoint -- an endpoint for "com.amazonaws.<region>.logs" is rejected with
    # InvalidParameterException ("... is not configured for the syslog ingestion
    # service"). The exact service name is undocumented and must be discovered.
    service_name = _find_syslog_vpc_endpoint_service_name(ec2)
    # PrivateDnsEnabled defaults to True for interface endpoints, but the shared network can
    # host only one private-DNS association per service zone -- a concurrent check reusing
    # this same shared network/service can already hold it, and CreateVpcEndpoint then fails
    # with InvalidParameter ("... conflicting DNS domain ... in the VPC"). This check only
    # needs a valid vpcEndpointId, not DNS resolution, so disable it explicitly.
    vpce_id = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=service_name,
        VpcEndpointType="Interface",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
        TagSpecifications=_tag_spec("vpc-endpoint", tag_name),
    )["VpcEndpoint"]["VpcEndpointId"]

    def _delete_endpoint():
        ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id])
        try:
            _poll_until(
                lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0][
                    "State"
                ],
                lambda state: state == "deleted",
                timeout_s=300.0,
                interval_s=2.0,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcEndpointId.NotFound":
                raise

    ctx.on_cleanup(_delete_endpoint)

    _poll_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0]["State"],
        lambda state: state == "available",
        timeout_s=240.0,
        interval_s=5.0,
    )

    logs.put_syslog_configuration(logGroupIdentifier=log_group_arn, vpcEndpointId=vpce_id)

    listed = logs.list_syslog_configurations(logGroupIdentifier=log_group_name)[
        "syslogConfigurations"
    ]
    assert len(listed) == 1, f"expected exactly one syslog configuration, got {listed}"
    assert listed[0]["vpcEndpointId"] == vpce_id, (
        f"expected the listed syslog configuration's vpcEndpointId to be {vpce_id!r}, "
        f"got {listed[0]['vpcEndpointId']!r}"
    )
    listed_log_group = listed[0]["logGroupArn"].split(":log-group:")[1].split(":")[0]
    assert listed_log_group == log_group_name, (
        f"expected the listed syslog configuration's log group to be {log_group_name!r}, "
        f"got {listed_log_group!r} (raw logGroupArn={listed[0]['logGroupArn']!r})"
    )

    logs.delete_syslog_configuration(logGroupIdentifier=log_group_name, vpcEndpointId=vpce_id)

    listed_after = logs.list_syslog_configurations(logGroupIdentifier=log_group_name)[
        "syslogConfigurations"
    ]
    assert listed_after == [], f"expected no syslog configurations after delete, got {listed_after}"



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
