"""list-syslog-configurations-reflects-put-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-syslog-configurations-reflects-put-and-delete"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSyslogConfigurations reflects a PutSyslogConfiguration addition and a
    DeleteSyslogConfiguration removal in real time."""
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-behav-syslog-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"][0]["arn"]

    vpce_id = _create_logs_vpc_endpoint(ctx)

    logs.put_syslog_configuration(logGroupIdentifier=log_group, vpcEndpointId=vpce_id)

    listed = logs.list_syslog_configurations()["syslogConfigurations"]
    matches = [
        c
        for c in listed
        if c.get("vpcEndpointId") == vpce_id and log_group.rsplit(":", 1)[-1] in c.get("logGroupArn", "")
    ]
    assert matches, (
        f"expected a syslog configuration for vpc endpoint {vpce_id} after PutSyslogConfiguration, "
        f"got {listed}"
    )
    assert matches[0]["logGroupArn"].rstrip("*").rstrip(":") == log_group_arn.rstrip("*").rstrip(":")

    # DeleteSyslogConfiguration requires vpcEndpointId in addition to
    # logGroupIdentifier -- a log group can have syslog configurations for more than
    # one VPC endpoint, so the endpoint must be identified explicitly to know which
    # one to remove.
    logs.delete_syslog_configuration(logGroupIdentifier=log_group, vpcEndpointId=vpce_id)

    listed_after = logs.list_syslog_configurations()["syslogConfigurations"]
    remaining = [c for c in listed_after if c.get("vpcEndpointId") == vpce_id]
    assert not remaining, (
        f"expected the syslog configuration to be gone after DeleteSyslogConfiguration, "
        f"got {remaining}"
    )


# ===== helpers =====

def _tag_spec(resource_type: str, name: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}],
    }


def _create_logs_vpc_endpoint(ctx) -> str:
    ec2 = ctx.client("ec2")

    # A freshly provisioned account may have no default VPC at all, so this check
    # provisions its own small VPC + subnet rather than depending on one being present.
    vpc_name = ctx.unique_name("sim2real-behav-syslogvpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.212.0.0/16",
        TagSpecifications=[_tag_spec("vpc", vpc_name)],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_after_dependents_clear(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.212.1.0/24",
        TagSpecifications=[_tag_spec("subnet", vpc_name)],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_after_dependents_clear(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    )

    sg_name = ctx.unique_name("sim2real-behav-syslogsg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real behavioral check - logs vpc endpoint",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", sg_name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    endpoint_name = ctx.unique_name("sim2real-behav-syslogvpce-")
    vpce_id = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        # PutSyslogConfiguration requires an interface endpoint to the dedicated
        # regional syslog-logs PrivateLink service, not the general "logs" service
        # endpoint (that gives an endpoint AWS rejects with "VPC endpoint ... is not
        # configured" for syslog use).
        ServiceName=f"com.amazonaws.{ctx.region}.syslog-logs",
        VpcEndpointType="Interface",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
        TagSpecifications=[_tag_spec("vpc-endpoint", endpoint_name)],
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint_and_wait(ec2, vpce_id))

    _wait_for(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0]["State"]
        == "available",
        timeout_s=240.0,
    )
    return vpce_id


_VPCE_NOT_FOUND = ("InvalidVpcEndpointId.NotFound", "InvalidVpcEndpoint.NotFound")


def _delete_vpc_endpoint_and_wait(ec2, vpce_id: str) -> None:
    """Delete the endpoint and wait until it is gone; an already-gone endpoint is fine,
    any other error (or an endpoint still present at the deadline) raises."""
    try:
        resp = ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id])
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") not in _VPCE_NOT_FOUND:
            raise
        return
    for item in resp.get("Unsuccessful", []):
        if item.get("Error", {}).get("Code") not in _VPCE_NOT_FOUND:
            raise RuntimeError(f"DeleteVpcEndpoints refused {vpce_id}: {item!r}")
    deadline = time.monotonic() + 180.0
    state = None
    while time.monotonic() < deadline:
        try:
            state = ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0][
                "State"
            ]
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") not in _VPCE_NOT_FOUND:
                raise
            return
        if state == "deleted":
            return
        time.sleep(2)
    raise RuntimeError(f"VPC endpoint {vpce_id} still {state!r} after 180 s")


def _delete_after_dependents_clear(fn, timeout_s: float = 30.0, interval_s: float = 3.0) -> None:
    """A VPC/subnet delete can transiently fail with DependencyViolation for a few seconds
    after the interface endpoint reports "deleted", while AWS finishes releasing its ENI."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_for(predicate, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception:
            pass
        time.sleep(interval_s)
    raise AssertionError("condition not met within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
