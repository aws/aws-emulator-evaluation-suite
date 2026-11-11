"""op-contract-createVpcEndpointConnectionNotification."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "op-contract-createVpcEndpointConnectionNotification"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcEndpointConnectionNotification: success wires an SNS topic to an interface
    endpoint's events; a nonexistent VpcEndpointId is rejected."""
    ec2 = ctx.client("ec2")
    sns = ctx.client("sns")
    region = ctx.region

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az = azs[0]["ZoneName"]

    vpc_id = _create_vpc(ec2, "10.212.0.0/16", _tag_spec(ctx, "vpc", "cn-vpc"))
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    # Interface endpoints default PrivateDnsEnabled=True for services that support it (e.g.
    # execute-api), and CreateVpcEndpoint rejects that combination unless the VPC has both DNS
    # attributes enabled -- a freshly created VPC only has EnableDnsSupport on by default, not
    # EnableDnsHostnames. Enable both explicitly rather than fighting the default.
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.212.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[_tag_spec(ctx, "subnet", "cn-subnet")],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-cn-sg-"),
        Description="sim2real",
        TagSpecifications=[_tag_spec(ctx, "security-group", "cn-sg")],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id)))

    endpoint_id = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{region}.execute-api",
        VpcEndpointType="Interface",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        TagSpecifications=[_tag_spec(ctx, "vpc-endpoint", "cn-vpce")],
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id]))

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-vpce-notify-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    resp = ec2.create_vpc_endpoint_connection_notification(
        VpcEndpointId=endpoint_id,
        ConnectionNotificationArn=topic_arn,
        ConnectionEvents=["Accept", "Delete"],
    )
    notification = resp["ConnectionNotification"]
    notification_id = notification["ConnectionNotificationId"]
    ctx.on_cleanup(
        lambda: ec2.delete_vpc_endpoint_connection_notifications(
            ConnectionNotificationIds=[notification_id]
        )
    )

    assert notification["VpcEndpointId"] == endpoint_id, notification
    assert notification["ConnectionNotificationArn"] == topic_arn, notification
    assert set(notification["ConnectionEvents"]) == {"Accept", "Delete"}, notification
    assert notification["ConnectionNotificationState"] == "Enabled", notification

    # Confirm the notification is durably visible via an independent Describe, tolerating the brief
    # eventual-consistency window real AWS has for a just-created notification id (it can still
    # answer InvalidConnectionNotification for a few seconds after
    # CreateVpcEndpointConnectionNotification returns).
    described = _poll_until(
        lambda: _describe_notification(ec2, notification_id),
        lambda items: len(items) == 1,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert len(described) == 1, f"expected the notification to appear in Describe, got {described!r}"
    seen = described[0]
    assert seen["VpcEndpointId"] == endpoint_id, seen
    assert seen["ConnectionNotificationArn"] == topic_arn, seen
    assert set(seen["ConnectionEvents"]) == {"Accept", "Delete"}, seen
    assert seen["ConnectionNotificationState"] == "Enabled", seen

    # Error boundary: a nonexistent VpcEndpointId is rejected.
    err = _client_error(
        lambda: ec2.create_vpc_endpoint_connection_notification(
            VpcEndpointId="vpce-00000000000000000",
            ConnectionNotificationArn=topic_arn,
            ConnectionEvents=["Accept"],
        )
    )
    assert err.get("Code") == "InvalidVpcEndpointId.NotFound", (
        f"expected InvalidVpcEndpointId.NotFound, got {err!r}"
    )
    assert err.get("Message") == "The vpc-endpoint ID 'vpce-00000000000000000' does not exist", (
        f"unexpected not-found message: {err!r}"
    )


def _retry_delete(fn, attempts: int = 60, delay_s: float = 3.0):
    # An interface endpoint's ENIs deprovision asynchronously after DeleteVpcEndpoints
    # returns, so a security group / subnet / VPC delete issued immediately afterwards can
    # still see DependencyViolation for a minute or more. Retry only that specific code; raise
    # anything else, and raise if the dependency never clears, so a genuine leak stays visible
    # in the harness's cleanup_detail rather than being swallowed.
    from botocore.exceptions import ClientError

    import time

    last = None
    for _ in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation":
                raise
            last = exc
            time.sleep(delay_s)
    raise last


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _notification_set(resp: dict) -> list:
    # boto3's EC2 model has historically kept the "Set" suffix on some legacy VPC-endpoint
    # response members; hedge against either naming to avoid a false failure on a naming detail.
    if "ConnectionNotificationSet" in resp:
        return resp["ConnectionNotificationSet"]
    return resp.get("ConnectionNotifications", [])


def _describe_notification(ec2, notification_id):
    from botocore.exceptions import ClientError

    try:
        return _notification_set(
            ec2.describe_vpc_endpoint_connection_notifications(ConnectionNotificationId=notification_id)
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"].startswith("InvalidConnectionNotification"):
            return []
        raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_vpc(ec2, cidr_block, tag_spec):
    """Create a VPC, failing loudly if the account has no quota left.

    A quota exhaustion is an environment precondition, not something a check may fix by deleting
    resources it does not own, so `VpcLimitExceeded` propagates.
    """
    return ec2.create_vpc(CidrBlock=cidr_block, TagSpecifications=[tag_spec])["Vpc"]["VpcId"]

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
