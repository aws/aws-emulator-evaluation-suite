"""op-contract-modify-vpc-endpoint-connection-notification."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-modify-vpc-endpoint-connection-notification"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpcEndpointConnectionNotification: success updates which connection
    events are subscribed and DescribeVpcEndpointConnectionNotifications reflects
    the new set; DryRun is rejected with DryRunOperation."""
    ec2 = ctx.client("ec2")
    sns = ctx.client("sns")
    region = ctx.region

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-vpce-notif-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "vpce.amazonaws.com"},
                "Action": "SNS:Publish",
                "Resource": topic_arn,
            }
        ],
    }
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(policy))

    vpc_id = _get_default_vpc(ec2, ctx=ctx)
    if vpc_id is None:
        vpc_id = ec2.create_vpc(CidrBlock="10.204.0.0/16", TagSpecifications=_tag_spec(ctx, "vpc", "vpcen-vpc"))["Vpc"][
            "VpcId"
        ]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = _get_default_subnet(ec2, vpc_id, ctx=ctx)
    if subnet_id is None:
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="10.204.1.0/24", TagSpecifications=_tag_spec(ctx, "subnet", "vpcen-subnet")
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id, GroupName=ctx.unique_name("sim2real-vpcen-sg-"), Description="sim2real vpce connection notification"
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))


    vpce_id = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{region}.ec2",
        VpcEndpointType="Interface",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        TagSpecifications=_tag_spec(ctx, "vpc-endpoint", "vpcen-if"),
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]))

    state = _poll_until(
        lambda: _describe_endpoint(ec2, vpce_id),
        lambda e: e is not None and e.get("State") == "available",
        timeout_s=240,
        interval_s=10,
    )
    assert state is not None and state["State"] == "available", state

    notif = ec2.create_vpc_endpoint_connection_notification(
        VpcEndpointId=vpce_id, ConnectionNotificationArn=topic_arn, ConnectionEvents=["Accept", "Reject"]
    )["ConnectionNotification"]
    notif_id = notif["ConnectionNotificationId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoint_connection_notifications(ConnectionNotificationIds=[notif_id]))
    assert sorted(notif["ConnectionEvents"]) == ["Accept", "Reject"], notif["ConnectionEvents"]

    # error boundary: DryRun must reject without mutating the notification. The DryRun call
    # below asks for the exact same target value ("Delete") that the success path sets next,
    # so without this independent read in between, a target that actually performed the
    # mutation on DryRun would be indistinguishable from one that correctly rejected it: the
    # following describe would show ["Delete"] either way.
    err, err_message = _error(
        lambda: ec2.modify_vpc_endpoint_connection_notification(
            ConnectionNotificationId=notif_id, ConnectionEvents=["Delete"], DryRun=True
        )
    )
    assert err == "DryRunOperation", err
    assert err_message == "Request would have succeeded, but DryRun flag is set.", err_message

    unmutated = _describe_notification(ec2, notif_id)
    assert unmutated is not None, "notification disappeared after a DryRun call"
    assert sorted(unmutated["ConnectionEvents"]) == ["Accept", "Reject"], (
        f"DryRun must not mutate ConnectionEvents, got {unmutated['ConnectionEvents']!r}"
    )

    # success path: narrow the subscribed events to Delete only.
    # Real AWS returns this operation's boolean success indicator under the key
    # "ReturnValue" (unlike most other Modify* EC2 operations, which use "Return").
    resp = ec2.modify_vpc_endpoint_connection_notification(ConnectionNotificationId=notif_id, ConnectionEvents=["Delete"])
    assert resp["ReturnValue"] is True, resp

    updated = _describe_notification(ec2, notif_id)
    assert updated is not None, "notification disappeared after the real modify call"
    assert updated["ConnectionEvents"] == ["Delete"], updated


# ===== helpers =====
def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _describe_endpoint(ec2, vpce_id):
    resp = ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])
    items = resp.get("VpcEndpoints", [])
    return items[0] if items else None


def _describe_notification(ec2, notif_id):
    resp = ec2.describe_vpc_endpoint_connection_notifications(ConnectionNotificationId=notif_id)
    items = resp.get("ConnectionNotificationSet", [])
    return items[0] if items else None


def _get_default_vpc(ec2, *, ctx):
    # Reusing the run's shared network (when one exists) avoids tripping the
    # per-region VPC quota when many checks in this suite each need "a VPC" but
    # don't care about its specific CIDR.
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    return vpcs[0]["VpcId"] if vpcs else None


def _get_default_subnet(ec2, vpc_id, *, ctx):
    resp = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )
    subnets = resp.get("Subnets", [])
    return subnets[0]["SubnetId"] if subnets else None


# EC2 network teardown: an asynchronously deleted dependent leaves its ENIs in the subnet / security
# group, so each delete retries DependencyViolation while they drain, inside one window shared by the
# check's network deletes and the suite's cleanup budget, then raises naming the ENIs still attached.
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
