"""op-contract-deleteVpcEndpointConnectionNotifications."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVpcEndpointConnectionNotifications"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVpcEndpointConnectionNotifications deletes the real one, reports the bogus one in Unsuccessful."""
    ec2 = ctx.client("ec2")
    sns = ctx.client("sns")

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-vpce-notif-"))["TopicArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sns.delete_topic(TopicArn=topic_arn)))
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

    vpc_id = ec2.create_vpc(
        CidrBlock="10.217.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "notif-vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.217.1.0/24", TagSpecifications=[_tag_spec(ctx, "subnet", "notif-subnet")]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-notif-sg-"),
        Description="sim2real behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec(ctx, "security-group", "notif-sg")],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    endpoint_id = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{ctx.region}.ec2",
        VpcEndpointType="Interface",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
        TagSpecifications=[_tag_spec(ctx, "vpc-endpoint", "notif-vpce")],
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint(ec2, endpoint_id))

    _poll_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]["State"],
        lambda s: s.lower() in ("available", "pendingacceptance"),
        timeout_s=180.0,
        interval_s=5.0,
    )

    created = ec2.create_vpc_endpoint_connection_notification(
        VpcEndpointId=endpoint_id,
        ConnectionNotificationArn=topic_arn,
        ConnectionEvents=["Delete", "Accept", "Reject"],
    )
    notification_id = created["ConnectionNotification"]["ConnectionNotificationId"]
    state = {"deleted": False}

    def _cleanup_notification():
        if not state["deleted"]:
            _safe(
                lambda: ec2.delete_vpc_endpoint_connection_notifications(
                    ConnectionNotificationIds=[notification_id]
                )
            )

    ctx.on_cleanup(_cleanup_notification)

    # real AWS can briefly still return a "not found" error for a just-created
    # connection notification id (eventual consistency) before Describe recognizes
    # it, so poll rather than asserting on the very first call.
    def _describe_notification():
        try:
            return _notification_set(
                ec2.describe_vpc_endpoint_connection_notifications(ConnectionNotificationId=notification_id)
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"].startswith("InvalidConnectionNotification"):
                return []
            raise

    described = _poll_until(_describe_notification, lambda items: len(items) == 1, timeout_s=60.0, interval_s=3.0)
    assert len(described) == 1, f"expected exactly one described notification, got {described!r}"
    assert described[0]["ConnectionNotificationArn"] == topic_arn, (
        f"expected ConnectionNotificationArn {topic_arn!r}, got {described[0]['ConnectionNotificationArn']!r}"
    )
    assert set(described[0]["ConnectionEvents"]) == {"Delete", "Accept", "Reject"}, (
        f"expected ConnectionEvents {{'Delete', 'Accept', 'Reject'}}, got {described[0]['ConnectionEvents']!r}"
    )

    # batch delete: one real notification id + one bogus one in the same request
    bogus_id = _mutate_id(notification_id)
    delete_resp = ec2.delete_vpc_endpoint_connection_notifications(
        ConnectionNotificationIds=[notification_id, bogus_id]
    )
    state["deleted"] = True

    unsuccessful = delete_resp["Unsuccessful"]
    assert len(unsuccessful) == 1, f"expected exactly one Unsuccessful entry, got {unsuccessful!r}"
    assert unsuccessful[0]["ResourceId"] == bogus_id, (
        f"expected the Unsuccessful entry to name the bogus id {bogus_id!r}, got {unsuccessful[0]['ResourceId']!r}"
    )
    # real EC2 reports a nonexistent connection notification id via a generic
    # "InternalError" code, with the specificity carried only in the message text
    # (rather than a dedicated *.NotFound error code as other Delete*s use)
    error = unsuccessful[0]["Error"]
    assert (error["Code"], error.get("Message")) == (
        "InternalError",
        f"Connection notification {bogus_id} not found",
    ), f"unexpected Unsuccessful error for the bogus notification id: {error!r}"

    # the real notification was still deleted despite the bogus one failing in the same batch.
    # Real AWS raises InvalidConnectionNotification (rather than returning an empty set) once
    # the notification id is gone entirely, so treat that error the same as "not found" here,
    # mirroring the _describe_notification helper used above.
    remaining = _describe_notification()
    assert remaining == [], f"expected the deleted notification to disappear, got {remaining!r}"


# ===== helpers =====
def _notification_set(resp: dict) -> list:
    # boto3's EC2 model has historically kept the "Set" suffix on some legacy VPC-endpoint
    # response members; hedge against either naming to avoid a false failure on a naming detail.
    if "ConnectionNotificationSet" in resp:
        return resp["ConnectionNotificationSet"]
    return resp.get("ConnectionNotifications", [])



def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


_ENDPOINT_GONE = frozenset({"InvalidVpcEndpoint.NotFound", "InvalidVpcEndpointId.NotFound"})


def _delete_vpc_endpoint(ec2, endpoint_id):
    """DeleteVpcEndpoints reports per-endpoint failures in Unsuccessful: an endpoint already
    gone is fine, any other failure raises."""
    failed = ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id]).get("Unsuccessful", [])
    if any(f["Error"]["Code"] not in _ENDPOINT_GONE for f in failed):
        raise RuntimeError(f"DeleteVpcEndpoints {endpoint_id} failed: {failed}")


def _mutate_id(real_id: str) -> str:
    return real_id[:-1] + ("0" if real_id[-1] != "0" else "1")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


# AWS-managed ENIs (endpoints, load balancers, instances) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
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
