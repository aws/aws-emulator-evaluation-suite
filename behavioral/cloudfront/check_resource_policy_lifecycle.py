"""resource-policy-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy -> GetResourcePolicy round-trips the policy document, and after
    DeleteResourcePolicy GetResourcePolicy returns a 200 with an empty PolicyDocument, as for a VPC
    origin that never had a policy (not EntityNotFound).
    """
    cf = ctx.client("cloudfront")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    origin = _create_vpc_origin(ctx)
    policy = _build_policy(origin["arn"], "cloudfront:GetVpcOrigin", principal_account=account_id)

    _put_resource_policy_with_retry(cf, origin["arn"], policy, timeout_s=650.0)

    got = cf.get_resource_policy(ResourceArn=origin["arn"])
    assert got["ResourceArn"] == origin["arn"], (
        f"expected ResourceArn {origin['arn']!r}, got {got['ResourceArn']!r}"
    )
    assert _as_json(got["PolicyDocument"]) == policy, (
        f"expected PolicyDocument to round-trip as {policy!r}, got {_as_json(got['PolicyDocument'])!r}"
    )

    cf.delete_resource_policy(ResourceArn=origin["arn"])

    after = _poll_for_document(
        lambda: _as_json(cf.get_resource_policy(ResourceArn=origin["arn"])["PolicyDocument"]),
        want={},
        timeout_s=270.0,
    )
    assert after == {}, f"expected the empty policy document after delete, got {after!r}"


# ===== helpers =====


def _as_json(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value


def _build_policy(resource_arn: str, action: str, principal_account: str = "111122223333") -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CrossAccountGrant",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{principal_account}:root"},
                "Action": action,
                "Resource": resource_arn,
            }
        ],
    }


def _poll_for_document(read, want, timeout_s: float) -> Any:
    """DeleteResourcePolicy on a VPC origin is asynchronous the same way PutResourcePolicy is,
    so re-read (bounded, with backoff) until the document equals ``want``; return the last read."""
    deadline = time.monotonic() + timeout_s
    delay = 3.0
    while True:
        doc = read()
        if doc == want or time.monotonic() >= deadline:
            return doc
        time.sleep(delay)
        delay = min(delay * 1.5, 15.0)


def _put_resource_policy_with_retry(
    cf, resource_arn: str, policy: dict[str, Any], timeout_s: float = 300.0
) -> None:
    """A brand-new VPC origin is not immediately consistent for resource-policy attachment.
    Measured empirically against real AWS: PutResourcePolicy against a just-created origin
    rejects with IllegalUpdate ("the specified resource wasn't successfully deployed") until the
    origin has finished deploying -- not the transient ServiceUnavailable/InternalError this
    retry originally guarded against. Both are eventual-consistency symptoms of the same
    underlying wait, so poll with backoff on either rather than failing on the first rejection."""
    deadline = time.monotonic() + timeout_s
    delay = 5.0
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            cf.put_resource_policy(ResourceArn=resource_arn, PolicyDocument=json.dumps(policy))
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("ServiceUnavailable", "InternalError", "Throttling", "IllegalUpdate"):
                raise
            last_exc = exc
            time.sleep(delay)
            delay = min(delay * 1.5, 30.0)
    if last_exc is not None:
        raise last_exc


def _create_vpc_origin(ctx) -> dict[str, str]:
    """PutResourcePolicy/GetResourcePolicy/DeleteResourcePolicy on CloudFront only accept a VPC
    origin's ARN as the resource ("The specified resource type isn't valid. Specify a VPC
    origin"), and CreateVpcOrigin itself synchronously validates that the referenced ALB really
    exists (a fabricated ARN is rejected with LoadBalancerNotFound). So a resource-policy check
    needs a REAL (if minimal/internal, never-routable) ALB behind it: two subnets of the run's
    shared network in different AZs (ALB's minimum), a security group, and an internal ALB. We only need the ALB to
    exist with a real ARN for CreateVpcOrigin's synchronous check to pass -- we don't need it (or
    the resulting VpcOrigin) to ever reach Deployed."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-vpco-")

    name_tag = [{"Key": "Name", "Value": name}]

    net = ctx.network()
    vpc_id = net.vpc_id
    subnet_ids = [net.subnets[az] for az in net.availability_zones[:2]]

    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral probe SG",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": name_tag}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
        IpAddressType="ipv4",
        Tags=name_tag,
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_load_balancer(elbv2, lb_arn))
    _wait_for_lb_active(elbv2, lb_arn)

    resp = cf.create_vpc_origin(
        VpcOriginEndpointConfig={
            "Name": name,
            "Arn": lb_arn,
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
        },
        Tags={"Items": name_tag},
    )
    vpc_origin = resp["VpcOrigin"]
    vo_id = vpc_origin["Id"]
    arn = vpc_origin["Arn"]
    ctx.on_cleanup(lambda: _delete_vpc_origin(ctx, vo_id))
    return {"id": vo_id, "arn": arn}


def _wait_for_lb_active(elbv2, lb_arn: str, timeout_s: float = 240.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lbs = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"]
        if lbs and lbs[0]["State"]["Code"] == "active":
            return
        time.sleep(5)


def _delete_load_balancer(elbv2, lb_arn: str, timeout_s: float = 300.0) -> None:
    """Delete the ALB and wait until it is gone, so its ENIs leave the security group."""
    elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
                return
            raise
        time.sleep(10)
    raise AssertionError(f"load balancer {lb_arn} still exists {timeout_s}s after DeleteLoadBalancer")


def _delete_vpc_origin(ctx, vo_id: str, timeout_s: float = 900.0) -> None:
    """Delete the VPC origin once it has left Deploying, then wait until it is gone."""
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    deleted = False
    while time.monotonic() < deadline:
        try:
            current = cf.get_vpc_origin(Id=vo_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("EntityNotFound", "NoSuchVpcOrigin"):
                return
            raise
        if not deleted and current["VpcOrigin"]["Status"] not in ("Deploying", "Creating"):
            try:
                cf.delete_vpc_origin(Id=vo_id, IfMatch=current["ETag"])
                deleted = True
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "InvalidIfMatchVersion", "PreconditionFailed", "IllegalDelete", "CannotDeleteEntityWhileInUse"
                ):
                    raise
        time.sleep(15)
    raise AssertionError(f"VPC origin {vo_id} still exists {timeout_s}s into its teardown")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that leaks the VPC.
# So wait (bounded) for the resource's ENIs to go, retry DependencyViolation inside the same window,
# and raise a final failure naming the ENIs still attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's cleanup budget.
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
