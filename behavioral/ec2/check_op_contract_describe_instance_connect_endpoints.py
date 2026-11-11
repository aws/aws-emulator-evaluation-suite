"""op-contract-describe-instance-connect-endpoints."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-instance-connect-endpoints"
GROUP = "error-semantics"
SERVICES = ["ec2"]
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."

_NAME_PREFIX = "sim2real-behav-describe-eice-"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceConnectEndpoints returns a well-formed endpoint set, a state filter
    actually discriminates a real endpoint (includes it under its own state, excludes it under
    a state it has never been in), and DryRun short-circuits with DryRunOperation."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_instance_connect_endpoints()
    assert isinstance(resp.get("InstanceConnectEndpoints"), list), f"expected a list, got {resp.get('InstanceConnectEndpoints')!r}"
    assert resp.get("NextToken") in (None, ""), f"expected no pagination token on a bare call, got {resp.get('NextToken')!r}"

    subnet_id = _existing_vpc_and_subnet(ec2, ctx)[1]
    endpoint_id = _create_endpoint_with_retry(ec2, subnet_id, ctx.unique_name(_NAME_PREFIX))
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_instance_connect_endpoint(InstanceConnectEndpointId=endpoint_id)))

    state = _poll_until(
        lambda: ec2.describe_instance_connect_endpoints(InstanceConnectEndpointIds=[endpoint_id])[
            "InstanceConnectEndpoints"
        ][0]["State"],
        lambda s: s in ("create-complete", "create-failed"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert state == "create-complete", f"expected create-complete, got {state!r}"

    # Independent read at the destination, through the plain unfiltered call, not the
    # create call's own response.
    unfiltered_ids = {
        e["InstanceConnectEndpointId"] for e in ec2.describe_instance_connect_endpoints()["InstanceConnectEndpoints"]
    }
    assert endpoint_id in unfiltered_ids, f"{endpoint_id} missing from unfiltered describe: {unfiltered_ids}"

    # The state filter must discriminate, not just echo an empty result: it includes the
    # real create-complete endpoint under its own state...
    matching = ec2.describe_instance_connect_endpoints(Filters=[{"Name": "state", "Values": ["create-complete"]}])
    matching_ids = {e["InstanceConnectEndpointId"] for e in matching["InstanceConnectEndpoints"]}
    assert all(e["State"] == "create-complete" for e in matching["InstanceConnectEndpoints"]), (
        f"filter leaked a non-matching state into: {matching['InstanceConnectEndpoints']}"
    )
    assert endpoint_id in matching_ids, f"{endpoint_id} missing from state=create-complete filter: {matching_ids}"

    # ...and excludes it under a state it has never been in.
    excluding = ec2.describe_instance_connect_endpoints(Filters=[{"Name": "state", "Values": ["delete-complete"]}])
    excluding_ids = {e["InstanceConnectEndpointId"] for e in excluding["InstanceConnectEndpoints"]}
    assert endpoint_id not in excluding_ids, f"{endpoint_id} leaked through state=delete-complete filter"

    # Error boundary: DryRun short-circuits before the listing is performed.
    dry_code, dry_message = _error(lambda: ec2.describe_instance_connect_endpoints(DryRun=True))
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code}"
    assert dry_message == _DRY_RUN_MESSAGE, f"expected message {_DRY_RUN_MESSAGE!r}, got {dry_message!r}"


# ===== helpers =====
def _create_endpoint_with_retry(ec2, subnet_id, name, *, timeout_s=180.0, interval_s=15.0):
    """CreateInstanceConnectEndpoint against a low per-account/region endpoint limit.

    Self-heal by deleting any leaked endpoints tagged from earlier runs of this same
    check, then poll-retry: deleting an endpoint does not free its quota slot
    instantaneously.
    """
    deadline = time.monotonic() + timeout_s
    cleaned_up = False
    last_error = None
    while True:
        try:
            return ec2.create_instance_connect_endpoint(
                SubnetId=subnet_id,
                TagSpecifications=[
                    {"ResourceType": "instance-connect-endpoint", "Tags": [{"Key": "Name", "Value": name}]}
                ],
            )["InstanceConnectEndpoint"]["InstanceConnectEndpointId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceLimitExceeded":
                raise
            last_error = exc

        if not cleaned_up:
            _delete_stale_endpoints(ec2)
            cleaned_up = True

        if time.monotonic() >= deadline:
            raise AssertionError(
                "account/region's Instance Connect Endpoint quota is exhausted by endpoints "
                f"outside this check's control even after self-healing leaked endpoints: {last_error}"
            )
        time.sleep(interval_s)


def _delete_stale_endpoints(ec2):
    endpoints = ec2.describe_instance_connect_endpoints()["InstanceConnectEndpoints"]
    for endpoint in endpoints:
        tag_names = {t["Key"]: t["Value"] for t in endpoint.get("Tags", [])}
        if not tag_names.get("Name", "").startswith(_NAME_PREFIX):
            continue
        if endpoint["State"] in ("delete-complete",):
            continue
        try:
            ec2.delete_instance_connect_endpoint(InstanceConnectEndpointId=endpoint["InstanceConnectEndpointId"])
        except ClientError:
            pass


def _existing_vpc_and_subnet(ec2, ctx):
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    candidate_vpc_ids = [v["VpcId"] for v in default_vpcs]
    if not candidate_vpc_ids:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")

    for vpc_id in candidate_vpc_ids:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if subnets:
            return vpc_id, subnets[0]["SubnetId"]

    # No usable VPC/subnet exists yet in this account/region; fall back to creating a
    # dedicated one (and clean it up).
    name = ctx.unique_name(_NAME_PREFIX)
    vpc_id = ec2.create_vpc(
        CidrBlock="10.98.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _ignore(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.98.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _ignore(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))
    return vpc_id, subnet_id


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidInstanceConnectEndpointId.NotFound",
            "InvalidNetworkInterfaceID.NotFound",
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


# EC2 network deletes wait for AWS-managed ENIs to leave: a resource in this VPC deletes asynchronously,
# so DeleteSubnet/DeleteSecurityGroup/DeleteVpc fail with DependencyViolation until its ENIs go. Retry
# that code to one deadline shared by the check's network deletes, then raise naming the ENIs left.
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
