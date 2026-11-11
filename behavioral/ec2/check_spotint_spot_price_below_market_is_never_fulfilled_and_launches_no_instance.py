"""spotint-spot-price-below-market-is-never-fulfilled-and-launches-no-instance."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "spotint-spot-price-below-market-is-never-fulfilled-and-launches-no-instance"
GROUP = 'spot-interruption'
SERVICES = ['ec2']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"
_PRODUCT = "Linux/UNIX"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_VPC_CIDR = "10.187.0.0/16"
_SUBNET_CIDR = "10.187.1.0/24"
#: The lowest price RequestSpotInstances will accept at all. Measured, not assumed: a bid of
#: "0.000800" is refused outright with InvalidParameterValue ('"0.000800" is an invalid spot
#: instance price'), so the under-bid cannot simply be some fraction of the market — below this
#: floor the request is a validation error rather than the price-too-low outcome under test.
_MIN_EXPRESSIBLE_PRICE = "0.001"

# ===== helpers =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _call_with_retry(fn, codes=_THROTTLE, retries=40, delay=5.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if _code(exc) in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    """Poll probe() until predicate(result); AssertionError on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _delete_with_retry(fn, *, gone=(), busy=("DependencyViolation", "InvalidParameterDependency"),
                       attempts=40, delay=5.0):
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = _code(exc)
            if code in gone:
                return None
            if code in busy and attempt < attempts - 1:
                time.sleep(delay)
                continue
            raise


def _usable_az(ec2, instance_type=_INSTANCE_TYPE):
    """An AZ that is BOTH 'available' and offers instance_type — neither call answers both."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _network(ctx, scenario):
    """A dedicated VPC with one subnet and one security group, built rather than borrowed."""
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2)

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id),
                                              gone=("InvalidVpcID.NotFound",)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-spotint-"), VpcId=vpc_id,
        Description="sim2real spot-interruption price floor",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return subnet_id, sg_id, az


def _market_price(ec2, az):
    """The current spot price for this type in this AZ, read off DescribeSpotPriceHistory.

    Derived, never assumed: the whole point of the check is a bid strictly below the live market, and
    the market is the one number in it that nobody controls.
    """
    history = ec2.describe_spot_price_history(
        InstanceTypes=[_INSTANCE_TYPE], ProductDescriptions=[_PRODUCT],
        AvailabilityZone=az, MaxResults=1,
    )["SpotPriceHistory"]
    assert history, (
        f"DescribeSpotPriceHistory returned no price for {_INSTANCE_TYPE!r}/{_PRODUCT!r} in "
        f"{az!r}; without a market price there is nothing to bid below"
    )
    price = float(history[0]["SpotPrice"])
    assert price > 0.0, f"the market price must be positive, got {history[0]!r}"
    return price


def _spot_request(ec2, request_id):
    """The spot request record off a PAGINATED describe, or None if it is not visible yet.

    A request RequestSpotInstances has already returned an id for is not immediately describable by
    that id (measured: InvalidSpotInstanceRequestID.NotFound for the first few seconds), so
    'not there yet' is None and every caller polls rather than reading it as a verdict.
    """
    try:
        for page in ec2.get_paginator("describe_spot_instance_requests").paginate(
                SpotInstanceRequestIds=[request_id]):
            for req in page["SpotInstanceRequests"]:
                if req["SpotInstanceRequestId"] == request_id:
                    return req
    except ClientError as exc:
        if _code(exc) != "InvalidSpotInstanceRequestID.NotFound":
            raise
    return None


def _spot_request_seen(ec2, request_id, timeout_s=180):
    """The spot request record, waiting out the create-to-describe consistency gap."""
    return _poll(lambda: _spot_request(ec2, request_id), lambda r: r is not None,
                 timeout_s=timeout_s, interval_s=5.0,
                 what=f"spot request {request_id} becoming describable")


def _instances_of_request(ec2, request_id):
    """Every instance EC2 attributes to this spot request, off a PAGINATED DescribeInstances.

    This is the absence oracle: it asks EC2 itself what the request launched rather than trusting
    the request record's own InstanceId field to be honest about having launched nothing.
    """
    found = []
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "spot-instance-request-id", "Values": [request_id]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["State"]["Name"] != "terminated":
                    found.append((inst["InstanceId"], inst["State"]["Name"]))
    return found


def _instance_state(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait for 'terminated' — the subnet and VPC deletions depend on it."""
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _instance_state(ec2, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _cancel_request_and_reap(ec2, request_id):
    """Cancel the request AND terminate whatever it launched, resolved at teardown time.

    RequestSpotInstances cannot tag the instance it eventually launches — LaunchSpecification has no
    TagSpecifications member — so between fulfilment and a follow-up CreateTags the instance carries
    no tag. Registering this teardown against the REQUEST, before any instance exists, and resolving
    the instance id here finds it wherever the check aborts.
    """
    try:
        _call_with_retry(
            lambda: ec2.cancel_spot_instance_requests(SpotInstanceRequestIds=[request_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidSpotInstanceRequestID.NotFound":
            raise
    for instance_id, _state in _instances_of_request(ec2, request_id):
        _terminate_and_wait(ec2, instance_id)


# ===== end helpers =====


@tags("axis:negative-delivery", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A spot request priced below the live market is accepted, settles at open/price-too-low and
    launches no instance, while the same launch specification with no maximum price is fulfilled,
    so the refusal is attributable to the bid alone."""
    scenario = "spotint-price-too-low"
    ec2 = ctx.client("ec2")
    subnet_id, sg_id, az = _network(ctx, scenario)
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"

    launch_spec = {
        "ImageId": ami,
        "InstanceType": _INSTANCE_TYPE,
        "SubnetId": subnet_id,
        "SecurityGroupIds": [sg_id],
    }

    def _request(scenario_tag, **kwargs):
        return _call_with_retry(lambda: ec2.request_spot_instances(
            Type="one-time", InstanceCount=1, LaunchSpecification=launch_spec,
            TagSpecifications=[{"ResourceType": "spot-instances-request", "Tags": [
                {"Key": "sim2real", "Value": scenario_tag}]}],
            **kwargs,
        ))["SpotInstanceRequests"][0]

    market = _market_price(ec2, az)
    underbid = _MIN_EXPRESSIBLE_PRICE
    # The market is read, never assumed; if it has fallen to or below EC2's minimum expressible bid
    # then no request in this region can be under-bid at all, and that is a finding about the region
    # rather than a price to invent.
    assert float(underbid) < market, (
        f"the lowest bid EC2 accepts ({underbid!r}) must be strictly below the live market price "
        f"for {_INSTANCE_TYPE!r}/{_PRODUCT!r} in {az!r} ({market!r}), or there is no under-bid to "
        f"test: the scenario is inexpressible here"
    )

    # --- the refusal: accepted, then never fulfilled ----------------------------------------------
    under = _request(scenario, SpotPrice=underbid)
    request_id = under["SpotInstanceRequestId"]
    ctx.on_cleanup(lambda: _cancel_request_and_reap(ec2, request_id))
    assert under["State"] == "open", (
        f"an under-bid request is well-formed and must be ACCEPTED into state 'open' rather than "
        f"rejected; RequestSpotInstances returned {under['State']!r} ({under.get('Status')!r})"
    )
    assert abs(float(under["SpotPrice"]) - float(underbid)) < 1e-9, (
        f"the request must carry back the maximum price it was given ({underbid!r}), got "
        f"{under.get('SpotPrice')!r}"
    )

    settled = _poll(
        lambda: _spot_request(ec2, request_id),
        lambda r: r is not None and r["Status"]["Code"] != "pending-evaluation",
        timeout_s=300, interval_s=5.0,
        what=f"spot request {request_id} settling out of 'pending-evaluation'")
    assert settled["Status"]["Code"] == "price-too-low", (
        f"a bid of {underbid!r} against a market of {market!r} must settle at status code "
        f"'price-too-low', got {settled['Status']!r} (state {settled['State']!r})"
    )
    assert settled["State"] == "open", (
        f"an under-bid request stays 'open' waiting for the market rather than failing; got "
        f"{settled['State']!r}"
    )
    assert "InstanceId" not in settled, (
        f"an unfulfilled request names no instance; it reported {settled.get('InstanceId')!r}"
    )

    # --- the effect that must be ABSENT, asked of EC2 rather than of the request record -----------
    # Given two more minutes to be wrong: a target that fulfils an under-bid slowly is still wrong.
    deadline = time.monotonic() + 120
    while True:
        launched = _instances_of_request(ec2, request_id)
        assert launched == [], (
            f"a request at {underbid!r} against a market of {market!r} must launch nothing, but "
            f"DescribeInstances filtered to {request_id} found {launched!r}. Fulfilling an "
            f"under-bid bills a customer who asked not to be billed above their maximum price."
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(2)

    # --- positive control, in this file: only the price differs ------------------------------------
    control = _request(scenario)
    control_id = control["SpotInstanceRequestId"]
    ctx.on_cleanup(lambda: _cancel_request_and_reap(ec2, control_id))
    assert "SpotPrice" not in control or float(control["SpotPrice"]) >= market, (
        f"the control omits SpotPrice so its maximum defaults to the on-demand price, which must be "
        f"at or above the market {market!r}; the request reported {control.get('SpotPrice')!r}"
    )
    fulfilled = _poll(
        lambda: _spot_request(ec2, control_id),
        lambda r: r is not None and r["State"] in ("active", "closed", "failed", "cancelled"),
        timeout_s=600, interval_s=5.0,
        what=f"the control spot request {control_id} leaving state 'open'")
    assert fulfilled["State"] == "active", (
        f"the control request must be fulfilled: expected state 'active', got "
        f"{fulfilled['State']!r} ({fulfilled.get('Status')!r}). Without this, the refusal above "
        f"could be explained by the AMI, the subnet or the instance type rather than by the price."
    )
    assert fulfilled["Status"]["Code"] == "fulfilled", (
        f"the control request must report status code 'fulfilled', got {fulfilled['Status']!r}"
    )
    control_instance = fulfilled.get("InstanceId")
    assert control_instance, (
        f"a fulfilled request names the instance it launched; the control reported "
        f"{control_instance!r}"
    )
    # Tagged the moment it is knowable: RequestSpotInstances could not tag it at create time.
    _call_with_retry(lambda: ec2.create_tags(
        Resources=[control_instance],
        Tags=[{"Key": "sim2real", "Value": scenario},
              {"Key": "Name", "Value": ctx.unique_name("sim2real-spotint-")}]))
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, control_instance))
    assert _instances_of_request(ec2, control_id) != [], (
        f"the same absence oracle must SEE the control's instance {control_instance!r}; a filter "
        f"that returns nothing for a request that did launch would have made the assertion above "
        f"vacuous"
    )

    # And the refused request is still refused — the market did not move under the check.
    still = _spot_request_seen(ec2, request_id)
    assert still["Status"]["Code"] == "price-too-low", (
        f"the under-bid request must still be 'price-too-low' at the end of the run, got "
        f"{still['Status']!r}; if the market fell below {underbid!r} mid-run the refusal this "
        f"check asserts was not the one it observed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
