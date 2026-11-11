"""instance-run-stop-start-terminate-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


#: AWS-owned public parameter naming the latest Amazon Linux 2023 AMI.
_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
#: The budget for one instance state wait.
POLL_BUDGET_S = 600.0


def _catalog_ami(ctx):
    """ImageId from the AL2023 public parameter, or the newest available amazon or own x86_64
    image when the parameter is absent."""
    try:
        return ctx.client("ssm").get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    except ClientError as exc:
        err = exc.response["Error"]
        # Only a missing parameter falls back to DescribeImages.
        if err["Code"] != "ParameterNotFound":
            raise AssertionError(
                f"prerequisite catalog-ami: GetParameter({_AMI_PARAM}) failed: {exc}"
            ) from exc
    images = ctx.client("ec2").describe_images(
        Owners=["amazon", "self"],
        Filters=[
            {"Name": "architecture", "Values": ["x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError(
            f"prerequisite catalog-ami: {_AMI_PARAM} is absent and DescribeImages lists no "
            "available amazon or own x86_64 image"
        )
    return max(images, key=lambda i: i.get("CreationDate", ""))["ImageId"]


def _own_subnet(ctx, run_tag):
    """Return (vpc_id, subnet_id) of a VPC+subnet this check creates and tears down itself."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [run_tag]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
    )
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.211.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [run_tag]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    _poll_until(
        lambda: ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["State"],
        lambda s: s == "available",
    )
    return vpc_id, subnet_id


def _poll_until(probe, predicate, timeout_s=POLL_BUDGET_S, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn(); return the ClientError response it raises. A success raises AssertionError:
    a target that accepts what AWS refuses fails loudly here."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_instance_state(ec2, instance_id, state, timeout_s=POLL_BUDGET_S):
    """Poll DescribeInstances until the instance reaches *state* (swallows the
    eventually-consistent InvalidInstanceID.NotFound window right after launch)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        reservations = resp.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            last = "__not_yet_visible__"
        else:
            last = reservations[0]["Instances"][0]["State"]["Name"]
        if last == state:
            return last
        time.sleep(3)
    raise AssertionError(
        f"instance {instance_id} did not reach {state!r} within {timeout_s}s (last {last!r})"
    )


CHECK = "instance-run-stop-start-terminate-lifecycle"
GROUP = 'instance-lifecycle'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RunInstances -> pending/running -> StopInstances -> stopped -> StartInstances -> running -> TerminateInstances -> terminated -> a mutation on the terminated id is rejected."""
    ec2 = ctx.client("ec2")
    ami = _catalog_ami(ctx)
    run_tag = {"Key": "sim2real-check", "Value": ctx.unique_name("inst-")}
    _vpc_id, subnet_id = _own_subnet(ctx, run_tag)
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1, SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}, run_tag]}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(_teardown(lambda: ec2.terminate_instances(InstanceIds=[instance_id]),
                             "InvalidInstanceID.NotFound"))
    _wait_instance_state(ec2, instance_id, "running")
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    az = inst["Placement"]["AvailabilityZone"]
    assert az.startswith(ctx.region), f"instance placed in AZ {az!r}, not in region {ctx.region!r}"
    assert inst["SubnetId"] == subnet_id, f"instance SubnetId {inst['SubnetId']!r}, expected {subnet_id!r}"
    stop_resp = ec2.stop_instances(InstanceIds=[instance_id])
    got = stop_resp["StoppingInstances"][0]["InstanceId"]
    assert got == instance_id, f"StopInstances echoed InstanceId {got!r}, expected {instance_id!r}"
    _wait_instance_state(ec2, instance_id, "stopped")

    start_resp = ec2.start_instances(InstanceIds=[instance_id])
    got = start_resp["StartingInstances"][0]["InstanceId"]
    assert got == instance_id, f"StartInstances echoed InstanceId {got!r}, expected {instance_id!r}"
    _wait_instance_state(ec2, instance_id, "running")

    term_resp = ec2.terminate_instances(InstanceIds=[instance_id])
    got = term_resp["TerminatingInstances"][0]["InstanceId"]
    assert got == instance_id, f"TerminateInstances echoed InstanceId {got!r}, expected {instance_id!r}"
    # Gone beat 1 (EC2 tombstone): the instance reads terminated by id.
    _wait_instance_state(ec2, instance_id, "terminated")

    # Gone beat 2: no live instance carries this run's tag.
    live = ec2.describe_instances(Filters=[
        {"Name": f"tag:{run_tag['Key']}", "Values": [run_tag["Value"]]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
    ])["Reservations"]
    live_ids = [i["InstanceId"] for r in live for i in r.get("Instances", [])]
    assert instance_id not in live_ids, f"terminated instance still listed among live instances: {live_ids!r}"

    # Gone beat 3: StartInstances on the terminated id is refused, never silently accepted.
    resp = _error(lambda: ec2.start_instances(InstanceIds=[instance_id]))
    err = resp.get("Error", {})
    status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    expected = (
        "IncorrectInstanceState",
        f"The instance '{instance_id}' is not in a state from which it can be started.",
    )
    got = (err.get("Code"), err.get("Message"))
    assert got == expected, f"StartInstances on the terminated instance: expected {expected}, got {got!r}"
    # EC2 query-protocol client errors are HTTP 400 (EC2 API error-code reference).
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx for IncorrectInstanceState, got {status!r}"


# AWS-managed ENIs of a resource in this VPC delete asynchronously, so DeleteSubnet / DeleteVpc
# fail DependencyViolation while they remain: _delete_net retries that code inside one window
# shared by the network deletes, treats not-found as gone, and raises naming the ENIs left.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_NOT_FOUND = {
    "delete_vpc": "InvalidVpcID.NotFound",
    "delete_subnet": "InvalidSubnetID.NotFound",
    "delete_security_group": "InvalidGroup.NotFound",
}
_NET_DEADLINES: dict = {}


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own ``not_found`` codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_net(client, op, **ident):
    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while True:
        try:
            getattr(client, op)(**ident)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == _NET_NOT_FOUND[op]:
                return
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}) still answered DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(10)


def _net_enis(client, flt):
    if not flt:
        return []
    enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
