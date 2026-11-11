"""two-instances-from-one-launch-keep-independent-stop-and-terminate-states."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


#: AWS-owned public parameter naming the latest Amazon Linux 2023 AMI.
_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
#: The budget for one instance state wait (AWS settles each transition well inside it).
POLL_BUDGET_S = 120.0


#: The runner's deadline for this check (monotonic clock), set as run() starts.
_RUN_END: dict = {}


def _bounded(timeout_s: float) -> float:
    """``timeout_s`` cut to the time the runner leaves this check, so a wait fails with its own
    last observation rather than the runner's timeout."""
    end = _RUN_END.get("t")
    return timeout_s if end is None else max(1.0, min(timeout_s, end - time.monotonic() - 3.0))


def _start_budget(ctx) -> None:
    left = ctx.time_left()
    _RUN_END["t"] = None if left is None else time.monotonic() + left



def _catalog_ami(ctx):
    """ImageId from the AL2023 public parameter, or the newest available amazon or own x86_64
    image when the parameter is absent."""
    try:
        return ctx.client("ssm").get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    except ClientError as exc:
        err = exc.response["Error"]
        # Only a missing parameter (GetParameter's ParameterNotFound, empty message) falls back.
        if (err.get("Code"), err.get("Message") or "") != ("ParameterNotFound", ""):
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
        CidrBlock="10.212.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [run_tag]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
    )
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.212.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [run_tag]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    _poll_until(
        lambda: ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["State"],
        lambda s: s == "available",
    )
    return vpc_id, subnet_id


def _poll_until(probe, predicate, timeout_s=POLL_BUDGET_S, interval_s=2.0):
    timeout_s = _bounded(timeout_s)
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
    timeout_s = _bounded(timeout_s)
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


CHECK = "two-instances-from-one-launch-keep-independent-stop-and-terminate-states"
GROUP = 'instance-lifecycle'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """One RunInstances launches two t3.nano instances whose states move independently: stopping and
    then terminating one from stopped leaves the other running, and the terminated one refuses
    StartInstances; the sibling, still running, then terminates from running."""
    _start_budget(ctx)
    ec2 = ctx.client("ec2")
    ami = _catalog_ami(ctx)
    run_tag = {"Key": "sim2real-check", "Value": ctx.unique_name("inst2-")}
    _vpc_id, subnet_id = _own_subnet(ctx, run_tag)
    launched = ec2.run_instances(
        ImageId=ami, InstanceType="t3.nano", MinCount=2, MaxCount=2, SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}, run_tag]}],
    )["Instances"]
    ids = [i["InstanceId"] for i in launched]
    for iid in ids:
        ctx.on_cleanup(_teardown(lambda i=iid: ec2.terminate_instances(InstanceIds=[i]),
                                 "InvalidInstanceID.NotFound"))
    assert len(set(ids)) == 2, f"RunInstances MinCount=MaxCount=2 returned {len(ids)} instance ids ({len(set(ids))} distinct)"
    first, second = ids
    for iid in ids:
        _wait_instance_state(ec2, iid, "running")
    types = {i["InstanceId"]: i["InstanceType"] for r in ec2.describe_instances(InstanceIds=ids)["Reservations"]
             for i in r["Instances"]}
    assert types == {first: "t3.nano", second: "t3.nano"}, f"expected both instances t3.nano, got {types!r}"

    stop = ec2.stop_instances(InstanceIds=[first])["StoppingInstances"]
    assert [s["InstanceId"] for s in stop] == [first], f"StopInstances echoed {[s['InstanceId'] for s in stop]!r}, expected only the first instance"
    _wait_instance_state(ec2, first, "stopped")
    assert _state(ec2, second) == "running", f"stopping one instance moved its sibling to {_state(ec2, second)!r}"

    # Terminate straight from stopped: the transition reports stopped as the previous state.
    term = ec2.terminate_instances(InstanceIds=[first])["TerminatingInstances"]
    got = [(t["InstanceId"], t["PreviousState"]["Name"]) for t in term]
    assert got == [(first, "stopped")], f"TerminateInstances (id, previous state): expected [(first, 'stopped')], got {got!r}"
    _wait_instance_state(ec2, first, "terminated")
    assert _state(ec2, second) == "running", f"terminating one instance moved its sibling to {_state(ec2, second)!r}"

    live = ec2.describe_instances(Filters=[
        {"Name": f"tag:{run_tag['Key']}", "Values": [run_tag["Value"]]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
    ])["Reservations"]
    live_ids = sorted(i["InstanceId"] for r in live for i in r.get("Instances", []))
    assert live_ids == [second], f"live instances of this launch: expected only the sibling, got {len(live_ids)} ids, sibling included: {second in live_ids}"

    resp = _error(lambda: ec2.start_instances(InstanceIds=[first]))
    err = resp.get("Error", {})
    status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    expected = ("IncorrectInstanceState", f"The instance '{first}' is not in a state from which it can be started.")
    got = (err.get("Code"), err.get("Message"))
    assert got == expected, f"StartInstances on the terminated instance: expected {expected}, got {got!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx for IncorrectInstanceState, got {status!r}"

    term = ec2.terminate_instances(InstanceIds=[second])["TerminatingInstances"]
    got = [(t["InstanceId"], t["PreviousState"]["Name"]) for t in term]
    assert got == [(second, "running")], f"TerminateInstances on the sibling (id, previous state): expected [(second, 'running')], got {got!r}"
    _wait_instance_state(ec2, second, "terminated")


def _state(ec2, instance_id):
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]


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
