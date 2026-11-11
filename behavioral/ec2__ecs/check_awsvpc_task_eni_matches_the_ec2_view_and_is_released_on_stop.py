"""awsvpc-task-eni-matches-the-ec2-view-and-is-released-on-stop."""
from __future__ import annotations

import sys
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "awsvpc-task-eni-matches-the-ec2-view-and-is-released-on-stop"
GROUP = 'networking'
SERVICES = ['ec2', 'ecs']

_TASK_RUNNING_TIMEOUT_S = 300.0
_TASK_STOPPED_TIMEOUT_S = 300.0
# Fargate ENI release lags the task reaching STOPPED by minutes.
_ENI_RELEASE_TIMEOUT_S = 600.0
_TEARDOWN_TIMEOUT_S = 300.0

_INSTANCE_TYPE_FOR_ZONE = "t3.micro"
_VPC_CIDR = "10.84.0.0/16"
_SUBNET_CIDR = "10.84.1.0/24"

_CONTAINER_DEFS = [{
    "name": "probe",
    "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
    "command": ["sleep", "600"],
    "essential": True,
}]

_GONE = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
         "InvalidInternetGatewayID.NotFound", "InvalidNetworkInterfaceID.NotFound",
         "ClusterNotFoundException")

_DETAIL_NAMES = ("subnetId", "networkInterfaceId", "macAddress", "privateIPv4Address")


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    """Bounded retry that RAISES on timeout. Never a bare sleep."""
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


def _tags(name: str) -> list[dict]:
    return [{"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "awsvpc-task-eni"}]


def _usable_zone(ec2, region: str) -> str:
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE_FOR_ZONE]}],
    )["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ in {region} is usable; offered {sorted(offered)!r}, available "
        f"{sorted(available)!r}"
    )
    return usable[0]


def _build_network(ec2, region: str, name: str, st: dict) -> None:
    """A VPC with one public subnet so the Fargate task can pull its public-ECR image. Nothing
    ambient is discovered: every id in *st* is created here."""
    st["vpc"] = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags(name)}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[st["vpc"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=st["vpc"], EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=st["vpc"], EnableDnsHostnames={"Value": True})

    st["igw"] = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags(name)}],
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=st["igw"], VpcId=st["vpc"])

    main_rt = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [st["vpc"]]}])["RouteTables"]
    assert len(main_rt) == 1, (
        f"a freshly created VPC must have exactly one (main) route table; got "
        f"{[r['RouteTableId'] for r in main_rt]!r}"
    )
    ec2.create_route(RouteTableId=main_rt[0]["RouteTableId"],
                     DestinationCidrBlock="0.0.0.0/0", GatewayId=st["igw"])

    st["subnet"] = ec2.create_subnet(
        VpcId=st["vpc"], CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=_usable_zone(ec2, region),
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags(name)}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=st["subnet"], MapPublicIpOnLaunch={"Value": True})

    sgs = [g["GroupId"] for g in ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [st["vpc"]]}])["SecurityGroups"]
        if g["GroupName"] == "default"]
    assert len(sgs) == 1, (
        f"the created VPC must have exactly one default security group; got {sgs!r}"
    )
    st["sg"] = sgs[0]


def _eni_attachment(task: dict | None) -> dict | None:
    if task is None:
        return None
    for att in task["attachments"]:
        if att["type"] == "ElasticNetworkInterface":
            return att
    return None


def _describe_eni(ec2, eni_id: str) -> dict | None:
    try:
        return ec2.describe_network_interfaces(
            NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidNetworkInterfaceID.NotFound":
            return None
        raise


def _error_code(fn) -> tuple[str, str]:
    """The ClientError (code, message) *fn* raises. RAISES if *fn* succeeds, so acceptance is
    never mistaken for a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return str(err.get("Code")), str(err.get("Message"))
    raise AssertionError("the call under test was expected to be refused and instead succeeded")


def _available_ips(ec2, subnet_id: str) -> int:
    return ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["AvailableIpAddressCount"]


def _teardown(ec2, ecs, st: dict) -> None:
    """Ordered, waiting teardown, IN BAND: every step runs, then whatever it could not remove
    (other than a not-found) is raised, so a leak fails the check."""
    steps: list = []
    if st.get("task"):
        steps.append(("stop-task", lambda: ecs.stop_task(
            cluster=st["cluster"], task=st["task"], reason="sim2real-behav-teardown")))
    if st.get("subnet"):
        steps.append(("await-eni-drain", lambda: _poll(
            lambda: ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [st["subnet"]]}])["NetworkInterfaces"],
            lambda enis: not enis,
            timeout_s=_TEARDOWN_TIMEOUT_S,
            what=f"subnet {st['subnet']} draining its ENIs")))
    if st.get("task_def"):
        steps.append(("deregister-task-def",
                    lambda: ecs.deregister_task_definition(taskDefinition=st["task_def"])))
    if st.get("cluster"):
        steps.append(("delete-cluster", lambda: ecs.delete_cluster(cluster=st["cluster"])))
    if st.get("subnet"):
        steps.append((f"delete-subnet {st['subnet']}",
                    lambda: ec2.delete_subnet(SubnetId=st["subnet"])))
    if st.get("igw"):
        steps.append(("detach-igw", lambda: ec2.detach_internet_gateway(
            InternetGatewayId=st["igw"], VpcId=st["vpc"])))
        steps.append((f"delete-igw {st['igw']}",
                    lambda: ec2.delete_internet_gateway(InternetGatewayId=st["igw"])))
    if st.get("vpc"):
        steps.append((f"delete-vpc {st['vpc']}", lambda: ec2.delete_vpc(VpcId=st["vpc"])))
    left: list[str] = []
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE:
                left.append(f"{label}: {exc.response.get('Error', {}).get('Code')}")
        except (AssertionError, WaiterError) as exc:
            # _poll raises AssertionError on timeout, get_waiter raises WaiterError.
            left.append(f"{label}: {type(exc).__name__}: {str(exc)[:120]}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created, so this run leaked: "
            f"{left!r} (vpc={st.get('vpc')!r} subnet={st.get('subnet')!r} "
            f"cluster={st.get('cluster')!r})"
        )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """An awsvpc task's ECS ENI attachment details match EC2's view of that ENI, the account cannot
    delete it while the task runs, and stopping the task deletes it and frees the subnet address.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-networking-awsvpc.html
    """
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")

    name = ctx.unique_name("sim2real-behav-taskeni-")
    st: dict = {}

    # Teardown is in-band with leftovers asserted; it stays cheap because the ENI release is
    # asserted in the body rather than waited for in a cleanup closure.
    try:
        _build_network(ec2, ctx.region, name, st)
        ips_before = _available_ips(ec2, st["subnet"])

        st["cluster"] = ecs.create_cluster(
            clusterName=name, tags=[{"key": "sim2real", "value": "awsvpc-task-eni"}],
        )["cluster"]["clusterName"]
        st["task_def"] = ecs.register_task_definition(
            family=name,
            containerDefinitions=_CONTAINER_DEFS,
            requiresCompatibilities=["FARGATE"],
            networkMode="awsvpc",
            cpu="256",
            memory="512",
            tags=[{"key": "sim2real", "value": "awsvpc-task-eni"}],
        )["taskDefinition"]["taskDefinitionArn"]
        ctx.on_cleanup(lambda: _retire_task_definition(ecs, st["task_def"]))

        run_resp = ecs.run_task(
            cluster=st["cluster"],
            taskDefinition=st["task_def"],
            launchType="FARGATE",
            count=1,
            networkConfiguration={"awsvpcConfiguration": {
                "subnets": [st["subnet"]], "securityGroups": [st["sg"]],
                "assignPublicIp": "ENABLED"}},
            tags=[{"key": "sim2real", "value": "awsvpc-task-eni"}],
        )
        assert run_resp["failures"] == [], (
            f"RunTask reported failures: {run_resp['failures']!r}"
        )
        st["task"] = run_resp["tasks"][0]["taskArn"]
        task_arn = st["task"]

        def _task():
            # DescribeTasks is eventually consistent right after RunTask: the ARN can be briefly
            # absent, so tolerate an empty list and let the bounded poll retry.
            tasks = ecs.describe_tasks(cluster=st["cluster"], tasks=[task_arn])["tasks"]
            return tasks[0] if tasks else None

        running = _poll(
            _task,
            lambda t: t is not None and t["lastStatus"] == "RUNNING"
            and (a := _eni_attachment(t)) is not None and a["status"] == "ATTACHED",
            timeout_s=_TASK_RUNNING_TIMEOUT_S,
            what=f"task {task_arn} reaching RUNNING with an ATTACHED ENI",
        )
        attachment = _eni_attachment(running)
        assert attachment is not None, (
            f"a RUNNING awsvpc task must carry an ElasticNetworkInterface attachment; the task "
            f"reports {running['attachments']!r}"
        )
        details = {d["name"]: d["value"] for d in attachment["details"]}
        missing = [n for n in _DETAIL_NAMES if n not in details]
        assert missing == [], (
            f"the attachment must carry the details {list(_DETAIL_NAMES)!r}; missing {missing!r}, "
            f"present {sorted(details)!r}"
        )

        # --- the join: EC2's own record of that ENI must agree with ECS's claim ------------
        eni_id = details["networkInterfaceId"]
        eni = _describe_eni(ec2, eni_id)
        assert eni is not None, (
            f"ECS reports networkInterfaceId {eni_id!r} for the RUNNING task, but EC2 has no such "
            f"interface — the attachment names an ENI that does not exist"
        )
        assert eni["PrivateIpAddress"] == details["privateIPv4Address"], (
            f"EC2 reports PrivateIpAddress {eni['PrivateIpAddress']!r} for {eni_id!r}; ECS's "
            f"attachment claims privateIPv4Address {details['privateIPv4Address']!r}"
        )
        assert eni["SubnetId"] == details["subnetId"] == st["subnet"], (
            f"EC2 reports SubnetId {eni['SubnetId']!r}, ECS claims subnetId "
            f"{details['subnetId']!r}, and the check placed the task in {st['subnet']!r}"
        )
        assert eni["MacAddress"] == details["macAddress"], (
            f"EC2 reports MacAddress {eni['MacAddress']!r}; ECS claims macAddress "
            f"{details['macAddress']!r}"
        )
        assert eni["VpcId"] == st["vpc"], (
            f"the task ENI must live in the VPC this check created ({st['vpc']!r}); EC2 reports "
            f"{eni['VpcId']!r}"
        )
        assert eni["Status"] == "in-use", (
            f"an ENI attached to a RUNNING task must be in-use; EC2 reports {eni['Status']!r}"
        )
        assert eni["Attachment"]["Status"] == "attached", (
            f"EC2 must report the attachment as attached; got {eni['Attachment']!r}"
        )
        assert [g["GroupId"] for g in eni["Groups"]] == [st["sg"]], (
            f"the ENI must carry exactly the security group RunTask was given ({st['sg']!r}); EC2 "
            f"reports {[g['GroupId'] for g in eni['Groups']]!r}"
        )
        assert eni["RequesterManaged"] is True, (
            f"a task ENI is created and owned by ECS, so EC2 must report RequesterManaged True; "
            f"got {eni['RequesterManaged']!r} (RequesterId={eni.get('RequesterId')!r})"
        )
        assert eni["InterfaceType"] == "interface", (
            f"expected InterfaceType 'interface', got {eni['InterfaceType']!r}"
        )
        # The address really left the pool.
        ips_held = _available_ips(ec2, st["subnet"])
        assert ips_held == ips_before - 1, (
            f"the task's ENI must consume exactly one subnet address: {ips_before} available "
            f"before the task, {ips_held} while it runs"
        )

        # --- the refusal, with its positive control in the same instant --------------------
        # The refusal code is the generic in-use one: the refusal is about state (attached), not
        # ownership.
        own_eni = ec2.create_network_interface(
            SubnetId=st["subnet"], Groups=[st["sg"]],
            Description="sim2real-behav positive control for DeleteNetworkInterface",
            TagSpecifications=[{"ResourceType": "network-interface", "Tags": _tags(name)}],
        )["NetworkInterface"]["NetworkInterfaceId"]
        # The control proves this account CAN delete an ENI it owns, in this subnet, right now.
        ec2.delete_network_interface(NetworkInterfaceId=own_eni)
        assert _describe_eni(ec2, own_eni) is None, (
            f"the positive control ENI {own_eni!r} must be gone after DeleteNetworkInterface, or "
            f"the refusal below proves nothing"
        )
        refusal, refusal_message = _error_code(
            lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))
        assert refusal == "InvalidParameterValue", (
            f"an ECS-managed task ENI must not be deletable by the account; DeleteNetworkInterface "
            f"on {eni_id!r} answered {refusal!r} while the same call on this account's own ENI "
            f"{own_eni!r} succeeded moments earlier"
        )
        expected = f"Network interface '{eni_id}' is currently in use."
        assert refusal_message == expected, (
            f"DeleteNetworkInterface refusal message on the task ENI: expected {expected!r}, got "
            f"{refusal_message!r}"
        )
        # The effect is absent: the ENI and the task both survived the refused delete.
        survived = _describe_eni(ec2, eni_id)
        assert survived is not None and survived["Status"] == "in-use", (
            f"the refused delete must have changed nothing; EC2 now reports {survived!r}"
        )
        still = _task()
        assert still is not None and still["lastStatus"] == "RUNNING", (
            f"the task must still be RUNNING after the refused delete; ECS reports "
            f"{still['lastStatus'] if still else None!r}"
        )

        # --- the release: stopping the task deletes the ENI --------------------------------
        ecs.stop_task(cluster=st["cluster"], task=task_arn, reason="sim2real-behav-release-leg")
        _poll(_task, lambda t: t is not None and t["lastStatus"] == "STOPPED",
              timeout_s=_TASK_STOPPED_TIMEOUT_S,
              what=f"task {task_arn} reaching STOPPED")
        st["task"] = None
        _poll(lambda: _describe_eni(ec2, eni_id), lambda e: e is None,
              timeout_s=_ENI_RELEASE_TIMEOUT_S, interval_s=10.0,
              what=f"the task ENI {eni_id} being deleted after the task stopped")
        assert _describe_eni(ec2, eni_id) is None, (
            f"a stopped task's ENI must be detached and deleted; EC2 still reports {eni_id!r}"
        )
        ips_after = _poll(lambda: _available_ips(ec2, st["subnet"]),
                          lambda n: n == ips_before,
                          timeout_s=_ENI_RELEASE_TIMEOUT_S, interval_s=10.0,
                          what=f"subnet {st['subnet']} returning to {ips_before} available "
                               f"addresses")
        assert ips_after == ips_before, (
            f"the released address must return to the subnet's pool: {ips_before} before the "
            f"task, {ips_after} after it stopped"
        )
    finally:
        _teardown(ec2, ecs, st)


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
