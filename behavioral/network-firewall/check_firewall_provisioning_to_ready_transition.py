"""firewall-provisioning-to-ready-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-provisioning-to-ready-transition"
GROUP = "state-machine"
SERVICES = ["network-firewall"]

# Prefix of the failure raised when a created resource never reaches its ready state, so a create
# that is accepted but never converges reads as a failed state transition.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new firewall starts PROVISIONING with ConfigurationSyncStateSummary PENDING, config sync
    reaches IN_SYNC, then the firewall reaches READY with SyncStates showing a READY attachment in
    the configured Availability Zone and subnet."""
    fw = _create_basic_firewall(ctx)
    nfw = fw["nfw"]

    first = nfw.describe_firewall(FirewallArn=fw["firewall_arn"])
    assert first["FirewallStatus"]["Status"] in ("PROVISIONING", "READY")
    assert first["FirewallStatus"]["ConfigurationSyncStateSummary"] in ("PENDING", "IN_SYNC", "CAPACITY_CONSTRAINED")

    # ConfigurationSyncStateSummary reaching IN_SYNC is a real state-machine transition independent
    # of endpoint ENI provisioning and can take several minutes on AWS -- assert it lands within a
    # bounded window.
    sync_deadline = time.monotonic() + 400
    desc = first
    sync_summary = desc["FirewallStatus"]["ConfigurationSyncStateSummary"]
    while time.monotonic() < sync_deadline and sync_summary != "IN_SYNC":
        desc = nfw.describe_firewall(FirewallArn=fw["firewall_arn"])
        sync_summary = desc["FirewallStatus"]["ConfigurationSyncStateSummary"]
        assert desc["FirewallStatus"]["Status"] != "FAILED", "firewall entered FAILED state"
        time.sleep(2)
    assert sync_summary == "IN_SYNC", f"config sync never reached IN_SYNC, last={sync_summary}"

    # Endpoint attachment READY requires ENI provisioning across AZs; allow a bounded window.
    ready_deadline = time.monotonic() + 250
    status = desc["FirewallStatus"]["Status"]
    while time.monotonic() < ready_deadline and status != "READY":
        desc = nfw.describe_firewall(FirewallArn=fw["firewall_arn"])
        status = desc["FirewallStatus"]["Status"]
        assert status != "FAILED", "firewall entered FAILED state"
        time.sleep(2)

    if status != "READY":
        raise _never_ready(
            f"firewall endpoint attachment did not reach READY within this check's bounded "
            f"window (last status={status}); full endpoint provisioning can exceed a single "
            f"check's timeout budget for this service",
        )

    sync_states = desc["FirewallStatus"].get("SyncStates", {})
    assert fw["az"] in sync_states, "SyncStates missing the configured Availability Zone"
    attachment = sync_states[fw["az"]]["Attachment"]
    assert attachment["Status"] == "READY"
    assert attachment["SubnetId"] == fw["subnet_id"]
    assert attachment.get("EndpointId", "").startswith("vpce-")


# ===== helpers =====
def _delete_firewall_policy(nfw, policy_arn: str, timeout_s: float = 120.0) -> None:
    """Delete the policy, retrying "still in use" while the deleted firewall releases it; an
    already-deleted policy is fine, any other error (or the deadline) raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn)
            return
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return
            in_use = err["Code"] == "InvalidOperationException" and "still in use" in err.get("Message", "")
            if not in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_basic_firewall(ctx, *, delete_protection=False, subnet_change_protection=False,
                            firewall_policy_change_protection=False, stateful_rule_group_arn=None):
    ec2 = ctx.client("ec2")
    nfw = ctx.client("network-firewall")
    name = ctx.unique_name("sim2real-nfw-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.88.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    def _del_vpc():
        _delete_net(ec2, "delete_vpc", VpcId=vpc_id)

    ctx.on_cleanup(_del_vpc)

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.88.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name + "-subnet"}]}],
    )["Subnet"]["SubnetId"]

    def _del_subnet():
        _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)

    ctx.on_cleanup(_del_subnet)

    policy_doc = {
        "StatelessDefaultActions": ["aws:forward_to_sfe"],
        "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
    }
    if stateful_rule_group_arn:
        policy_doc["StatefulRuleGroupReferences"] = [{"ResourceArn": stateful_rule_group_arn}]
    policy_name = ctx.unique_name("sim2real-nfw-policy-")
    policy_resp = nfw.create_firewall_policy(FirewallPolicyName=policy_name, FirewallPolicy=policy_doc)
    policy_arn = policy_resp["FirewallPolicyResponse"]["FirewallPolicyArn"]
    ctx.on_cleanup(lambda: _delete_firewall_policy(nfw, policy_arn))

    fw_resp = nfw.create_firewall(
        FirewallName=name,
        FirewallPolicyArn=policy_arn,
        VpcId=vpc_id,
        SubnetMappings=[{"SubnetId": subnet_id}],
        DeleteProtection=delete_protection,
        SubnetChangeProtection=subnet_change_protection,
        FirewallPolicyChangeProtection=firewall_policy_change_protection,
    )
    firewall_arn = fw_resp["Firewall"]["FirewallArn"]
    update_token = nfw.describe_firewall(FirewallArn=firewall_arn)["UpdateToken"]

    def _del_firewall():
        try:
            nfw.update_firewall_delete_protection(FirewallArn=firewall_arn, DeleteProtection=False)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            nfw.delete_firewall(FirewallArn=firewall_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline:
            try:
                nfw.describe_firewall(FirewallArn=firewall_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            time.sleep(2)
        raise AssertionError(f"firewall {firewall_arn} still present 420s after DeleteFirewall")

    ctx.on_cleanup(_del_firewall)

    return {
        "nfw": nfw, "ec2": ec2, "name": name, "vpc_id": vpc_id, "subnet_id": subnet_id, "az": az,
        "policy_name": policy_name, "policy_arn": policy_arn, "firewall_arn": firewall_arn,
        "update_token": update_token,
    }


# EC2 network teardown: a resource in this VPC deletes asynchronously and its ENIs can still hold the
# subnet / VPC, failing the delete with DependencyViolation. Wait for those ENIs and retry that code
# within one window shared by the check's network deletes, then raise naming the ENIs still attached.
_NET_TEARDOWN_S = 300.0
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
