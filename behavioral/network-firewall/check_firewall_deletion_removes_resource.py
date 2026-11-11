"""firewall-deletion-removes-resource."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-deletion-removes-resource"
GROUP = "state-machine"
SERVICES = ["network-firewall"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteFirewall (with DeleteProtection disabled) removes the firewall: it eventually
    disappears from DescribeFirewall and ListFirewalls, and a mutation on it is refused."""
    fw = _create_basic_firewall(ctx)
    nfw = fw["nfw"]

    del_resp = nfw.delete_firewall(FirewallArn=fw["firewall_arn"])
    del_status = del_resp["FirewallStatus"]["Status"]
    assert del_status in ("DELETING", "READY", "PROVISIONING"), (
        f"expected DeleteFirewall's own response to report a pre-deletion status, got {del_status}"
    )

    deadline = time.monotonic() + 300
    removed = False
    gone_message = None
    last_status = None
    while time.monotonic() < deadline:
        try:
            desc = nfw.describe_firewall(FirewallArn=fw["firewall_arn"])
            last_status = desc["FirewallStatus"]["Status"]
            # PROVISIONING may still be observed briefly right after the delete call while the
            # prior create's config sync finishes; it must eventually flip to DELETING.
            assert last_status in ("DELETING", "PROVISIONING"), f"unexpected status while deleting: {last_status}"
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                removed = True
                gone_message = e.response["Error"].get("Message")
                break
            raise
        time.sleep(2)

    assert removed, f"firewall was never removed, last observed status={last_status}"
    expected_gone = "No object with the provided name or resource identifier was found"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"

    listed_arns = {f["FirewallArn"] for f in nfw.list_firewalls().get("Firewalls", [])}
    assert fw["firewall_arn"] not in listed_arns, (
        f"deleted firewall {fw['firewall_arn']} still appears in ListFirewalls: {listed_arns}"
    )

    # a mutation on the now-dead id must also fail, and with the specific not-found code --
    # not just reads.
    mutate_code, mutate_message = _error(
        lambda: nfw.update_firewall_delete_protection(FirewallArn=fw["firewall_arn"], DeleteProtection=False)
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected a mutation on the deleted firewall to fail with ResourceNotFoundException, got {mutate_code}"
    )
    expected_message = "No object with the provided name or resource identifier was found"
    assert mutate_message == expected_message, f"expected message {expected_message!r}, got {mutate_message!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    a target accepting a call real AWS refuses must not pass as an error mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_policy_when_free(nfw, policy_arn, timeout_s=120):
    """Teardown: DeleteFirewallPolicy, retrying while the deleted firewall's association drains."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidOperationException" or time.monotonic() > deadline:
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
    ctx.on_cleanup(lambda: _delete_policy_when_free(nfw, policy_arn))

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
