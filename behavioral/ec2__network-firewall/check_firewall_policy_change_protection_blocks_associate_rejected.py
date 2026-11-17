"""firewall-policy-change-protection-blocks-associate-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-policy-change-protection-blocks-associate-rejected"
GROUP = "change-protection"
SERVICES = ["ec2", "network-firewall"]

#: a minimal firewall policy: no rule groups, both stateless defaults forward to the stateful engine.
_POLICY = {
    "StatelessDefaultActions": ["aws:forward_to_sfe"],
    "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
}

_BLOCKED = ("InvalidOperationException", "Cannot AssociateFirewallPolicy because FirewallPolicyChangeProtection is on")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateFirewallPolicy on a firewall with FirewallPolicyChangeProtection=True is
    refused with InvalidOperationException and the firewall keeps its original policy;
    turning the protection off lets the identical call succeed.

    Reference: https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_AssociateFirewallPolicy.html
    Reference: https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_UpdateFirewallPolicyChangeProtection.html
    """
    deadline_box: dict = {}
    ec2 = ctx.client("ec2")
    nfw = ctx.client("network-firewall")
    tag = ctx.unique_name("sim2real-nfwr-fpcp-")

    az = _az(ec2)
    vpc = _vpc(ctx, ec2, "10.6.0.0/16", tag, deadline_box)
    subnet = _subnet(ctx, ec2, vpc, "10.6.0.0/24", az, tag, deadline_box)
    policy_a_arn = _policy(ctx, nfw, tag + "-a", deadline_box)
    policy_b_arn = _policy(ctx, nfw, tag + "-b", deadline_box)

    made = nfw.create_firewall(
        FirewallName=tag, FirewallPolicyArn=policy_a_arn, VpcId=vpc,
        SubnetMappings=[{"SubnetId": subnet}], FirewallPolicyChangeProtection=True,
    )
    firewall_arn = made["Firewall"]["FirewallArn"]
    ctx.on_cleanup(lambda: _drop_firewall(ctx, nfw, firewall_arn, deadline_box))
    assert made["Firewall"]["FirewallPolicyChangeProtection"] is True, (
        f"CreateFirewall(FirewallPolicyChangeProtection=True) returned "
        f"FirewallPolicyChangeProtection={made['Firewall']['FirewallPolicyChangeProtection']!r}")

    _wait_ready(nfw, firewall_arn, deadline_box)

    before = nfw.describe_firewall(FirewallArn=firewall_arn)
    assert before["Firewall"]["FirewallPolicyChangeProtection"] is True, (
        f"DescribeFirewall reported FirewallPolicyChangeProtection="
        f"{before['Firewall']['FirewallPolicyChangeProtection']!r} once READY, expected True")
    assert before["Firewall"]["FirewallPolicyArn"] == policy_a_arn, (
        f"DescribeFirewall named policy {before['Firewall']['FirewallPolicyArn']!r} before any "
        f"change, expected the policy this firewall was created with")
    token = before["UpdateToken"]

    code, message = _error(lambda: nfw.associate_firewall_policy(
        FirewallArn=firewall_arn, UpdateToken=token, FirewallPolicyArn=policy_b_arn,
    ))
    assert (code, message) == _BLOCKED, (
        f"AssociateFirewallPolicy on a change-protected firewall returned {(code, message)!r}, "
        f"expected {_BLOCKED!r}")

    still_a = nfw.describe_firewall(FirewallArn=firewall_arn)
    assert still_a["Firewall"]["FirewallPolicyArn"] == policy_a_arn, (
        f"the refused AssociateFirewallPolicy changed the firewall's policy to "
        f"{still_a['Firewall']['FirewallPolicyArn']!r}, expected it to keep {policy_a_arn!r}")
    assert still_a["UpdateToken"] == token, (
        f"the refused AssociateFirewallPolicy advanced UpdateToken to {still_a['UpdateToken']!r}")

    off = nfw.update_firewall_policy_change_protection(
        FirewallArn=firewall_arn, UpdateToken=token, FirewallPolicyChangeProtection=False,
    )
    assert off["FirewallPolicyChangeProtection"] is False, (
        f"UpdateFirewallPolicyChangeProtection(False) returned "
        f"FirewallPolicyChangeProtection={off['FirewallPolicyChangeProtection']!r}")
    off_token = off["UpdateToken"]

    # positive control: the identical AssociateFirewallPolicy call now succeeds
    nfw.associate_firewall_policy(
        FirewallArn=firewall_arn, UpdateToken=off_token, FirewallPolicyArn=policy_b_arn,
    )

    after = nfw.describe_firewall(FirewallArn=firewall_arn)
    assert after["Firewall"]["FirewallPolicyArn"] == policy_b_arn, (
        f"AssociateFirewallPolicy with FirewallPolicyChangeProtection off returned "
        f"{after['Firewall']['FirewallPolicyArn']!r}, expected the new policy {policy_b_arn!r}")
    assert after["Firewall"]["FirewallPolicyChangeProtection"] is False, (
        f"DescribeFirewall reported FirewallPolicyChangeProtection="
        f"{after['Firewall']['FirewallPolicyChangeProtection']!r} after turning it off, expected False")
    after_token = after["UpdateToken"]

    back_on = nfw.update_firewall_policy_change_protection(
        FirewallArn=firewall_arn, UpdateToken=after_token, FirewallPolicyChangeProtection=True,
    )
    assert back_on["FirewallPolicyChangeProtection"] is True, (
        f"UpdateFirewallPolicyChangeProtection(True) returned "
        f"FirewallPolicyChangeProtection={back_on['FirewallPolicyChangeProtection']!r}")

    final = nfw.describe_firewall(FirewallArn=firewall_arn)
    assert final["Firewall"]["FirewallPolicyChangeProtection"] is True, (
        f"DescribeFirewall reported FirewallPolicyChangeProtection="
        f"{final['Firewall']['FirewallPolicyChangeProtection']!r} after turning it back on, expected True")
    assert final["Firewall"]["FirewallPolicyArn"] == policy_b_arn, (
        f"DescribeFirewall named policy {final['Firewall']['FirewallPolicyArn']!r} after "
        f"re-enabling change protection, expected it to still be {policy_b_arn!r}")


# ===== helpers =====

def _deadline_left(deadline_box, budget_s: float = 840.0) -> float:
    """Seconds left in this run's teardown window, which opens at its first teardown call."""
    return max(deadline_box.setdefault("t", time.monotonic() + budget_s) - time.monotonic(), 0.0)


def _error(fn) -> tuple[str, str]:
    """(code, message) of the AWS error fn() raises; raises itself when the call SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


_RETRYABLE = ("DependencyViolation", "IncorrectState", "InvalidState", "InUse", "Pending",
              "still in use", "still exist in route table")


def _retry_delete(call, what: str, deadline_box) -> None:
    """One teardown call, retried every 2 s while a dependency drains, inside the run's teardown
    window; a final failure raises."""
    deadline = time.monotonic() + _deadline_left(deadline_box)
    last = None
    while time.monotonic() < deadline:
        try:
            call()
            return
        except Exception as exc:  # noqa: BLE001 - a teardown must not mask the verdict
            last = exc
            text = f"{type(exc).__name__} {exc}"
            if "NotFound" in text or "does not exist" in text or "ResourceNotFound" in text:
                return
            if not any(t in text for t in _RETRYABLE):
                break
            time.sleep(2)
    raise RuntimeError(f"could not delete {what}: {last}")


def _az(ec2) -> str:
    zones = [z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"]]
    assert zones, "region has no available availability zones"
    return sorted(zones)[0]


def _name(tag: str, rtype: str) -> list[dict]:
    return [{"ResourceType": rtype, "Tags": [{"Key": "Name", "Value": tag}]}]


def _vpc(ctx, ec2, cidr: str, tag: str, deadline_box) -> str:
    vpc = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=_name(tag, "vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc), f"vpc {vpc}", deadline_box))
    return vpc


def _subnet(ctx, ec2, vpc: str, cidr: str, az: str, tag: str, deadline_box) -> str:
    sid = ec2.create_subnet(VpcId=vpc, CidrBlock=cidr, AvailabilityZone=az,
                            TagSpecifications=_name(tag, "subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid), f"subnet {sid}",
                                         deadline_box))
    return sid


def _policy(ctx, nfw, name: str, deadline_box) -> str:
    """A firewall policy; its cleanup retries while a firewall still references it."""
    arn = nfw.create_firewall_policy(FirewallPolicyName=name, FirewallPolicy=dict(_POLICY))[
        "FirewallPolicyResponse"]["FirewallPolicyArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: nfw.delete_firewall_policy(FirewallPolicyArn=arn),
                                         f"firewall policy {arn}", deadline_box))
    return arn


def _wait_ready(nfw, arn: str, deadline_box, budget_s: float = 600.0) -> None:
    """Poll DescribeFirewall until FirewallStatus.Status reaches READY."""
    deadline = time.monotonic() + budget_s
    while True:
        status = nfw.describe_firewall(FirewallArn=arn)["FirewallStatus"]["Status"]
        if status == "READY":
            return
        assert status in ("PROVISIONING", "CONFIGURING"), (
            f"firewall reached status {status!r} while waiting for READY")
        assert time.monotonic() < deadline, f"firewall still {status!r} after {budget_s}s"
        time.sleep(5.0)


def _firewall_status(nfw, arn: str) -> str:
    try:
        return nfw.describe_firewall(FirewallArn=arn)["FirewallStatus"]["Status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _drop_firewall(ctx, nfw, arn: str, deadline_box) -> None:
    """Delete the firewall unless it is already deleting, then poll until DescribeFirewall raises."""
    status = _firewall_status(nfw, arn)
    if status == "GONE":
        return
    if status != "DELETING":
        _retry_delete(lambda: nfw.delete_firewall(FirewallArn=arn), f"firewall {arn}", deadline_box)
    deadline = time.monotonic() + _deadline_left(deadline_box)
    while time.monotonic() < deadline:
        if _firewall_status(nfw, arn) == "GONE":
            return
        time.sleep(2.0)
    raise AssertionError(f"firewall {arn} still present after its teardown window")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
