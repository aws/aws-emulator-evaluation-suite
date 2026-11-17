"""firewall-policy-change-protection-toggle-invalidates-token."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-policy-change-protection-toggle-invalidates-token"
GROUP = "change-protection"
SERVICES = ["ec2", "network-firewall"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A superseded UpdateToken is refused with InvalidTokenException on
    UpdateFirewallPolicyChangeProtection; the positive control, the same call with the
    current token, returns the new value and a fresh token that DescribeFirewall then reports.

    Reference: https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_UpdateFirewallPolicyChangeProtection.html
    """
    teardown_deadline: dict = {}
    ec2 = ctx.client("ec2")
    nfw = ctx.client("network-firewall")
    tag = ctx.unique_name("sim2real-nfwr-cp-")

    az = _azs(ec2, 1)[0]
    vpc = _vpc(ctx, ec2, "10.4.0.0/16", tag, teardown_deadline)
    subnet = _subnet(ctx, ec2, vpc, "10.4.0.0/24", az, tag, teardown_deadline)
    policy_arn = _policy(ctx, nfw, tag + "-pol", teardown_deadline)

    made = nfw.create_firewall(
        FirewallName=tag, FirewallPolicyArn=policy_arn, VpcId=vpc,
        SubnetMappings=[{"SubnetId": subnet}], FirewallPolicyChangeProtection=True,
    )
    firewall_arn = made["Firewall"]["FirewallArn"]
    assert made["Firewall"]["FirewallPolicyChangeProtection"] is True
    ctx.on_cleanup(lambda: _drop_firewall(ctx, nfw, firewall_arn, teardown_deadline))

    initial = nfw.describe_firewall(FirewallArn=firewall_arn)
    assert initial["Firewall"]["FirewallPolicyChangeProtection"] is True, (
        f"DescribeFirewall reported FirewallPolicyChangeProtection="
        f"{initial['Firewall']['FirewallPolicyChangeProtection']!r} right after create, expected True")
    old_token = initial["UpdateToken"]

    off = nfw.update_firewall_policy_change_protection(
        FirewallArn=firewall_arn, UpdateToken=old_token, FirewallPolicyChangeProtection=False,
    )
    assert off["FirewallPolicyChangeProtection"] is False, (
        f"UpdateFirewallPolicyChangeProtection(False) returned "
        f"FirewallPolicyChangeProtection={off['FirewallPolicyChangeProtection']!r}")
    new_token = off["UpdateToken"]
    assert new_token != old_token, (
        f"UpdateFirewallPolicyChangeProtection kept the same UpdateToken {new_token!r}")

    after = nfw.describe_firewall(FirewallArn=firewall_arn)
    assert after["Firewall"]["FirewallPolicyChangeProtection"] is False, (
        f"DescribeFirewall reported FirewallPolicyChangeProtection="
        f"{after['Firewall']['FirewallPolicyChangeProtection']!r} after the update, expected False")
    assert after["UpdateToken"] == new_token, (
        f"DescribeFirewall's UpdateToken {after['UpdateToken']!r} does not match the "
        f"UpdateToken {new_token!r} the update returned")

    code, message = _error(lambda: nfw.update_firewall_policy_change_protection(
        FirewallArn=firewall_arn, UpdateToken=old_token, FirewallPolicyChangeProtection=True,
    ))
    assert code == "InvalidTokenException", (
        f"reusing the superseded UpdateToken returned {code!r}, expected InvalidTokenException")
    assert message == "Update token isn't valid.", (
        f"reusing the superseded UpdateToken was refused with message {message!r}")

    # effect absent: the stale-token call did not flip the flag back
    still_off = nfw.describe_firewall(FirewallArn=firewall_arn)
    assert still_off["Firewall"]["FirewallPolicyChangeProtection"] is False, (
        f"the refused stale-token call changed FirewallPolicyChangeProtection to "
        f"{still_off['Firewall']['FirewallPolicyChangeProtection']!r}")
    assert still_off["UpdateToken"] == new_token, (
        f"the refused stale-token call advanced UpdateToken to {still_off['UpdateToken']!r}")


# ===== helpers =====

def _teardown_left(teardown_deadline, budget_s: float = 840.0) -> float:
    """Seconds left in this run's teardown window, which opens at its first teardown call."""
    return max(teardown_deadline.setdefault("t", time.monotonic() + budget_s) - time.monotonic(), 0.0)


def _error(fn) -> tuple[str, str]:
    """(code, message) of the AWS error fn() raises; raises itself when the call SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("the call succeeded; real AWS rejects it, so there is no error code")


_RETRYABLE = ("DependencyViolation", "IncorrectState", "InvalidState", "InUse", "Pending",
              "still in use", "still exist in route table")


def _retry_delete(call, what: str, teardown_deadline) -> None:
    """One teardown call, retried every 2 s while a dependency drains, inside the run's teardown
    window; a final failure raises."""
    deadline = time.monotonic() + _teardown_left(teardown_deadline)
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


def _azs(ec2, n: int) -> list[str]:
    zones = [z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"]]
    assert len(zones) >= n, f"region has {len(zones)} available zones {zones!r}; need {n}"
    return sorted(zones)[:n]


def _name(tag: str, rtype: str) -> list[dict]:
    return [{"ResourceType": rtype, "Tags": [{"Key": "Name", "Value": tag}]}]


def _vpc(ctx, ec2, cidr: str, tag: str, teardown_deadline) -> str:
    vpc = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=_name(tag, "vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc), f"vpc {vpc}", teardown_deadline))
    return vpc


def _subnet(ctx, ec2, vpc: str, cidr: str, az: str, tag: str, teardown_deadline) -> str:
    sid = ec2.create_subnet(VpcId=vpc, CidrBlock=cidr, AvailabilityZone=az,
                            TagSpecifications=_name(tag, "subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid), f"subnet {sid}",
                                         teardown_deadline))
    return sid


#: The firewall policy: no rule groups, both stateless defaults forward to the stateful engine.
_POLICY = {
    "StatelessDefaultActions": ["aws:forward_to_sfe"],
    "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
}


def _policy(ctx, nfw, name: str, teardown_deadline) -> str:
    """A firewall policy; its cleanup retries while a firewall still references it."""
    arn = nfw.create_firewall_policy(FirewallPolicyName=name, FirewallPolicy=dict(_POLICY))[
        "FirewallPolicyResponse"]["FirewallPolicyArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: nfw.delete_firewall_policy(FirewallPolicyArn=arn),
                                         f"firewall policy {arn}", teardown_deadline))
    return arn


def _drop_firewall(ctx, nfw, arn: str, teardown_deadline) -> None:
    """Delete the firewall unless it is already deleting, then poll until DescribeFirewall raises."""
    status = _firewall_status(nfw, arn)
    if status == "GONE":
        return
    if status != "DELETING":
        _retry_delete(lambda: nfw.delete_firewall(FirewallArn=arn), f"firewall {arn}", teardown_deadline)
    deadline = time.monotonic() + _teardown_left(teardown_deadline)
    while time.monotonic() < deadline:
        if _firewall_status(nfw, arn) == "GONE":
            return
        time.sleep(2.0)
    raise AssertionError(f"firewall {arn} still present after its teardown window")


def _firewall_status(nfw, arn: str) -> str:
    try:
        return nfw.describe_firewall(FirewallArn=arn)["FirewallStatus"]["Status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
