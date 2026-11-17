"""update-firewall-analysis-settings-replace-by-name-unknown-firewall-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-firewall-analysis-settings-replace-by-name-unknown-firewall-rejected"
GROUP = "error-semantics"
SERVICES = ["network-firewall", "ec2"]

_NOT_FOUND = (
    "ResourceNotFoundException",
    "No object with the provided name or resource identifier was found",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFirewallAnalysisSettings by FirewallName replaces the enabled analysis types rather
    than adding to them, and DescribeFirewall reports exactly the replacement set; the identical
    call against a firewall name that was never created is refused with ResourceNotFoundException."""
    nfw = ctx.client("network-firewall")
    ec2 = ctx.client("ec2")
    firewall_name = _create_ready_firewall(ctx, nfw, ec2)

    before = nfw.describe_firewall(FirewallName=firewall_name)
    assert before["Firewall"].get("EnabledAnalysisTypes") == ["TLS_SNI"], (
        f"expected the new firewall to carry only TLS_SNI, got "
        f"{before['Firewall'].get('EnabledAnalysisTypes')!r}"
    )
    current_token = before["UpdateToken"]

    replaced = nfw.update_firewall_analysis_settings(
        FirewallName=firewall_name,
        UpdateToken=current_token,
        EnabledAnalysisTypes=["HTTP_HOST"],
    )
    assert replaced.get("EnabledAnalysisTypes") == ["HTTP_HOST"], (
        f"UpdateFirewallAnalysisSettings returned {replaced.get('EnabledAnalysisTypes')!r}, "
        f"expected [HTTP_HOST] to have replaced [TLS_SNI], not merged with it"
    )

    after = nfw.describe_firewall(FirewallName=firewall_name)
    assert after["Firewall"].get("EnabledAnalysisTypes") == ["HTTP_HOST"], (
        f"DescribeFirewall reports {after['Firewall'].get('EnabledAnalysisTypes')!r} after the "
        f"replacement, expected exactly [HTTP_HOST]"
    )
    live_token = after["UpdateToken"]

    missing_name = ctx.unique_name("sim2real-nfw-missing-")
    code, message = _expect_error(
        lambda: nfw.update_firewall_analysis_settings(
            FirewallName=missing_name,
            UpdateToken=live_token,
            EnabledAnalysisTypes=["HTTP_HOST"],
        )
    )
    assert code == _NOT_FOUND[0], (
        f"UpdateFirewallAnalysisSettings on a firewall name that was never created gave code "
        f"{code!r}, expected {_NOT_FOUND[0]!r}"
    )
    assert message == _NOT_FOUND[1], (
        f"UpdateFirewallAnalysisSettings on a firewall name that was never created gave message "
        f"{message!r}, expected {_NOT_FOUND[1]!r}"
    )

    still = nfw.describe_firewall(FirewallName=firewall_name)
    assert still["Firewall"].get("EnabledAnalysisTypes") == ["HTTP_HOST"], (
        f"after the refused call on the unknown name, the real firewall's analysis types read "
        f"{still['Firewall'].get('EnabledAnalysisTypes')!r}, expected the earlier replacement "
        f"[HTTP_HOST] to still stand"
    )


# ===== helpers =====
def _expect_error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_ready_firewall(ctx, nfw, ec2) -> str:
    """Create a VPC, subnet, firewall policy and firewall with TLS_SNI analysis enabled, wait
    for it to reach READY, and register cleanup for every piece in reverse order."""
    name = ctx.unique_name("sim2real-nfwanalysis-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.95.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _delete_retrying_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.95.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_retrying_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    policy_name = ctx.unique_name("sim2real-nfwanalysis-policy-")
    policy_arn = nfw.create_firewall_policy(
        FirewallPolicyName=policy_name,
        FirewallPolicy={
            "StatelessDefaultActions": ["aws:forward_to_sfe"],
            "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
        },
    )["FirewallPolicyResponse"]["FirewallPolicyArn"]
    ctx.on_cleanup(lambda: _delete_policy_once_unreferenced(nfw, policy_arn))

    nfw.create_firewall(
        FirewallName=name,
        FirewallPolicyArn=policy_arn,
        VpcId=vpc_id,
        SubnetMappings=[{"SubnetId": subnet_id}],
        DeleteProtection=False,
        SubnetChangeProtection=False,
        FirewallPolicyChangeProtection=False,
        EnabledAnalysisTypes=["TLS_SNI"],
    )
    ctx.on_cleanup(lambda: _delete_firewall_and_await_gone(nfw, name))

    _wait_for_ready(nfw, name)
    return name


def _wait_for_ready(nfw, name: str, budget_s: float = 600.0, interval_s: float = 10.0) -> None:
    deadline = time.monotonic() + budget_s
    while True:
        status = nfw.describe_firewall(FirewallName=name)["FirewallStatus"]["Status"]
        if status == "READY":
            return
        if status == "FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"firewall {name!r} did not reach READY, last status {status!r}")
        time.sleep(interval_s)


def _delete_firewall_and_await_gone(nfw, name: str, budget_s: float = 600.0, interval_s: float = 5.0) -> None:
    try:
        nfw.delete_firewall(FirewallName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + budget_s
    while True:
        try:
            nfw.describe_firewall(FirewallName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"firewall {name!r} was still visible {budget_s}s after DeleteFirewall")
        time.sleep(interval_s)


def _delete_policy_once_unreferenced(nfw, policy_arn: str, budget_s: float = 120.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + budget_s
    while True:
        try:
            nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "InvalidOperationException" or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _delete_retrying_dependency(fn, budget_s: float = 300.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
