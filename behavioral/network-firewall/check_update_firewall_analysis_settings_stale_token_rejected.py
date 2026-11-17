"""update-firewall-analysis-settings-stale-token-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-firewall-analysis-settings-stale-token-rejected"
GROUP = "error-semantics"
SERVICES = ["network-firewall", "ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFirewallAnalysisSettings adds HTTP_HOST to a firewall already analyzing TLS_SNI,
    DescribeFirewall reflects both types under a fresh UpdateToken, repeating the call with the
    superseded token is refused with InvalidTokenException, and an empty list disables analysis."""
    nfw = ctx.client("network-firewall")
    ec2 = ctx.client("ec2")
    fw = _create_firewall(ctx, nfw, ec2, enabled_analysis_types=["TLS_SNI"])
    firewall_arn = fw["firewall_arn"]

    before = nfw.describe_firewall(FirewallArn=firewall_arn)
    assert set(before["Firewall"].get("EnabledAnalysisTypes", [])) == {"TLS_SNI"}, (
        f"expected the firewall to start with only TLS_SNI enabled, got "
        f"{before['Firewall'].get('EnabledAnalysisTypes')!r}"
    )
    stale_token = before["UpdateToken"]

    toggled = nfw.update_firewall_analysis_settings(
        FirewallArn=firewall_arn, UpdateToken=stale_token,
        EnabledAnalysisTypes=["TLS_SNI", "HTTP_HOST"],
    )
    assert set(toggled["EnabledAnalysisTypes"]) == {"TLS_SNI", "HTTP_HOST"}, (
        f"UpdateFirewallAnalysisSettings returned {toggled['EnabledAnalysisTypes']!r}, "
        f"expected TLS_SNI and HTTP_HOST"
    )
    fresh_token = toggled["UpdateToken"]
    assert fresh_token != stale_token, (
        f"UpdateFirewallAnalysisSettings returned the same UpdateToken {fresh_token!r} "
        f"it was called with"
    )

    after_toggle = nfw.describe_firewall(FirewallArn=firewall_arn)
    assert set(after_toggle["Firewall"].get("EnabledAnalysisTypes", [])) == {"TLS_SNI", "HTTP_HOST"}, (
        f"DescribeFirewall reports {after_toggle['Firewall'].get('EnabledAnalysisTypes')!r} after "
        f"the toggle, expected TLS_SNI and HTTP_HOST"
    )
    assert after_toggle["UpdateToken"] == fresh_token, (
        f"DescribeFirewall's UpdateToken {after_toggle['UpdateToken']!r} does not match the "
        f"token {fresh_token!r} the update returned"
    )

    _STALE_TOKEN_ERROR = ("InvalidTokenException", "Update token isn't valid.")
    code, message = _expect_error(
        lambda: nfw.update_firewall_analysis_settings(
            FirewallArn=firewall_arn, UpdateToken=stale_token,
            EnabledAnalysisTypes=["TLS_SNI"],
        )
    )
    assert code == _STALE_TOKEN_ERROR[0], (
        f"replaying the superseded UpdateToken gave code {code!r}, expected "
        f"{_STALE_TOKEN_ERROR[0]!r}"
    )
    assert message == _STALE_TOKEN_ERROR[1], (
        f"replaying the superseded UpdateToken gave message {message!r}, expected "
        f"{_STALE_TOKEN_ERROR[1]!r}"
    )

    # the refused replay must not have changed anything: both the enabled types and the token
    # stay exactly where the successful toggle above left them.
    still_after = nfw.describe_firewall(FirewallArn=firewall_arn)
    assert set(still_after["Firewall"].get("EnabledAnalysisTypes", [])) == {"TLS_SNI", "HTTP_HOST"}, (
        f"after the refused replay, DescribeFirewall reports "
        f"{still_after['Firewall'].get('EnabledAnalysisTypes')!r}, expected the toggle's "
        f"TLS_SNI and HTTP_HOST to be unchanged"
    )
    assert still_after["UpdateToken"] == fresh_token, (
        f"after the refused replay, UpdateToken is {still_after['UpdateToken']!r}, expected it "
        f"to remain {fresh_token!r}"
    )

    # positive control: the same disabling update, using the CURRENT token, succeeds and is
    # reflected by DescribeFirewall.
    disabled = nfw.update_firewall_analysis_settings(
        FirewallArn=firewall_arn, UpdateToken=fresh_token, EnabledAnalysisTypes=[],
    )
    assert disabled.get("EnabledAnalysisTypes", []) == [], (
        f"UpdateFirewallAnalysisSettings with an empty list returned "
        f"{disabled.get('EnabledAnalysisTypes')!r}, expected no analysis types enabled"
    )

    after_disable = nfw.describe_firewall(FirewallArn=firewall_arn)
    assert after_disable["Firewall"].get("EnabledAnalysisTypes", []) == [], (
        f"DescribeFirewall reports {after_disable['Firewall'].get('EnabledAnalysisTypes')!r} "
        f"after disabling analysis, expected no analysis types enabled"
    )


def _expect_error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_firewall(ctx, nfw, ec2, *, enabled_analysis_types):
    name = ctx.unique_name("sim2real-nfw-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(_teardown(
        lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)), "InvalidVpcID.NotFound"
    ))

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.91.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name + "-subnet"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(_teardown(
        lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id)), "InvalidSubnetID.NotFound"
    ))

    policy_name = ctx.unique_name("sim2real-nfw-policy-")
    policy_resp = nfw.create_firewall_policy(
        FirewallPolicyName=policy_name,
        FirewallPolicy={
            "StatelessDefaultActions": ["aws:forward_to_sfe"],
            "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
        },
    )
    policy_arn = policy_resp["FirewallPolicyResponse"]["FirewallPolicyArn"]

    def _del_policy():
        _delete_firewall_policy_when_free(nfw, policy_arn)

    ctx.on_cleanup(_del_policy)

    fw_resp = nfw.create_firewall(
        FirewallName=name,
        FirewallPolicyArn=policy_arn,
        VpcId=vpc_id,
        SubnetMappings=[{"SubnetId": subnet_id}],
        DeleteProtection=False,
        EnabledAnalysisTypes=list(enabled_analysis_types),
    )
    firewall_arn = fw_resp["Firewall"]["FirewallArn"]

    def _del_firewall():
        try:
            nfw.delete_firewall(FirewallArn=firewall_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        for _ in range(90):
            try:
                nfw.describe_firewall(FirewallArn=firewall_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            time.sleep(5)
        raise AssertionError(f"firewall {firewall_arn} was not deleted within 450s")

    ctx.on_cleanup(_del_firewall)

    return {"firewall_arn": firewall_arn, "policy_arn": policy_arn}


def _retry_dependency(fn, timeout_s=180, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "DependencyViolation" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_firewall_policy_when_free(nfw, policy_arn, timeout_s=120, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if e.response["Error"]["Code"] == "InvalidOperationException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
