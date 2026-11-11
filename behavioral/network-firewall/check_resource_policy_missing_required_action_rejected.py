"""resource-policy-missing-required-action-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-missing-required-action-rejected"
GROUP = "overly-permissive"
SERVICES = ["network-firewall"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy on a firewall policy naming an action outside AssociateFirewallPolicy and
    ListFirewallPolicies fails with InvalidResourcePolicyException and the exact message and attaches
    nothing; a policy limited to the allowed actions is attached."""
    nfw = ctx.client("network-firewall")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    policy_name = ctx.unique_name("sim2real-nfw-policy-")
    created = nfw.create_firewall_policy(
        FirewallPolicyName=policy_name,
        FirewallPolicy={
            "StatelessDefaultActions": ["aws:forward_to_sfe"],
            "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
        },
        Tags=[{"Key": "Name", "Value": policy_name}],
    )
    policy_arn = created["FirewallPolicyResponse"]["FirewallPolicyArn"]
    ctx.on_cleanup(lambda: nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn))

    # network-firewall:DeleteFirewallPolicy is outside the fixed action set AWS allows for a
    # firewall-policy resource (only AssociateFirewallPolicy/ListFirewallPolicies), so the
    # policy statement fails validation.
    incomplete_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": account_id},
            "Action": ["network-firewall:DeleteFirewallPolicy"],
            "Resource": policy_arn,
        }],
    })
    code, message = _error(lambda: nfw.put_resource_policy(ResourceArn=policy_arn, Policy=incomplete_doc))
    assert code == "InvalidResourcePolicyException", f"expected InvalidResourcePolicyException, got {code}"
    expected_message = "The supplied policy does not match RAM managed permissions."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no resource policy got attached
    absent_code, absent_message = _error(lambda: nfw.describe_resource_policy(ResourceArn=policy_arn))
    assert absent_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException (no policy attached), got {absent_code}"
    )
    expected_absent = "No object with the provided name or resource identifier was found"
    assert absent_message == expected_absent, f"expected message {expected_absent!r}, got {absent_message!r}"

    # positive control: sticking to the allowed action set succeeds
    complete_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": account_id},
            "Action": ["network-firewall:AssociateFirewallPolicy", "network-firewall:ListFirewallPolicies"],
            "Resource": policy_arn,
        }],
    })
    nfw.put_resource_policy(ResourceArn=policy_arn, Policy=complete_doc)
    ctx.on_cleanup(lambda: _delete_resource_policy_ignore_missing(nfw, policy_arn))
    attached = nfw.describe_resource_policy(ResourceArn=policy_arn)
    assert "AssociateFirewallPolicy" in attached["Policy"], (
        f"expected the allowed-action policy to be attached, got {attached['Policy']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_resource_policy_ignore_missing(nfw, resource_arn):
    try:
        nfw.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "InvalidResourcePolicyException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


