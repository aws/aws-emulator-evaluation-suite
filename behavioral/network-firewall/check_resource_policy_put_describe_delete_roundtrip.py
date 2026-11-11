"""resource-policy-put-describe-delete-roundtrip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-put-describe-delete-roundtrip"
GROUP = "resource-config"
SERVICES = ["network-firewall"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy/DescribeResourcePolicy/DeleteResourcePolicy form a full lifecycle on
    a firewall policy: the attached policy document round-trips exactly, and after deletion
    DescribeResourcePolicy reports ResourceNotFoundException again."""
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    policy_arn = created["FirewallPolicyResponse"]["FirewallPolicyArn"]
    ctx.on_cleanup(lambda: nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn))

    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": account_id},
        "Action": ["network-firewall:AssociateFirewallPolicy", "network-firewall:ListFirewallPolicies"],
        "Resource": policy_arn,
    }
    doc = json.dumps({"Version": "2012-10-17", "Statement": [statement]})
    nfw.put_resource_policy(ResourceArn=policy_arn, Policy=doc)

    fetched = nfw.describe_resource_policy(ResourceArn=policy_arn)
    fetched_doc = json.loads(fetched["Policy"])
    fetched_statement = fetched_doc["Statement"][0]
    assert fetched_statement["Action"] == statement["Action"], (
        f"expected Action {statement['Action']!r} to round-trip, got {fetched_statement.get('Action')!r}"
    )
    assert fetched_statement["Resource"] == policy_arn, (
        f"expected Resource {policy_arn!r} to round-trip, got {fetched_statement.get('Resource')!r}"
    )

    # DeleteResourcePolicy right after a put can be refused while the policy's RAM-managed
    # permission is still being created; retry that refusal within a bounded window.
    delete_deadline = time.monotonic() + 120
    while True:
        try:
            nfw.delete_resource_policy(ResourceArn=policy_arn)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidResourcePolicyException" or time.monotonic() > delete_deadline:
                raise
            time.sleep(5)
    code, message = _error(lambda: nfw.describe_resource_policy(ResourceArn=policy_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code}"
    expected_message = "No object with the provided name or resource identifier was found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    redelete_code, redelete_message = _error(lambda: nfw.delete_resource_policy(ResourceArn=policy_arn))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a delete of the already-deleted resource policy to fail with "
        f"ResourceNotFoundException, got {redelete_code}"
    )
    expected_redelete = "No object with the provided name or resource identifier was found"
    assert redelete_message == expected_redelete, (
        f"expected message {expected_redelete!r}, got {redelete_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
