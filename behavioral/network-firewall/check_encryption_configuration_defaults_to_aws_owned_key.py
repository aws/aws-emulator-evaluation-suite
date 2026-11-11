"""encryption-configuration-defaults-to-aws-owned-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encryption-configuration-defaults-to-aws-owned-key"
GROUP = "resource-config"
SERVICES = ["network-firewall"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A rule group created without an explicit EncryptionConfiguration is encrypted with an
    AWS owned KMS key by default (Type=AWS_OWNED_KMS_KEY), matching AWS's documented default
    for Network Firewall resources."""
    nfw = ctx.client("network-firewall")
    rg_name = ctx.unique_name("sim2real-nfw-rg-")

    created = nfw.create_rule_group(
        RuleGroupName=rg_name, Type="STATEFUL", Capacity=10,
        RuleGroup={"RulesSource": {"StatefulRules": [{
            "Action": "ALERT",
            "Header": {"Protocol": "TCP", "Source": "ANY", "SourcePort": "ANY",
                       "Direction": "ANY", "Destination": "ANY", "DestinationPort": "ANY"},
            "RuleOptions": [{"Keyword": "sid:1"}],
        }]}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    rule_group_arn = created["RuleGroupResponse"]["RuleGroupArn"]
    ctx.on_cleanup(lambda: nfw.delete_rule_group(RuleGroupArn=rule_group_arn))

    enc = created["RuleGroupResponse"]["EncryptionConfiguration"]
    assert enc["Type"] == "AWS_OWNED_KMS_KEY", f"expected AWS_OWNED_KMS_KEY by default, got {enc}"

    desc_enc = nfw.describe_rule_group(RuleGroupArn=rule_group_arn)["RuleGroupResponse"]["EncryptionConfiguration"]
    assert desc_enc["Type"] == "AWS_OWNED_KMS_KEY", f"expected AWS_OWNED_KMS_KEY on independent read, got {desc_enc}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
