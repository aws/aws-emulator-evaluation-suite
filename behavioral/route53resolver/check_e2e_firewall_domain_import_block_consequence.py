"""e2e-firewall-domain-import-block-consequence."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-firewall-domain-import-block-consequence"
GROUP = "e2e"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Domains imported from S3 land in a domain list wired to a BLOCK rule on a VPC.

    The import lists the domain, the single rule is BLOCK on that list, and the association is
    COMPLETE by id and by VPC. No DNS query is sent, so blocking itself is not observed.
    """
    domain = "sim2real-imported-block.test"
    bucket, key = _upload_domain_file(ctx, [domain])

    r53r = ctx.client("route53resolver")
    domain_list_id = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-fdl-req-"),
        Name=ctx.unique_name("sim2real-fdl-")[:64],
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(
        lambda: r53r.delete_firewall_domain_list(FirewallDomainListId=domain_list_id)
    )

    import_resp = r53r.import_firewall_domains(
        FirewallDomainListId=domain_list_id,
        Operation="REPLACE",
        DomainFileUrl=f"s3://{bucket}/{key}",
    )
    assert import_resp["Id"] == domain_list_id, (
        f"expected import response Id {domain_list_id!r}, got {import_resp['Id']!r}"
    )

    status = _poll_until(
        lambda: r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id)[
            "FirewallDomainList"
        ]["Status"],
        lambda s: s in ("COMPLETE", "COMPLETE_IMPORT_FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert status == "COMPLETE", f"import reached {status}, not COMPLETE"

    imported = r53r.list_firewall_domains(FirewallDomainListId=domain_list_id)["Domains"]
    assert any(d.lower().rstrip(".") == domain.lower().rstrip(".") for d in imported), imported

    rule_group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-frg-req-"),
        Name=ctx.unique_name("sim2real-frg-")[:64],
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(
        lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=rule_group_id)
    )

    r53r.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-fr-req-"),
        FirewallRuleGroupId=rule_group_id,
        FirewallDomainListId=domain_list_id,
        Priority=100,
        Action="BLOCK",
        BlockResponse="NODATA",
        Name=ctx.unique_name("sim2real-fr-")[:64],
    )
    ctx.on_cleanup(
        lambda: r53r.delete_firewall_rule(
            FirewallRuleGroupId=rule_group_id, FirewallDomainListId=domain_list_id
        )
    )

    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name("sim2real-fw-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.83.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    assoc_id = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-fassoc-req-"),
        FirewallRuleGroupId=rule_group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=ctx.unique_name("sim2real-fassoc-")[:64],
    )["FirewallRuleGroupAssociation"]["Id"]
    ctx.on_cleanup(
        lambda: r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    )

    assoc_status = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id
        )["FirewallRuleGroupAssociation"]["Status"],
        lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=60,
        interval_s=3,
    )
    assert assoc_status == "COMPLETE", f"expected association status COMPLETE, got {assoc_status!r}"

    rules = r53r.list_firewall_rules(FirewallRuleGroupId=rule_group_id)["FirewallRules"]
    assert len(rules) == 1, f"expected exactly 1 firewall rule, got {len(rules)}: {rules}"
    assert rules[0]["FirewallDomainListId"] == domain_list_id, (
        f"expected rule to reference domain list {domain_list_id!r}, "
        f"got {rules[0]['FirewallDomainListId']!r}"
    )
    assert rules[0]["Action"] == "BLOCK", f"expected rule Action BLOCK, got {rules[0]['Action']!r}"

    # Read from the VPC side, through a different operation than the polled by-id read.
    vpc_associations = r53r.list_firewall_rule_group_associations(VpcId=vpc_id)[
        "FirewallRuleGroupAssociations"
    ]
    assert any(
        a["Id"] == assoc_id and a["Status"] == "COMPLETE" for a in vpc_associations
    ), f"expected association {assoc_id!r} COMPLETE in VPC {vpc_id!r}, got {vpc_associations}"

    enforced_domains = r53r.list_firewall_domains(FirewallDomainListId=domain_list_id)[
        "Domains"
    ]
    assert any(
        d.lower().rstrip(".") == domain.lower().rstrip(".") for d in enforced_domains
    ), enforced_domains


def _upload_domain_file(ctx, domains: list[str]) -> tuple[str, str]:
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-r53r-domains-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # us-east-1 rejects an explicit LocationConstraint on create_bucket.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "domains.txt"
    body = "\n".join(domains) + "\n"
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRoute53ResolverRead",
                "Effect": "Allow",
                "Principal": {"Service": "route53resolver.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/{key}",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket, key


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
