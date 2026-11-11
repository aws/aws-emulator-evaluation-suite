"""e2e-firewall-domain-block-full-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-firewall-domain-block-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Domains imported from S3 feed a BLOCK rule whose rule group VPC association reaches COMPLETE.

    Full teardown then confirms the domain list, rule group, and VPC association are all gone.
    """
    s3 = ctx.client("s3")
    ec2 = ctx.client("ec2")
    r53r = ctx.client("route53resolver")

    vpc_id = _create_vpc(ctx, ec2)
    domain_file_url = _upload_domain_file(ctx, s3, ["e2e-lifecycle-blocked.test.", "e2e-lifecycle-blocked-2.test."])

    list_id = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-cfdl-"),
        Name=ctx.unique_name("sim2real-fwdomains-")[:64],
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_domain_list(r53r, list_id))

    import_result = r53r.import_firewall_domains(
        FirewallDomainListId=list_id, Operation="REPLACE", DomainFileUrl=domain_file_url
    )
    assert import_result["Status"] in ("IMPORTING", "COMPLETE")

    imported_list = _poll_until(
        lambda: r53r.get_firewall_domain_list(FirewallDomainListId=list_id)["FirewallDomainList"],
        lambda lst: lst["Status"] in ("COMPLETE", "COMPLETE_IMPORT_FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert imported_list["Status"] == "COMPLETE", f"import failed: {imported_list}"
    assert imported_list["DomainCount"] == 2

    group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crg-"),
        Name=ctx.unique_name("sim2real-fwgroup-")[:64],
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_rule_group(r53r, group_id))

    rule_name = ctx.unique_name("sim2real-rule-")[:64]
    r53r.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-cfr-"),
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=list_id,
        Priority=100,
        Action="BLOCK",
        BlockResponse="NXDOMAIN",
        Name=rule_name,
    )
    ctx.on_cleanup(lambda: _safe_delete_firewall_rule(r53r, group_id, list_id))

    assoc_id = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-afrg-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=ctx.unique_name("sim2real-fwassoc-")[:64],
        MutationProtection="DISABLED",
    )["FirewallRuleGroupAssociation"]["Id"]
    ctx.on_cleanup(lambda: _safe_disassociate_group(r53r, assoc_id))


    active = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ],
        lambda a: a["Status"] in ("COMPLETE", "DELETING"),
        # An association can sit in UPDATING for minutes before it reaches COMPLETE.
        timeout_s=_bound(ctx, 300),
        interval_s=2,
    )
    assert active["Status"] == "COMPLETE"

    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    _poll_until(
        lambda: _association_gone(r53r, assoc_id),
        lambda gone: gone,
        timeout_s=_bound(ctx, 300),
        interval_s=2,
    )

    r53r.delete_firewall_rule(FirewallRuleGroupId=group_id, FirewallDomainListId=list_id)
    _poll_until(
        lambda: _rule_gone(r53r, group_id, rule_name),
        lambda gone: gone,
        timeout_s=30,
        interval_s=2,
    )

    r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
    _poll_until(
        lambda: _rule_group_gone(r53r, group_id),
        lambda gone: gone,
        timeout_s=60,
        interval_s=2,
    )

    r53r.delete_firewall_domain_list(FirewallDomainListId=list_id)
    _poll_until(
        lambda: _domain_list_gone(r53r, list_id),
        lambda gone: gone,
        timeout_s=60,
        interval_s=2,
    )


def _bound(ctx, timeout_s):
    left = ctx.time_left()
    return timeout_s if left is None else min(timeout_s, left)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _create_vpc(ctx, ec2):
    name = ctx.unique_name("sim2real-r53r-vpc-")
    resp = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _upload_domain_file(ctx, s3, domains):
    bucket = ctx.unique_name("sim2real-r53r-fwimport-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    key = "domains.txt"

    def _cleanup_bucket():
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    body = "\n".join(domains) + "\n"
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))
    return f"s3://{bucket}/{key}"


def _rule_gone(r53r, group_id, rule_name):
    rules = r53r.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]
    return not any(r["Name"] == rule_name for r in rules)


def _association_gone(r53r, assoc_id):
    try:
        r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        return False
    except ClientError as e:
        return e.response["Error"]["Code"] == "ResourceNotFoundException"


def _rule_group_gone(r53r, group_id):
    try:
        r53r.get_firewall_rule_group(FirewallRuleGroupId=group_id)
        return False
    except ClientError as e:
        return e.response["Error"]["Code"] == "ResourceNotFoundException"


def _domain_list_gone(r53r, list_id):
    try:
        r53r.get_firewall_domain_list(FirewallDomainListId=list_id)
        return False
    except ClientError as e:
        return e.response["Error"]["Code"] == "ResourceNotFoundException"


def _safe_disassociate_group(r53r, assoc_id, timeout_s=300):
    """Disassociate and wait until the association is gone, so the rule group's delete that runs
    next is not refused as still associated. An association still UPDATING refuses with
    ConflictException, so that is retried too; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _poll_until(lambda: _association_gone(r53r, assoc_id), lambda gone: gone,
                timeout_s=max(2.0, deadline - time.monotonic()), interval_s=2)


def _safe_delete_firewall_rule(r53r, group_id, list_id):
    try:
        r53r.delete_firewall_rule(FirewallRuleGroupId=group_id, FirewallDomainListId=list_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_rule_group(r53r, group_id):
    try:
        r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_domain_list(r53r, list_id):
    try:
        r53r.delete_firewall_domain_list(FirewallDomainListId=list_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
