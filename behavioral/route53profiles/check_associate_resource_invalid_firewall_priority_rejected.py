"""associate-resource-invalid-firewall-priority-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-resource-invalid-firewall-priority-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53profiles"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateResourceToProfile rejects a DNS Firewall priority outside the allowed 100-9900 range."""
    r53p = ctx.client("route53profiles")

    profile_id = _create_profile(ctx)
    rule_group_arn = _create_firewall_rule_group(ctx)

    error = _client_error(
        lambda: r53p.associate_resource_to_profile(
            ProfileId=profile_id,
            ResourceArn=rule_group_arn,
            Name=ctx.unique_name("sim2real-behav-resassoc-"),
            ResourceProperties=json.dumps({"priority": 1}),
        )
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error['Code']!r}"
    expected_message = (
        '[RSLVR-02017] The priority value you provided is reserved. Provide a number between "100" and "9900".'
    )
    assert error["Message"] == expected_message, f"expected {expected_message!r}, got {error['Message']!r}"

    # the invalid association must not have been created
    listing = r53p.list_profile_resource_associations(ProfileId=profile_id)["ProfileResourceAssociations"]
    assert not any(a["ResourceArn"] == rule_group_arn for a in listing)

    # positive control: an in-range priority for the same rule group succeeds
    good = r53p.associate_resource_to_profile(
        ProfileId=profile_id,
        ResourceArn=rule_group_arn,
        Name=ctx.unique_name("sim2real-behav-resassoc-"),
        ResourceProperties=json.dumps({"priority": 150}),
    )["ProfileResourceAssociation"]
    good_id = good["Id"]
    ctx.on_cleanup(lambda: _disassociate_resource_blocking(r53p, profile_id, rule_group_arn, good_id))
    assert good["ResourceArn"] == rule_group_arn

    # terminal read: an independent operation confirms the accepted association actually landed
    fetched = r53p.get_profile_resource_association(ProfileResourceAssociationId=good_id)[
        "ProfileResourceAssociation"
    ]
    assert fetched["ResourceArn"] == rule_group_arn, f"expected {rule_group_arn!r}, got {fetched['ResourceArn']!r}"
    assert json.loads(fetched["ResourceProperties"])["priority"] == 150


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_profile(ctx) -> str:
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    deadline = time.monotonic() + min(200, ctx.time_left() or 200)
    while True:
        try:
            profile_id = r53p.create_profile(
                Name=name,
                ClientToken=ctx.unique_name("sim2real-behav-token-"),
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )["Profile"]["Id"]
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "LimitExceededException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_profile_blocking(r53p, profile_id))
    return profile_id


def _delete_profile_blocking(r53p, profile_id: str) -> None:
    try:
        r53p.delete_profile(ProfileId=profile_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            r53p.get_profile(ProfileId=profile_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)


def _disassociate_resource_blocking(r53p, profile_id: str, resource_arn: str, assoc_id: str) -> None:
    """Teardown: the disassociation is asynchronous, and DeleteFirewallRuleGroup refuses a rule
    group that is still associated, so wait for the association to disappear."""
    try:
        r53p.disassociate_resource_from_profile(ProfileId=profile_id, ResourceArn=resource_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            r53p.get_profile_resource_association(ProfileResourceAssociationId=assoc_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)


def _create_firewall_rule_group(ctx) -> str:
    resolver = ctx.client("route53resolver")
    name = ctx.unique_name("sim2real-behav-frg-")
    rule_group = resolver.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-crid-"),
        Name=name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["FirewallRuleGroup"]
    rule_group_id = rule_group["Id"]
    ctx.on_cleanup(lambda: resolver.delete_firewall_rule_group(FirewallRuleGroupId=rule_group_id))
    return rule_group["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
