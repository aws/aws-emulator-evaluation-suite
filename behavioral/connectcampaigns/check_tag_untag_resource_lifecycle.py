"""tag-untag-resource-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-untag-resource-lifecycle"
GROUP = "tagging"
SERVICES = ["connectcampaigns"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource; UntagResource removes them."""
    fixture = _provision_campaign_fixture(ctx)
    campaign = _create_campaign(ctx, fixture)
    campaigns = ctx.client("connectcampaigns")

    campaigns.tag_resource(arn=campaign["arn"], tags={"env": "sim2real", "owner": "behavioral"})
    tags_after_tag = campaigns.list_tags_for_resource(arn=campaign["arn"])["tags"]
    assert tags_after_tag.get("env") == "sim2real", f"expected env=sim2real, got {tags_after_tag!r}"
    assert tags_after_tag.get("owner") == "behavioral", (
        f"expected owner=behavioral, got {tags_after_tag!r}"
    )

    campaigns.untag_resource(arn=campaign["arn"], tagKeys=["owner"])
    tags_after_untag = campaigns.list_tags_for_resource(arn=campaign["arn"])["tags"]
    assert "owner" not in tags_after_untag, "untagged key must be absent"
    assert tags_after_untag.get("env") == "sim2real", "remaining tag must be untouched"


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last!r}")


def _provision_campaign_fixture(ctx):
    connect = ctx.client("connect")
    campaigns = ctx.client("connectcampaigns")
    created_instance = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-cc-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real": CHECK},
    )
    instance_id = created_instance["Id"]
    instance_arn = created_instance["Arn"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))

    _poll_until(
        lambda: connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=300.0,
        interval_s=5.0,
    )

    flows = connect.list_contact_flows(
        InstanceId=instance_id, ContactFlowTypes=["CONTACT_FLOW"], MaxResults=25
    )["ContactFlowSummaryList"]
    if not flows:
        raise AssertionError("newly created Connect instance has no default contact flows")
    contact_flow_id = flows[0]["Id"]

    source_phone_number = _claim_source_phone_number(ctx, connect, instance_arn)

    campaigns.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )

    def _cleanup_onboarding():
        _delete_instance_config(campaigns, instance_id, time.monotonic() + _CONFIG_DELETE_S)
        try:
            campaigns.delete_instance_onboarding_job(connectInstanceId=instance_id)
        except (
            campaigns.exceptions.ResourceNotFoundException,
            campaigns.exceptions.InvalidStateException,
        ):
            pass  # only a FAILED job is deletable; a succeeded one goes with its config

    ctx.on_cleanup(_cleanup_onboarding)

    status = _poll_until(
        lambda: campaigns.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ],
        lambda s: s["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    if status["status"] != "SUCCEEDED":
        raise AssertionError(f"instance onboarding job failed: {status}")

    return {
        "connect_instance_id": instance_id,
        "contact_flow_id": contact_flow_id,
        "source_phone_number": source_phone_number,
    }


def _claim_source_phone_number(ctx, connect, instance_arn):
    available = connect.search_available_phone_numbers(
        TargetArn=instance_arn, PhoneNumberCountryCode="US", PhoneNumberType="DID", MaxResults=10
    )["AvailableNumbersList"]
    if not available:
        raise AssertionError("no available DID phone numbers to claim for outbound dialing")
    for candidate in available:
        try:
            claimed = connect.claim_phone_number(
                TargetArn=instance_arn,
                PhoneNumber=candidate["PhoneNumber"],
                Tags={"sim2real": CHECK},
            )
        except connect.exceptions.InvalidParameterException:
            continue
        phone_number_id = claimed["PhoneNumberId"]
        ctx.on_cleanup(lambda: connect.release_phone_number(PhoneNumberId=phone_number_id))
        return candidate["PhoneNumber"]
    raise AssertionError(f"could not claim any of {len(available)} advertised-available DID numbers")


def _create_campaign(ctx, fixture, *, dialer_config=None, name=None):
    campaigns = ctx.client("connectcampaigns")
    resp = campaigns.create_campaign(
        name=name or ctx.unique_name("sim2real-campaign-"),
        connectInstanceId=fixture["connect_instance_id"],
        dialerConfig=dialer_config or {"agentlessDialerConfig": {"dialingCapacity": 1.0}},
        outboundCallConfig={
            "connectContactFlowId": fixture["contact_flow_id"],
            "connectSourcePhoneNumber": fixture["source_phone_number"],
        },
        tags={"sim2real": CHECK},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: campaigns.delete_campaign(id=campaign_id))
    return {"id": campaign_id, "arn": resp["arn"]}


# ===== campaigns teardown =====
# Registered right after the instance exists, so (LIFO) it runs after every campaign cleanup.
# Order: stop/delete leftover campaigns -> delete_connect_instance_config -> delete_instance.
# A campaigns instance config that outlives its instance keeps the instance ARN in an
# account-wide EventBridge rule pattern; past that pattern's 2048-char limit EVERY onboarding in
# the account fails with EVENT_BRIDGE_MANAGED_RULE_LIMIT_EXCEEDED. Config deletion refuses while a
# campaign is active, and both deletes are asynchronous (a pending instance deletion still counts
# against the account's Connect instance quota), so each step is waited out.
_TEARDOWN_TIMEOUT_S = 600
_CONFIG_DELETE_S = 60


def _offboard_and_delete_instance(ctx, instance_id):
    connect = ctx.client("connect")
    campaigns = ctx.client("connectcampaigns")
    deadline = time.monotonic() + _TEARDOWN_TIMEOUT_S
    try:
        leftovers = campaigns.list_campaigns(
            filters={"instanceIdFilter": {"value": instance_id, "operator": "Eq"}}
        )["campaignSummaryList"]
        for summary in leftovers:
            try:
                if campaigns.get_campaign_state(id=summary["id"])["state"] in ("Running", "Paused"):
                    campaigns.stop_campaign(id=summary["id"])
                    while time.monotonic() < deadline and campaigns.get_campaign_state(
                        id=summary["id"]
                    )["state"] in ("Running", "Paused"):
                        time.sleep(2)
                campaigns.delete_campaign(id=summary["id"])
            except campaigns.exceptions.ResourceNotFoundException:
                pass
        _delete_instance_config(campaigns, instance_id, deadline)
    finally:
        try:
            connect.delete_instance(InstanceId=instance_id)
        except connect.exceptions.ResourceNotFoundException:
            pass
        while True:
            try:
                connect.describe_instance(InstanceId=instance_id)
            except connect.exceptions.ResourceNotFoundException:
                break
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"Connect instance {instance_id} still exists {_TEARDOWN_TIMEOUT_S}s after DeleteInstance"
                )
            time.sleep(2)


def _delete_instance_config(campaigns, instance_id, deadline):
    """Teardown: delete the instance config until it reads not-found; the refusal while a
    campaign on the instance is still being released (InvalidStateException) is retried."""
    while True:
        try:
            campaigns.get_connect_instance_config(connectInstanceId=instance_id)
            campaigns.delete_connect_instance_config(connectInstanceId=instance_id)
        except campaigns.exceptions.ResourceNotFoundException:
            return
        except campaigns.exceptions.InvalidStateException:
            if time.monotonic() >= deadline:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"campaigns config for instance {instance_id} outlived its teardown deadline")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
