"""update-campaign-communication-limits-override-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-campaign-communication-limits-override-round-trip"
GROUP = "state"
SERVICES = ["connectcampaignsv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCampaignCommunicationLimits sets a per-campaign override that DescribeCampaign
    reflects exactly, and DeleteCampaignCommunicationLimits(config="ALL_CHANNEL_SUBTYPES")
    removes the override so the campaign falls back to having none set."""
    campaigns = ctx.client("connectcampaignsv2")
    instance_id = _provision_onboarded_instance(ctx)
    flow_id = _create_disconnect_contact_flow(ctx, instance_id)
    source_phone_number = _claim_phone_number(ctx, instance_id)
    domain_name = _create_customer_profiles_domain(ctx)
    segment_arn = _create_segment_definition(ctx, domain_name)
    campaign_id = campaigns.create_campaign(
        name=ctx.unique_name("sim2real-campaign-"),
        connectInstanceId=instance_id,
        source={"customerProfilesSegmentArn": segment_arn},
        channelSubtypeConfig={
            "telephony": {
                "capacity": 1.0,
                "outboundMode": {"agentless": {}},
                "defaultOutboundConfig": {
                    "connectContactFlowId": flow_id,
                    "connectSourcePhoneNumber": source_phone_number,
                },
            }
        },
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: campaigns.delete_campaign(id=campaign_id))
    _wait_for_campaign_state(ctx, campaign_id, "Initialized")

    desc_before = campaigns.describe_campaign(id=campaign_id)["campaign"]
    assert desc_before.get("communicationLimitsOverride") in (None, {}), (
        f"expected no communicationLimitsOverride on a freshly created campaign, "
        f"got {desc_before.get('communicationLimitsOverride')}"
    )

    override = {
        "allChannelSubtypes": {
            "communicationLimitsList": [
                {"maxCountPerRecipient": 3, "frequency": 7, "unit": "DAY"}
            ]
        },
        "instanceLimitsHandling": "OPT_IN",
    }
    campaigns.update_campaign_communication_limits(
        id=campaign_id, communicationLimitsOverride=override
    )
    desc = campaigns.describe_campaign(id=campaign_id)["campaign"]
    assert desc["communicationLimitsOverride"] == override, (
        f"expected communicationLimitsOverride to echo {override} exactly, "
        f"got {desc.get('communicationLimitsOverride')}"
    )

    campaigns.delete_campaign_communication_limits(id=campaign_id, config="ALL_CHANNEL_SUBTYPES")
    desc_after = campaigns.describe_campaign(id=campaign_id)["campaign"]
    # DeleteCampaignCommunicationLimits(ALL_CHANNEL_SUBTYPES) clears only the per-channel
    # limits list; instanceLimitsHandling is a separate opt-in/out flag that this config
    # value does not touch, so it survives the delete unchanged.
    assert desc_after.get("communicationLimitsOverride") == {
        "instanceLimitsHandling": override["instanceLimitsHandling"]
    }, (
        f"expected only allChannelSubtypes cleared by "
        f"DeleteCampaignCommunicationLimits(ALL_CHANNEL_SUBTYPES), leaving "
        f"instanceLimitsHandling={override['instanceLimitsHandling']!r} in place, "
        f"got {desc_after.get('communicationLimitsOverride')}"
    )


# ===== helpers =====
def _error_code(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return None


def _create_connect_instance(ctx) -> str:
    connect = ctx.client("connect")
    alias = ctx.unique_name("sim2realcc").replace("_", "-")[:60]
    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real": CHECK},
    )["Id"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))
    deadline = time.monotonic() + 180
    status = "CREATION_IN_PROGRESS"
    while time.monotonic() < deadline:
        status = connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"]
        if status == "ACTIVE":
            return instance_id
        if status == "CREATION_FAILED":
            raise AssertionError("connect instance creation failed")
        time.sleep(3)
    raise AssertionError(f"connect instance never became ACTIVE (last status={status})")


def _create_disconnect_contact_flow(ctx, instance_id: str) -> str:
    connect = ctx.client("connect")
    flow_content = json.dumps(
        {
            "Version": "2019-10-30",
            "StartAction": "12345678-1234-1234-1234-123456789012",
            "Actions": [
                {
                    "Identifier": "12345678-1234-1234-1234-123456789012",
                    "Type": "DisconnectParticipant",
                    "Transitions": {},
                    "Parameters": {},
                }
            ],
        }
    )
    resp = connect.create_contact_flow(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2real-flow-"),
        Type="CONTACT_FLOW",
        Content=flow_content,
        Tags={"sim2real": CHECK},
    )
    return resp["ContactFlowId"]


def _claim_phone_number(ctx, instance_id: str) -> str:
    connect = ctx.client("connect")
    target_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=target_arn,
        PhoneNumberCountryCode="US",
        PhoneNumberType="DID",
        MaxResults=1,
    )["AvailableNumbersList"]
    if not numbers:
        raise AssertionError("no available phone numbers to claim for the test Connect instance")
    phone_number = numbers[0]["PhoneNumber"]
    claim_id = connect.claim_phone_number(
        TargetArn=target_arn, PhoneNumber=phone_number, Tags={"sim2real": CHECK}
    )["PhoneNumberId"]
    ctx.on_cleanup(lambda: connect.release_phone_number(PhoneNumberId=claim_id))
    return phone_number


def _create_customer_profiles_domain(ctx) -> str:
    profiles = ctx.client("customer-profiles")
    domain_name = ctx.unique_name("sim2realcccp").replace("-", "")[:64]
    profiles.create_domain(DomainName=domain_name, DefaultExpirationDays=30)
    ctx.on_cleanup(lambda: profiles.delete_domain(DomainName=domain_name))
    return domain_name


def _create_segment_definition(ctx, domain_name: str) -> str:
    profiles = ctx.client("customer-profiles")
    segment_name = ctx.unique_name("sim2realcccpseg").replace("-", "")[:64]
    resp = profiles.create_segment_definition(
        DomainName=domain_name,
        SegmentDefinitionName=segment_name,
        DisplayName=segment_name,
        SegmentGroups={
            "Groups": [
                {
                    "Dimensions": [
                        {
                            "ProfileAttributes": {
                                "FirstName": {
                                    "DimensionType": "INCLUSIVE",
                                    "Values": ["s2r-placeholder"],
                                }
                            }
                        }
                    ],
                    "SourceType": "ALL",
                    "Type": "ALL",
                }
            ],
            "Include": "ALL",
        },
    )
    ctx.on_cleanup(
        lambda: profiles.delete_segment_definition(
            DomainName=domain_name, SegmentDefinitionName=segment_name
        )
    )
    return resp["SegmentDefinitionArn"]


def _wait_for_campaign_state(ctx, campaign_id: str, target: str, timeout_s: float = 90.0) -> None:
    campaigns = ctx.client("connectcampaignsv2")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = campaigns.get_campaign_state(id=campaign_id)["state"]
        if state == target:
            return
        time.sleep(3)
    raise AssertionError(f"campaign {campaign_id} never reached {target} (last state={state})")


def _provision_onboarded_instance(ctx) -> str:
    campaigns = ctx.client("connectcampaignsv2")
    instance_id = _create_connect_instance(ctx)
    campaigns.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )
    deadline = time.monotonic() + 120
    status = "IN_PROGRESS"
    while time.monotonic() < deadline:
        status = campaigns.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ]["status"]
        if status != "IN_PROGRESS":
            break
        time.sleep(3)
    if status != "SUCCEEDED":
        failure_code = _onboarding_failure_code(campaigns, instance_id)
        raise AssertionError(f"instance onboarding did not succeed (status={status}, failureCode={failure_code})")
    return instance_id


# ===== campaigns teardown =====
# Registered right after the instance exists, so (LIFO) it runs after every campaign cleanup.
# Order: stop/delete leftover campaigns -> delete_connect_instance_config -> delete_instance.
# A campaigns instance config that outlives its instance keeps the instance ARN in an
# account-wide EventBridge rule pattern; past that pattern's 2048-char limit EVERY onboarding in
# the account fails with EVENT_BRIDGE_MANAGED_RULE_LIMIT_EXCEEDED. Config deletion refuses while a
# campaign is active, and both deletes are asynchronous (a pending instance deletion still counts
# against the account's Connect instance quota), so each step is waited out.
_TEARDOWN_TIMEOUT_S = 600


def _offboard_and_delete_instance(ctx, instance_id):
    connect = ctx.client("connect")
    campaigns = ctx.client("connectcampaignsv2")
    deadline = time.monotonic() + _TEARDOWN_TIMEOUT_S

    def _delete_instance():
        try:
            connect.delete_instance(InstanceId=instance_id)
        except connect.exceptions.ResourceNotFoundException:
            return
        while time.monotonic() < deadline:
            try:
                connect.describe_instance(InstanceId=instance_id)
            except connect.exceptions.ResourceNotFoundException:
                return
            time.sleep(2)
        raise AssertionError(f"connect instance {instance_id} still present after {_TEARDOWN_TIMEOUT_S}s")

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
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        _delete_instance_config(campaigns, instance_id, deadline)
    finally:
        # A return here would discard an error raised by the offboarding above, so it lives in a
        # nested function.
        _delete_instance()


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


def _onboarding_failure_code(campaigns, instance_id):
    # The job status carries the cause (e.g. EVENT_BRIDGE_MANAGED_RULE_LIMIT_EXCEEDED); a failure
    # message without it sends the reader hunting.
    try:
        return campaigns.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ].get("failureCode")
    except Exception as e:
        return f"<unreadable: {type(e).__name__}>"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
