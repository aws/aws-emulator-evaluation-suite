"""update-campaign-schedule-persists."""
from __future__ import annotations

import datetime
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-campaign-schedule-persists"
GROUP = "state"
SERVICES = ["connectcampaignsv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCampaignSchedule replaces a campaign's schedule window; DescribeCampaign returns the
    new startTime/endTime exactly, not the original ones."""
    campaigns = ctx.client("connectcampaignsv2")
    instance_id = _provision_onboarded_instance(ctx)
    flow_id = _create_disconnect_contact_flow(ctx, instance_id)
    source_phone_number = _claim_phone_number(ctx, instance_id)
    segment_arn = (
        f"arn:aws:profile:{ctx.region}:123456789012:domains/s2r-domain/segment-definitions/"
        f"{uuid.uuid4()}"
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    original_start = now + datetime.timedelta(minutes=15)
    original_end = now + datetime.timedelta(days=10)
    campaign_id = campaigns.create_campaign(
        name=ctx.unique_name("sim2real-campaign-"),
        connectInstanceId=instance_id,
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
        source={"customerProfilesSegmentArn": segment_arn},
        schedule={"startTime": original_start, "endTime": original_end},
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["id"]
    ctx.on_cleanup(lambda: campaigns.delete_campaign(id=campaign_id))

    new_start = now + datetime.timedelta(minutes=30)
    new_end = now + datetime.timedelta(days=20)
    campaigns.update_campaign_schedule(id=campaign_id, schedule={"startTime": new_start, "endTime": new_end})

    # The service echoes startTime/endTime at millisecond precision, dropping the
    # sub-millisecond remainder of the microsecond value we sent.
    expected_start = _to_millis(new_start)
    expected_end = _to_millis(new_end)

    desc = campaigns.describe_campaign(id=campaign_id)["campaign"]
    assert desc["schedule"]["startTime"] == expected_start, (
        f"expected startTime {expected_start!r}, got {desc['schedule']['startTime']!r}"
    )
    assert desc["schedule"]["endTime"] == expected_end, (
        f"expected endTime {expected_end!r}, got {desc['schedule']['endTime']!r}"
    )
    assert desc["schedule"]["startTime"] != _to_millis(original_start), (
        f"startTime still equals the original schedule's startTime {original_start!r}"
    )


# ===== helpers =====
def _to_millis(value: datetime.datetime) -> datetime.datetime:
    return value.replace(microsecond=(value.microsecond // 1000) * 1000)


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
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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
    )
    return resp["ContactFlowId"]


def _claim_phone_number(ctx, instance_id: str) -> str:
    connect = ctx.client("connect")
    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn, PhoneNumberCountryCode="US", PhoneNumberType="DID", MaxResults=1
    )["AvailableNumbersList"]
    if not numbers:
        raise AssertionError("no available phone numbers to claim for the test Connect instance")
    phone_number = numbers[0]["PhoneNumber"]
    claim_id = connect.claim_phone_number(
        TargetArn=instance_arn,
        PhoneNumber=phone_number,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["PhoneNumberId"]
    ctx.on_cleanup(lambda: connect.release_phone_number(PhoneNumberId=claim_id))
    return phone_number


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
