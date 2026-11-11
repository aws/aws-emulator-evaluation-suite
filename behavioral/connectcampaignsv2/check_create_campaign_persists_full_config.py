"""create-campaign-persists-full-config."""
from __future__ import annotations

import datetime
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-campaign-persists-full-config"
GROUP = "state"
SERVICES = ["connectcampaignsv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCampaign persists channelSubtypeConfig, source, schedule, entryLimitsConfig and tags
    exactly as submitted -- DescribeCampaign returns the same values back, not just an id/name
    placeholder."""
    campaigns = ctx.client("connectcampaignsv2")
    instance_id = _provision_onboarded_instance(ctx)
    flow_id = _create_disconnect_contact_flow(ctx, instance_id)
    source_phone_number = _claim_phone_number(ctx, instance_id)
    segment_arn = (
        f"arn:aws:profile:{ctx.region}:111122223333:domains/s2r-domain/segment-definitions/"
        f"{uuid.uuid4()}"
    )

    # CreateCampaign truncates Schedule timestamps to millisecond precision on real AWS, so a
    # microsecond-precision Python datetime never round-trips exactly -- truncate what we submit
    # to the same resolution the service stores, rather than asserting a value it cannot return.
    now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)
    start_time = now.replace(microsecond=(now.microsecond // 1000) * 1000)
    end_time = start_time + datetime.timedelta(days=30)
    name = ctx.unique_name("sim2real-campaign-")
    channel_config = {
        "telephony": {
            "capacity": 1.0,
            "outboundMode": {"agentless": {}},
            "defaultOutboundConfig": {
                "connectContactFlowId": flow_id,
                "connectSourcePhoneNumber": source_phone_number,
                "answerMachineDetectionConfig": {
                    "enableAnswerMachineDetection": True,
                    "awaitAnswerMachinePrompt": True,
                },
            },
        }
    }

    resp = campaigns.create_campaign(
        name=name,
        connectInstanceId=instance_id,
        channelSubtypeConfig=channel_config,
        source={"customerProfilesSegmentArn": segment_arn},
        schedule={"startTime": start_time, "endTime": end_time},
        entryLimitsConfig={"maxEntryCount": 7, "minEntryInterval": "PT2H"},
        tags={"owner": "sim2real", "purpose": "behavioral-check"},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: campaigns.delete_campaign(id=campaign_id))

    # CreateCampaign's own response never echoes `tags` back on real AWS, though the model
    # declares the response member -- the independent DescribeCampaign read below is the
    # only place tags persistence is verified.
    desc = campaigns.describe_campaign(id=campaign_id)["campaign"]
    assert desc["name"] == name, f"expected name {name!r}, got {desc.get('name')!r}"
    assert desc["connectInstanceId"] == instance_id, (
        f"expected connectInstanceId {instance_id!r}, got {desc.get('connectInstanceId')!r}"
    )
    assert desc["channelSubtypeConfig"] == channel_config, (
        f"channelSubtypeConfig mismatch: {desc.get('channelSubtypeConfig')!r}"
    )
    assert desc["source"] == {
        "customerProfilesSegmentArn": segment_arn
    }, f"source mismatch: {desc.get('source')!r}"
    assert desc["entryLimitsConfig"] == {
        "maxEntryCount": 7,
        "minEntryInterval": "PT2H",
    }, f"entryLimitsConfig mismatch: {desc.get('entryLimitsConfig')!r}"
    assert desc["schedule"]["startTime"] == start_time, (
        f"expected schedule.startTime {start_time!r}, got {desc['schedule'].get('startTime')!r}"
    )
    assert desc["schedule"]["endTime"] == end_time, (
        f"expected schedule.endTime {end_time!r}, got {desc['schedule'].get('endTime')!r}"
    )
    assert desc["tags"] == {
        "owner": "sim2real",
        "purpose": "behavioral-check",
    }, f"DescribeCampaign tags mismatch: {desc.get('tags')!r}"


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
    )
    return resp["ContactFlowId"]


def _claim_phone_number(ctx, instance_id: str) -> str:
    # A number returned by SearchAvailablePhoneNumbers can be claimed by someone else before
    # ClaimPhoneNumber, so try several candidates rather than treating one loss as fatal.
    connect = ctx.client("connect")
    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn,
        PhoneNumberCountryCode="US",
        PhoneNumberType="DID",
        MaxResults=10,
    )["AvailableNumbersList"]
    if not numbers:
        raise AssertionError("no available phone numbers to claim for the test Connect instance")
    last_error = None
    for candidate in numbers:
        phone_number = candidate["PhoneNumber"]
        try:
            claim_id = connect.claim_phone_number(TargetArn=instance_arn, PhoneNumber=phone_number)[
                "PhoneNumberId"
            ]
        except ClientError as err:
            last_error = err
            continue
        ctx.on_cleanup(lambda claim_id=claim_id: connect.release_phone_number(PhoneNumberId=claim_id))
        return phone_number
    raise AssertionError(f"could not claim any of {len(numbers)} candidate numbers: {last_error}")


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
