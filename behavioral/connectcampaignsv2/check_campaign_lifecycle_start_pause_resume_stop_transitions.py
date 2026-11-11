"""campaign-lifecycle-start-pause-resume-stop-transitions."""
from __future__ import annotations

import datetime
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "campaign-lifecycle-start-pause-resume-stop-transitions"
GROUP = "state-machine"
SERVICES = ["connectcampaignsv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A telephony campaign goes Initialized, Running, Paused, Running, Stopped: PutOutboundRequestBatch gets
    one result per token while Running and ConflictException naming PAUSED while Paused, and StartCampaign
    on the Stopped campaign fails with ConflictException naming STOPPED."""
    campaigns = ctx.client("connectcampaignsv2")
    instance_id = _provision_onboarded_instance(ctx)
    flow_id = _create_disconnect_contact_flow(ctx, instance_id)
    claimed_numbers = _claim_phone_numbers(ctx, instance_id, count=2)
    source_phone_number, destination_phone_number = claimed_numbers

    campaign_id = campaigns.create_campaign(
        name=ctx.unique_name("s2r-campaign-"),
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
    )["id"]
    ctx.on_cleanup(lambda: _stop_and_delete_campaign(ctx, campaign_id))

    state = campaigns.get_campaign_state(id=campaign_id)["state"]
    assert state == "Initialized", f"expected freshly created campaign to be Initialized, got {state}"

    campaigns.start_campaign(id=campaign_id)
    _wait_for_campaign_state(ctx, campaign_id, "Running")

    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    _assert_batch_answered(campaigns, campaign_id, destination_phone_number, expiration, "while Running")

    campaigns.pause_campaign(id=campaign_id)
    _wait_for_campaign_state(ctx, campaign_id, "Paused")

    error = _error(
        lambda: campaigns.put_outbound_request_batch(
            id=campaign_id,
            outboundRequests=[
                {
                    "clientToken": str(uuid.uuid4()),
                    "expirationTime": expiration,
                    "channelSubtypeParameters": {
                        "telephony": {
                            "destinationPhoneNumber": destination_phone_number,
                            "attributes": {},
                        }
                    },
                }
            ],
        )
    )
    assert error["Code"] == "ConflictException", f"expected ConflictException, got {error}"
    expected_paused = f"Campaign: {campaign_id} is in invalid state: PAUSED"
    assert error["Message"] == expected_paused, f"expected {expected_paused!r}, got {error['Message']!r}"

    # effect absent: the rejected dial request did not advance the campaign out of Paused
    paused_state = campaigns.get_campaign_state(id=campaign_id)["state"]
    assert paused_state == "Paused", f"expected campaign to remain Paused, got {paused_state}"

    campaigns.resume_campaign(id=campaign_id)
    _wait_for_campaign_state(ctx, campaign_id, "Running")

    # restore: the identical call that was refused while Paused is taken again while Running
    _assert_batch_answered(campaigns, campaign_id, destination_phone_number, expiration, "after Resume")

    campaigns.stop_campaign(id=campaign_id)
    _wait_for_campaign_state(ctx, campaign_id, "Stopped")

    start_error = _error(lambda: campaigns.start_campaign(id=campaign_id))
    assert start_error["Code"] == "ConflictException", f"expected ConflictException, got {start_error}"
    expected_stopped = f"Campaign: {campaign_id} is in invalid state: STOPPED"
    assert start_error["Message"] == expected_stopped, (
        f"expected {expected_stopped!r}, got {start_error['Message']!r}"
    )
    final_state = campaigns.get_campaign_state(id=campaign_id)["state"]
    assert final_state == "Stopped", f"expected campaign to remain Stopped, got {final_state}"


def _error(fn) -> dict:
    """Call fn(); return its error ({"Code", "Message"}). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _assert_batch_answered(campaigns, campaign_id: str, destination: str, expiration, when: str) -> None:
    token = str(uuid.uuid4())
    resp = campaigns.put_outbound_request_batch(
        id=campaign_id,
        outboundRequests=[
            {
                "clientToken": token,
                "expirationTime": expiration,
                "channelSubtypeParameters": {"telephony": {"destinationPhoneNumber": destination, "attributes": {}}},
            }
        ],
    )
    answered = [r["clientToken"] for r in resp.get("successfulRequests", []) + resp.get("failedRequests", [])]
    assert answered == [token], f"expected exactly one per-request result for {token} {when}, got {resp}"


def _stop_and_delete_campaign(ctx, campaign_id: str) -> None:
    # DeleteCampaign refuses a Running or Paused campaign, so stop it first.
    campaigns = ctx.client("connectcampaignsv2")
    if campaigns.get_campaign_state(id=campaign_id)["state"] in ("Running", "Paused"):
        campaigns.stop_campaign(id=campaign_id)
        _wait_for_campaign_state(ctx, campaign_id, "Stopped")
    campaigns.delete_campaign(id=campaign_id)


def _create_connect_instance(ctx) -> str:
    connect = ctx.client("connect")
    alias = ctx.unique_name("s2rcc").replace("_", "-")[:60]
    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
    )["Id"]
    ctx.on_cleanup(lambda: connect.delete_instance(InstanceId=instance_id))
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
        raise AssertionError(f"instance onboarding did not succeed (status={status})")
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
        Name=ctx.unique_name("s2r-flow-"),
        Type="CONTACT_FLOW",
        Content=flow_content,
    )
    return resp["ContactFlowId"]


def _claim_phone_numbers(ctx, instance_id: str, count: int) -> list[str]:
    """Search-then-claim right before each claim, one at a time: a number returned by
    SearchAvailablePhoneNumbers can be claimed by someone else before we get to it, so a batch
    fetched upfront goes stale by the second claim."""
    connect = ctx.client("connect")
    target_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]

    claimed: list[str] = []
    for _ in range(count):
        numbers = connect.search_available_phone_numbers(
            TargetArn=target_arn, PhoneNumberCountryCode="US", PhoneNumberType="DID", MaxResults=10
        )["AvailableNumbersList"]
        phone_number = None
        claim_id = None
        for entry in numbers:
            candidate = entry["PhoneNumber"]
            if candidate in claimed:
                continue
            try:
                claim_id = connect.claim_phone_number(TargetArn=target_arn, PhoneNumber=candidate)[
                    "PhoneNumberId"
                ]
                phone_number = candidate
                break
            except ClientError as err:
                if err.response["Error"]["Code"] != "InvalidParameterException":
                    raise
        if phone_number is None:
            raise AssertionError(f"could not claim an available phone number (tried {len(numbers)} candidates)")
        ctx.on_cleanup(lambda claim_id=claim_id: connect.release_phone_number(PhoneNumberId=claim_id))

        deadline = time.monotonic() + 120
        status = "IN_PROGRESS"
        while time.monotonic() < deadline:
            status = connect.describe_phone_number(PhoneNumberId=claim_id)["ClaimedPhoneNumberSummary"][
                "PhoneNumberStatus"
            ]["Status"]
            if status == "CLAIMED":
                break
            if status == "FAILED":
                raise AssertionError(f"claiming phone number {phone_number} failed")
            time.sleep(3)
        else:
            raise AssertionError(f"phone number {phone_number} never reached CLAIMED (last status={status})")
        claimed.append(phone_number)
    return claimed


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
