"""put-outbound-request-batch-on-initialized-campaign-rejected."""
from __future__ import annotations

import datetime
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-outbound-request-batch-on-initialized-campaign-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaignsv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """PutOutboundRequestBatch on an Initialized campaign fails as a whole call with
    ConflictException and leaves it Initialized; once the campaign is Running the identical call
    reaches per-item processing, so the rejection is a state gate, not a blanket denial."""
    campaigns = ctx.client("connectcampaignsv2")
    instance_id = _provision_onboarded_instance(ctx)
    flow_id = _create_disconnect_contact_flow(ctx, instance_id)
    source_phone_number = _claim_phone_number(ctx, instance_id)
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
                    "answerMachineDetectionConfig": {
                        "enableAnswerMachineDetection": False,
                        "awaitAnswerMachinePrompt": False,
                    },
                },
            }
        },
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _stop_and_delete_campaign(ctx, campaign_id))

    state = campaigns.get_campaign_state(id=campaign_id)["state"]
    assert state == "Initialized", f"expected Initialized right after create, got {state!r}"

    def _put_batch(token: str):
        campaigns.put_outbound_request_batch(
            id=campaign_id,
            outboundRequests=[
                {
                    "clientToken": token,
                    "expirationTime": datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(hours=1),
                    "channelSubtypeParameters": {
                        "telephony": {
                            "destinationPhoneNumber": "+15005550006",
                            "attributes": {"firstName": "Jordan"},
                        }
                    },
                }
            ],
        )

    err = _error(lambda: _put_batch(str(uuid.uuid4())))
    assert err["Code"] == "ConflictException", f"expected ConflictException, got {err['Code']}"
    expected_message = f"Campaign: {campaign_id} is in invalid state: INITIALIZED"
    assert err["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {err['Message']!r}"
    )

    state = campaigns.get_campaign_state(id=campaign_id)["state"]
    assert state == "Initialized", (
        f"campaign must remain Initialized after the rejected batch, got {state!r}"
    )

    batch = campaigns.get_campaign_state_batch(campaignIds=[campaign_id])
    successful_ids = [r["campaignId"] for r in batch.get("successfulRequests", [])]
    assert campaign_id in successful_ids, (
        f"expected {campaign_id} in GetCampaignStateBatch successfulRequests, got {batch!r}"
    )

    # positive control: once actually running, the state gate lifts. The
    # ConflictException above is raised before any per-item processing, so a call that reaches
    # per-item processing at all (a 200 with a per-item FailedRequest, which the model's own
    # FailureCode enum -- InvalidInput/RequestThrottled/UnknownError/BufferLimitExceeded -- never
    # spells as a state conflict) proves the whole-call state gate is gone, independent of
    # whatever unrelated telephony/entitlement reason a given item might still fail for.
    campaigns.start_campaign(id=campaign_id)
    _wait_for_state(ctx, campaign_id, "Running")

    accepted_token = str(uuid.uuid4())
    try:
        put_resp = campaigns.put_outbound_request_batch(
            id=campaign_id,
            outboundRequests=[
                {
                    "clientToken": accepted_token,
                    "expirationTime": datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(hours=1),
                    "channelSubtypeParameters": {
                        "telephony": {
                            "destinationPhoneNumber": "+15005550006",
                            "attributes": {"firstName": "Jordan"},
                        }
                    },
                }
            ],
        )
    except ClientError as err:
        raise AssertionError(
            f"expected the state gate lifted once Running (no whole-call rejection), "
            f"got {err.response['Error']!r}"
        ) from err
    returned_tokens = [r["clientToken"] for r in put_resp.get("successfulRequests", [])] + [
        r["clientToken"] for r in put_resp.get("failedRequests", [])
    ]
    assert accepted_token in returned_tokens, (
        f"expected the request to reach per-item processing once Running, got {put_resp!r}"
    )

    state = campaigns.get_campaign_state(id=campaign_id)["state"]
    assert state == "Running", f"expected Running after the accepted batch, got {state!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so a target that
    accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    deadline = time.monotonic() + 600
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


def _release_phone_number(connect, phone_number_id):
    # A claimed number can already be gone by teardown time; only a still-present one is released.
    try:
        connect.release_phone_number(PhoneNumberId=phone_number_id)
    except connect.exceptions.ResourceNotFoundException:
        pass


def _claim_phone_number(ctx, instance_id: str) -> str:
    # Concurrent checks in this shared account race for the same small available-number pool,
    # so a candidate search returns can already be claimed by someone else by the time we call
    # ClaimPhoneNumber -- retry across a few candidates rather than treating one loss as fatal.
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
        ctx.on_cleanup(lambda claim_id=claim_id: _release_phone_number(connect, claim_id))
        return phone_number
    raise AssertionError(f"could not claim any of {len(numbers)} candidate numbers: {last_error}")


def _stop_and_delete_campaign(ctx, campaign_id: str) -> None:
    # DeleteCampaign refuses a Running or Paused campaign, so stop it first.
    campaigns = ctx.client("connectcampaignsv2")
    if campaigns.get_campaign_state(id=campaign_id)["state"] in ("Running", "Paused"):
        campaigns.stop_campaign(id=campaign_id)
        _wait_for_state(ctx, campaign_id, "Stopped")
    campaigns.delete_campaign(id=campaign_id)


def _wait_for_state(ctx, campaign_id: str, target: str, timeout_s: float = 90.0) -> None:
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
