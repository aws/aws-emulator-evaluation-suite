"""start-campaign-already-running-is-an-idempotent-no-op."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "start-campaign-already-running-is-an-idempotent-no-op"
GROUP = "state-machine"
SERVICES = ["connectcampaigns"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartCampaign on an already-Running campaign is accepted as an idempotent no-op that leaves
    it Running, and a different valid transition (Pause) still succeeds on it afterwards."""
    instance_id, flow_id = _create_onboarded_instance(ctx)
    queue_id = _default_queue_id(ctx, instance_id)
    phone_number = _claim_phone_number(ctx, instance_id)
    campaign_id, _arn = _create_campaign(ctx, instance_id, flow_id, queue_id, phone_number)
    cc = ctx.client("connectcampaigns")

    cc.start_campaign(id=campaign_id)
    state = _wait_for_state(ctx, campaign_id, "Running")
    assert state == "Running", f"expected Running after StartCampaign, got {state!r}"

    # StartCampaign on an already-Running campaign succeeds (idempotent no-op on real AWS);
    # it must not raise and must not reset/duplicate the campaign.
    cc.start_campaign(id=campaign_id)
    state_after = cc.get_campaign_state(id=campaign_id)["state"]
    assert state_after == "Running", (
        f"a repeated StartCampaign on an already-Running campaign must not change state, "
        f"expected Running, got {state_after!r}"
    )

    # positive control: the campaign is not stuck -- a different valid transition still works
    cc.pause_campaign(id=campaign_id)
    paused_state = _wait_for_state(ctx, campaign_id, "Paused")
    assert paused_state == "Paused", f"expected Paused after PauseCampaign, got {paused_state!r}"


# ===== helpers =====
_FLOW_CONTENT = json.dumps(
    {
        "Version": "2019-10-30",
        "StartAction": "12345678-1234-1234-1234-123456789012",
        "Actions": [
            {
                "Identifier": "12345678-1234-1234-1234-123456789012",
                "Type": "DisconnectParticipant",
                "Parameters": {},
                "Transitions": {},
            }
        ],
    }
)


def _create_onboarded_instance(ctx):
    connect = ctx.client("connect")
    cc = ctx.client("connectcampaigns")

    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-cc-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real-check": CHECK},
    )["Id"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))

    deadline = time.monotonic() + 180
    status = None
    while time.monotonic() < deadline:
        status = connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"]
        if status == "ACTIVE":
            break
        if status == "FAILED":
            raise AssertionError("connect instance creation failed")
        time.sleep(5)
    else:
        raise AssertionError(f"connect instance never became ACTIVE (last status={status})")

    flow_id = connect.create_contact_flow(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2real-cc-flow-"),
        Type="CONTACT_FLOW",
        Content=_FLOW_CONTENT,
    )["ContactFlowId"]

    cc.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )
    ctx.on_cleanup(lambda: _safe_delete_instance_config(ctx, instance_id))

    deadline = time.monotonic() + 180
    status = None
    while time.monotonic() < deadline:
        status = cc.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ]["status"]
        if status == "SUCCEEDED":
            break
        if status == "FAILED":
            failure_code = _onboarding_failure_code(cc, instance_id)
            raise AssertionError(f"instance onboarding job failed (failureCode={failure_code})")
        time.sleep(3)
    else:
        raise AssertionError(f"onboarding job never reached SUCCEEDED (last status={status})")

    return instance_id, flow_id


def _safe_delete_instance_config(ctx, instance_id):
    cc = ctx.client("connectcampaigns")
    _delete_instance_config(cc, instance_id, time.monotonic() + _CONFIG_DELETE_S)


def _default_queue_id(ctx, instance_id):
    connect = ctx.client("connect")
    queues = connect.list_queues(InstanceId=instance_id, QueueTypes=["STANDARD"])["QueueSummaryList"]
    if not queues:
        raise AssertionError(f"connect instance {instance_id} has no standard queue to target")
    return queues[0]["Id"]


def _claim_phone_number(ctx, instance_id):
    connect = ctx.client("connect")
    target_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=target_arn, PhoneNumberCountryCode="US", PhoneNumberType="DID", MaxResults=1
    )["AvailableNumbersList"]
    if not numbers:
        raise AssertionError("no available DID phone numbers to claim for the test Connect instance")
    phone_number = numbers[0]["PhoneNumber"]
    claim_id = connect.claim_phone_number(TargetArn=target_arn, PhoneNumber=phone_number)["PhoneNumberId"]
    ctx.on_cleanup(lambda: connect.release_phone_number(PhoneNumberId=claim_id))
    return phone_number


def _create_campaign(ctx, instance_id, flow_id, queue_id, phone_number, dialer_config=None, name=None):
    cc = ctx.client("connectcampaigns")
    resp = cc.create_campaign(
        name=name or ctx.unique_name("sim2real-campaign-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config or {"agentlessDialerConfig": {"dialingCapacity": 1.0}},
        outboundCallConfig={
            "connectContactFlowId": flow_id,
            "connectQueueId": queue_id,
            "connectSourcePhoneNumber": phone_number,
        },
        tags={"sim2real-check": CHECK},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_campaign(ctx, campaign_id))
    return campaign_id, resp["arn"]


def _safe_delete_campaign(ctx, campaign_id):
    cc = ctx.client("connectcampaigns")
    try:
        cc.delete_campaign(id=campaign_id)
    except cc.exceptions.ResourceNotFoundException:
        pass


def _wait_for_state(ctx, campaign_id, expected, timeout_s=60.0):
    cc = ctx.client("connectcampaigns")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = cc.get_campaign_state(id=campaign_id)["state"]
        if state == expected:
            return state
        time.sleep(2)
    raise AssertionError(f"campaign never reached {expected!r}, last seen {state!r}")


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
