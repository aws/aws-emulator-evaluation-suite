"""update-campaign-dialer-config-to-agentless-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-campaign-dialer-config-to-agentless-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Switching a non-agentless campaign to agentless via UpdateCampaignDialerConfig is rejected
    with ValidationException naming both dialer types and leaves its config unchanged, while a
    switch between two non-agentless types is allowed."""
    instance_id, flow_id = _create_onboarded_instance(ctx)
    queue_id = _default_queue_id(ctx, instance_id)
    phone_number = _claim_phone_number(ctx, instance_id)
    campaign_id, _arn = _create_campaign(
        ctx,
        instance_id,
        flow_id,
        queue_id,
        phone_number,
        dialer_config={"progressiveDialerConfig": {"bandwidthAllocation": 0.5}},
    )
    cc = ctx.client("connectcampaigns")

    code, message = _error(
        lambda: cc.update_campaign_dialer_config(
            id=campaign_id,
            dialerConfig={"agentlessDialerConfig": {"dialingCapacity": 1.0}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message!r})"
    assert message == "Updating campaign dialer type from PROGRESSIVE to AGENTLESS is not allowed ", message

    described = cc.describe_campaign(id=campaign_id)["campaign"]
    assert "progressiveDialerConfig" in described["dialerConfig"], (
        f"dialer config must not change on a rejected update, got {described['dialerConfig']!r}"
    )
    assert "agentlessDialerConfig" not in described["dialerConfig"], (
        f"rejected update to agentlessDialerConfig must not take effect, got {described['dialerConfig']!r}"
    )

    # positive control: switching between two non-agentless dialer types is allowed
    cc.update_campaign_dialer_config(
        id=campaign_id,
        dialerConfig={"predictiveDialerConfig": {"bandwidthAllocation": 0.5}},
    )
    described_after = cc.describe_campaign(id=campaign_id)["campaign"]
    assert "predictiveDialerConfig" in described_after["dialerConfig"], (
        f"expected the non-agentless-to-non-agentless update to succeed, got {described_after['dialerConfig']!r}"
    )


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


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so an acceptance fails as an acceptance, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    ctx.on_cleanup(lambda: _release_phone_number(ctx, claim_id))
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


def _release_phone_number(ctx, phone_number_id):
    """Teardown: release a claimed number, tolerating one that is already gone."""
    connect = ctx.client("connect")
    try:
        connect.release_phone_number(PhoneNumberId=phone_number_id)
    except connect.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
