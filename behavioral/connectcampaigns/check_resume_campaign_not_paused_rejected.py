"""resume-campaign-not-paused-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resume-campaign-not-paused-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResumeCampaign on an already-Running campaign succeeds as a no-op and on a Paused one
    resumes it, but on a terminal Stopped campaign it is rejected with ConflictException and the
    campaign stays Stopped."""
    instance_id, flow_id = _create_onboarded_instance(ctx)
    campaign_id, _arn = _create_campaign(ctx, instance_id, flow_id)
    cc = ctx.client("connectcampaigns")

    cc.start_campaign(id=campaign_id)
    state = _wait_for_state(ctx, campaign_id, "Running")
    assert state == "Running", f"expected Running after start, got {state}"

    # ResumeCampaign on an already-Running campaign is idempotent, not rejected.
    err = _resume_error(cc, campaign_id)
    assert err is None, f"expected ResumeCampaign on a Running campaign to succeed, got {err}"
    state = cc.get_campaign_state(id=campaign_id)["state"]
    assert state == "Running", f"idempotent ResumeCampaign must not change state, got {state}"

    # positive control: once actually paused, Resume succeeds (restore + identical call)
    cc.pause_campaign(id=campaign_id)
    state = _wait_for_state(ctx, campaign_id, "Paused")
    assert state == "Paused", f"expected Paused after pause, got {state}"
    cc.resume_campaign(id=campaign_id)
    state = _wait_for_state(ctx, campaign_id, "Running")
    assert state == "Running", f"expected Running after resuming a Paused campaign, got {state}"

    # ResumeCampaign on a terminal Stopped campaign is rejected -- Stopped can never be resumed.
    # The terminal-state rejection is ConflictException, not
    # InvalidCampaignStateException (which ResumeCampaign models but real AWS reserves for a
    # different case -- ConflictException carries no "state" field, unlike InvalidCampaignStateException).
    cc.stop_campaign(id=campaign_id)
    state = _wait_for_state(ctx, campaign_id, "Stopped")
    assert state == "Stopped", f"expected Stopped after stop, got {state}"
    err = _resume_error(cc, campaign_id)
    assert err is not None, "expected ResumeCampaign on a Stopped campaign to be rejected"
    code = err["Error"]["Code"]
    message = err["Error"].get("Message")
    assert code == "ConflictException", f"expected ConflictException, got {code} ({message!r})"
    assert message == f"Campaign: {campaign_id} is in invalid state: STOPPED", message
    state = cc.get_campaign_state(id=campaign_id)["state"]
    assert state == "Stopped", f"rejected ResumeCampaign must not change state, got {state}"


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


def _resume_error(cc, campaign_id):
    try:
        cc.resume_campaign(id=campaign_id)
    except ClientError as exc:
        return exc.response
    return None


def _create_onboarded_instance(ctx):
    connect = ctx.client("connect")
    cc = ctx.client("connectcampaigns")

    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-cc-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real": CHECK},
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


def _create_campaign(ctx, instance_id, flow_id, dialer_config=None, name=None):
    cc = ctx.client("connectcampaigns")
    connect = ctx.client("connect")
    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]

    queues = connect.list_queues(InstanceId=instance_id, QueueTypes=["STANDARD"])["QueueSummaryList"]
    if not queues:
        raise AssertionError("newly created Connect instance has no default standard queue")
    queue_id = queues[0]["Id"]

    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn,
        PhoneNumberCountryCode="US",
        PhoneNumberType="DID",
        MaxResults=1,
    )["AvailableNumbersList"]
    if not numbers:
        raise AssertionError("no available phone numbers to claim for the test Connect instance")
    phone_number = numbers[0]["PhoneNumber"]
    claim_id = connect.claim_phone_number(TargetArn=instance_arn, PhoneNumber=phone_number)[
        "PhoneNumberId"
    ]
    ctx.on_cleanup(lambda: _release_phone_number(ctx, claim_id))

    resp = cc.create_campaign(
        name=name or ctx.unique_name("sim2real-campaign-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config or {"progressiveDialerConfig": {"bandwidthAllocation": 0.5}},
        outboundCallConfig={
            "connectContactFlowId": flow_id,
            "connectQueueId": queue_id,
            "connectSourcePhoneNumber": phone_number,
        },
        tags={"sim2real": CHECK},
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
