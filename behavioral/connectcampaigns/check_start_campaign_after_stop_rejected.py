"""start-campaign-after-stop-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-campaign-after-stop-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Stopped is terminal: StartCampaign on a Stopped campaign is rejected with ConflictException
    naming the campaign and its STOPPED state and the campaign stays Stopped, while a fresh
    campaign still starts (control)."""
    cc = ctx.client("connectcampaigns")
    instance_id = _create_onboarded_instance(ctx)
    flow_id = _pick_or_create_flow(ctx, instance_id)
    phone_number = _claim_phone_number(ctx, instance_id)

    stopped_id = _create_campaign(ctx, instance_id, flow_id, phone_number)
    cc.start_campaign(id=stopped_id)
    _poll_until(
        lambda: cc.get_campaign_state(id=stopped_id)["state"],
        lambda s: s == "Running",
        timeout_s=60.0,
        interval_s=3.0,
    )
    cc.stop_campaign(id=stopped_id)
    _poll_until(
        lambda: cc.get_campaign_state(id=stopped_id)["state"],
        lambda s: s == "Stopped",
        timeout_s=60.0,
        interval_s=3.0,
    )

    try:
        result = cc.start_campaign(id=stopped_id)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
    else:
        raise AssertionError(f"StartCampaign on a Stopped campaign SUCCEEDED: {result!r}")
    assert code == "ConflictException", f"expected ConflictException, got {code} ({message!r})"
    assert message == f"Campaign: {stopped_id} is in invalid state: STOPPED", message

    final_state = cc.get_campaign_state(id=stopped_id)["state"]
    assert final_state == "Stopped", f"expected campaign to remain Stopped after rejected StartCampaign, got {final_state}"

    # positive control: a fresh campaign can still be started normally.
    control_phone = _claim_phone_number(ctx, instance_id)
    control_id = _create_campaign(ctx, instance_id, flow_id, control_phone)
    cc.start_campaign(id=control_id)
    state = _poll_until(
        lambda: cc.get_campaign_state(id=control_id)["state"],
        lambda s: s == "Running",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert state == "Running", f"expected control campaign to reach Running, got {state}"


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


def _safe(fn, gone=("ResourceNotFoundException",)):
    """Teardown: run one delete; only the given already-gone codes count as done."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in gone:
            raise


# Only a FAILED onboarding job is deletable (InvalidStateException otherwise); a succeeded job
# goes with its instance config.
_JOB_GONE = ("ResourceNotFoundException", "InvalidStateException")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last!r}")


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

    _poll_until(
        lambda: connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=300.0,
        interval_s=5.0,
    )

    cc.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )
    ctx.on_cleanup(lambda: _safe(lambda: cc.delete_instance_onboarding_job(connectInstanceId=instance_id), _JOB_GONE))
    ctx.on_cleanup(lambda: _delete_instance_config(cc, instance_id, time.monotonic() + _CONFIG_DELETE_S))

    status = _poll_until(
        lambda: cc.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ],
        lambda s: s["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    if status["status"] != "SUCCEEDED":
        failure_code = _onboarding_failure_code(cc, instance_id)
        raise AssertionError(f"instance onboarding job ended in {status} (failureCode={failure_code}), expected SUCCEEDED")

    return instance_id


def _pick_or_create_flow(ctx, instance_id):
    connect = ctx.client("connect")
    return connect.create_contact_flow(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2real-cc-flow-"),
        Type="CONTACT_FLOW",
        Content=_FLOW_CONTENT,
        Tags={"sim2real": CHECK},
    )["ContactFlowId"]


def _claim_phone_number(ctx, instance_id):
    connect = ctx.client("connect")
    available = connect.search_available_phone_numbers(
        InstanceId=instance_id,
        PhoneNumberCountryCode="US",
        PhoneNumberType="DID",
        MaxResults=1,
    )["AvailableNumbersList"]
    if not available:
        raise AssertionError("no available DID phone numbers to claim for connectcampaigns outbound config")
    phone_number = available[0]["PhoneNumber"]
    resp = connect.claim_phone_number(InstanceId=instance_id, PhoneNumber=phone_number)
    phone_number_id = resp["PhoneNumberId"]
    ctx.on_cleanup(lambda: _safe(lambda: connect.release_phone_number(PhoneNumberId=phone_number_id)))
    return phone_number


def _create_campaign(ctx, instance_id, contact_flow_id, phone_number, *, dialer_config=None, name=None):
    campaigns = ctx.client("connectcampaigns")
    resp = campaigns.create_campaign(
        name=name or ctx.unique_name("sim2real-campaign-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config or {"agentlessDialerConfig": {}},
        outboundCallConfig={
            "connectContactFlowId": contact_flow_id,
            "connectSourcePhoneNumber": phone_number,
        },
        tags={"sim2real": CHECK},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: _safe(lambda: campaigns.delete_campaign(id=campaign_id)))
    return campaign_id


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
        try:
            leftovers = campaigns.list_campaigns(
                filters={"instanceIdFilter": {"value": instance_id, "operator": "Eq"}}
            )["campaignSummaryList"]
        except campaigns.exceptions.ValidationException as err:
            # An instance whose config is already deleted is not onboarded and has no campaigns.
            if "not onboarded" not in err.response["Error"]["Message"]:
                raise
            leftovers = []
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
