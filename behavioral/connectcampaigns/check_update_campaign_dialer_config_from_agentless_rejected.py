"""update-campaign-dialer-config-from-agentless-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-campaign-dialer-config-from-agentless-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An agentless campaign's dialer type is immutable: UpdateCampaignDialerConfig to progressive is
    rejected with ValidationException naming the transition and the config stays agentless, while
    the same progressive config is accepted on a non-agentless campaign (control)."""
    cc = ctx.client("connectcampaigns")
    instance_id = _create_onboarded_instance(ctx)
    flow_id = _pick_or_create_flow(ctx, instance_id)

    agentless_campaign_id = _create_campaign(
        ctx, instance_id, flow_id, dialer_config={"agentlessDialerConfig": {"dialingCapacity": 1.0}}
    )

    progressive_config = {"progressiveDialerConfig": {"bandwidthAllocation": 0.5}}
    code, message = _error_code_and_message(
        lambda: cc.update_campaign_dialer_config(
            id=agentless_campaign_id, dialerConfig=progressive_config
        )
    )
    # Real AWS rejects this at request validation, not as a ConflictException, with a
    # ValidationException whose message names the specific from/to dialer types.
    assert code == "ValidationException", f"unexpected code: {code} ({message!r})"
    assert message == "Updating campaign dialer type from AGENTLESS to PROGRESSIVE is not allowed ", (
        repr(message)
    )

    described = cc.describe_campaign(id=agentless_campaign_id)["campaign"]
    assert "agentlessDialerConfig" in described["dialerConfig"], described["dialerConfig"]

    # positive control: progressiveDialerConfig is itself a valid, acceptable shape when used
    # to create a brand-new (non-agentless) campaign
    other_campaign_id = _create_campaign(ctx, instance_id, flow_id, dialer_config=progressive_config)
    other_described = cc.describe_campaign(id=other_campaign_id)["campaign"]
    assert "progressiveDialerConfig" in other_described["dialerConfig"], other_described["dialerConfig"]

    # second positive control: UpdateCampaignDialerConfig itself can succeed for a legitimate
    # transition (between two non-agentless types) -- without this, the rejection above is
    # indistinguishable from "the update call never succeeds at all".
    cc.update_campaign_dialer_config(
        id=other_campaign_id, dialerConfig={"predictiveDialerConfig": {"bandwidthAllocation": 0.5}}
    )
    other_described_after = cc.describe_campaign(id=other_campaign_id)["campaign"]
    assert "predictiveDialerConfig" in other_described_after["dialerConfig"], other_described_after["dialerConfig"]


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


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _safe(fn, gone=("ResourceNotFoundException",)):
    """Teardown: run one delete; only the given already-gone codes count as done."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in gone:
            raise


# Only a FAILED onboarding job is deletable (InvalidStateException otherwise); a succeeded job
# goes with its instance config.
_JOB_GONE = ("ResourceNotFoundException", "InvalidStateException")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_onboarded_instance(ctx):
    connect = ctx.client("connect")
    cc = ctx.client("connectcampaigns")
    alias = ctx.unique_name("sim2realcc-")
    resp = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"env": "sim2real"},
    )
    instance_id = resp["Id"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))
    _poll_until(
        lambda: connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=600.0,
        interval_s=5.0,
    )
    cc.start_instance_onboarding_job(connectInstanceId=instance_id, encryptionConfig={"enabled": False})
    ctx.on_cleanup(lambda: _safe(lambda: cc.delete_instance_onboarding_job(connectInstanceId=instance_id), _JOB_GONE))
    status = _poll_until(
        lambda: cc.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ]["status"],
        lambda s: s in ("SUCCEEDED", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    if status != "SUCCEEDED":
        failure_code = _onboarding_failure_code(cc, instance_id)
        raise AssertionError(f"instance onboarding job ended in {status} (failureCode={failure_code}), expected SUCCEEDED")
    return instance_id


def _pick_or_create_flow(ctx, instance_id):
    connect = ctx.client("connect")
    return connect.create_contact_flow(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2realcc-flow-"),
        Type="CONTACT_FLOW",
        Content=_FLOW_CONTENT,
        Tags={"env": "sim2real"},
    )["ContactFlowId"]


def _create_campaign(ctx, instance_id, contact_flow_id, dialer_config=None, name=None):
    cc = ctx.client("connectcampaigns")
    connect = ctx.client("connect")
    dialer_config = dialer_config or {"progressiveDialerConfig": {"bandwidthAllocation": 0.5}}

    # CreateCampaign requires the outbound call config to carry a claimed source phone number
    # (real AWS rejects connectContactFlowId alone), and a non-agentless dialer additionally
    # requires connectQueueId ("Missing required parameter ConnectQueueId").
    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn, PhoneNumberCountryCode="US", PhoneNumberType="DID", MaxResults=10
    )["AvailableNumbersList"]
    assert numbers, "no available phone numbers to claim for the test Connect instance"
    # An advertised number can already be gone by the time it is claimed ("Phone number not
    # available"), so try the next candidate rather than charging that race to the target.
    claim_id = None
    for candidate in numbers:
        phone_number = candidate["PhoneNumber"]
        try:
            claim_id = connect.claim_phone_number(TargetArn=instance_arn, PhoneNumber=phone_number)[
                "PhoneNumberId"
            ]
            break
        except connect.exceptions.InvalidParameterException:
            continue
    if claim_id is None:
        raise AssertionError(f"could not claim any of {len(numbers)} advertised-available DID numbers")
    ctx.on_cleanup(lambda: _safe(lambda: connect.release_phone_number(PhoneNumberId=claim_id)))

    queues = connect.list_queues(InstanceId=instance_id, QueueTypes=["STANDARD"])["QueueSummaryList"]
    assert queues, "newly created Connect instance has no default standard queue"
    queue_id = queues[0]["Id"]

    resp = cc.create_campaign(
        name=name or ctx.unique_name("sim2real-camp-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config,
        outboundCallConfig={
            "connectContactFlowId": contact_flow_id,
            "connectSourcePhoneNumber": phone_number,
            "connectQueueId": queue_id,
        },
        tags={"env": "sim2real"},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: _safe(lambda: cc.delete_campaign(id=campaign_id)))
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
