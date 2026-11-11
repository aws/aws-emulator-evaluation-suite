"""get-campaign-state-batch-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-campaign-state-batch-after-delete"
GROUP = "state"
SERVICES = ["connectcampaigns"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCampaignStateBatch reports a deleted campaign id in failedRequests with failureCode
    ResourceNotFound, while a live campaign in the same call lands in successfulRequests."""
    cc = ctx.client("connectcampaigns")
    instance_id = _create_onboarded_instance(ctx)
    flow_id = _pick_or_create_flow(ctx, instance_id)
    queue_id = _pick_queue(ctx, instance_id)
    phone_number = _claim_phone_number(ctx, instance_id)

    live_campaign_id = _create_campaign(ctx, instance_id, flow_id, queue_id, phone_number)
    doomed_campaign_id = _create_campaign(ctx, instance_id, flow_id, queue_id, phone_number)

    cc.delete_campaign(id=doomed_campaign_id)
    _poll_until(
        lambda: _describe_code(cc, doomed_campaign_id),
        lambda c: c == "ResourceNotFoundException",
        timeout_s=60.0,
        interval_s=2.0,
    )

    resp = cc.get_campaign_state_batch(campaignIds=[live_campaign_id, doomed_campaign_id])
    successful = {r["campaignId"]: r["state"] for r in resp.get("successfulRequests", [])}
    failed = {r["campaignId"]: r["failureCode"] for r in resp.get("failedRequests", [])}

    assert successful.get(live_campaign_id) == "Initialized", successful
    assert failed.get(doomed_campaign_id) == "ResourceNotFound", failed
    assert doomed_campaign_id not in successful, (
        f"deleted campaign {doomed_campaign_id} unexpectedly reported as successful: {successful}"
    )
    assert live_campaign_id not in failed, (
        f"live campaign {live_campaign_id} unexpectedly reported as failed: {failed}"
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


_DESCRIBE_SUCCEEDED = "<describe_campaign succeeded>"


def _describe_code(cc, campaign_id):
    """Poll probe: the error code of DescribeCampaign, or a sentinel no error code can equal
    while the campaign is still describable."""
    from botocore.exceptions import ClientError

    try:
        cc.describe_campaign(id=campaign_id)
    except ClientError as err:
        return err.response["Error"]["Code"]
    return _DESCRIBE_SUCCEEDED


# Only a failed onboarding job can be deleted; any other job goes with the instance config.
_JOB_NOT_DELETABLE = ("InvalidStateException",)


def _teardown(fn, done=(), busy=()):
    """Run one teardown call. ResourceNotFoundException or a code in `done` means nothing is left to
    delete; a code in `busy` (a dependency still being released) is retried every 2 s for up to 60 s;
    anything else raises."""
    deadline = time.monotonic() + 60
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException" or code in done:
                return
            if code not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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
        Tags={"sim2real": CHECK},
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
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: cc.delete_instance_onboarding_job(connectInstanceId=instance_id),
            done=_JOB_NOT_DELETABLE,
        )
    )
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
        Tags={"sim2real": CHECK},
    )["ContactFlowId"]


def _pick_queue(ctx, instance_id):
    connect = ctx.client("connect")
    queues = connect.list_queues(InstanceId=instance_id, QueueTypes=["STANDARD"])["QueueSummaryList"]
    if not queues:
        raise AssertionError(f"connect instance {instance_id} has no standard queue for the campaign")
    return queues[0]["Id"]


def _claim_phone_number(ctx, instance_id):
    connect = ctx.client("connect")
    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn,
        PhoneNumberCountryCode="US",
        PhoneNumberType="DID",
        MaxResults=1,
    )["AvailableNumbersList"]
    if not numbers:
        raise AssertionError("no available phone numbers to claim for the test Connect instance")
    phone_number = numbers[0]["PhoneNumber"]
    claim_id = connect.claim_phone_number(TargetArn=instance_arn, PhoneNumber=phone_number)["PhoneNumberId"]
    ctx.on_cleanup(lambda: _teardown(lambda: connect.release_phone_number(PhoneNumberId=claim_id), busy=("ResourceInUseException",)))
    return phone_number


def _create_campaign(ctx, instance_id, contact_flow_id, queue_id, phone_number, dialer_config=None, name=None):
    cc = ctx.client("connectcampaigns")
    dialer_config = dialer_config or {"progressiveDialerConfig": {"bandwidthAllocation": 0.5}}
    resp = cc.create_campaign(
        name=name or ctx.unique_name("sim2real-camp-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config,
        outboundCallConfig={
            "connectContactFlowId": contact_flow_id,
            "connectQueueId": queue_id,
            "connectSourcePhoneNumber": phone_number,
        },
        tags={"sim2real": CHECK},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: _teardown(lambda: cc.delete_campaign(id=campaign_id)))
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
        except campaigns.exceptions.ResourceNotFoundException:
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
        _teardown(lambda: campaigns.delete_connect_instance_config(connectInstanceId=instance_id), busy=("InvalidStateException",))
        while True:
            try:
                campaigns.get_connect_instance_config(connectInstanceId=instance_id)
            except campaigns.exceptions.ResourceNotFoundException:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f"campaigns instance config {instance_id} still present after {_TEARDOWN_TIMEOUT_S}s")
            time.sleep(2)
    finally:
        try:
            connect.delete_instance(InstanceId=instance_id)
        except connect.exceptions.ResourceNotFoundException:
            pass
        else:
            while True:
                try:
                    connect.describe_instance(InstanceId=instance_id)
                except connect.exceptions.ResourceNotFoundException:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"Connect instance {instance_id} still present after {_TEARDOWN_TIMEOUT_S}s")
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
