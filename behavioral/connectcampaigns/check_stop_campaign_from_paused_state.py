"""stop-campaign-from-paused-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-campaign-from-paused-state"
GROUP = "state-machine"
SERVICES = ["connectcampaigns"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopCampaign works directly from Paused: a Paused campaign transitions straight to Stopped
    without being Resumed first."""
    cc = ctx.client("connectcampaigns")
    instance_id = _create_onboarded_instance(ctx)
    flow_id = _pick_or_create_flow(ctx, instance_id)
    queue_id = _get_or_create_queue_id(ctx, instance_id)
    campaign_id = _create_campaign(ctx, instance_id, flow_id, queue_id)

    cc.start_campaign(id=campaign_id)
    _poll_until(
        lambda: cc.get_campaign_state(id=campaign_id)["state"],
        lambda s: s == "Running",
        timeout_s=60.0,
        interval_s=3.0,
    )
    cc.pause_campaign(id=campaign_id)
    _poll_until(
        lambda: cc.get_campaign_state(id=campaign_id)["state"],
        lambda s: s == "Paused",
        timeout_s=60.0,
        interval_s=3.0,
    )

    cc.stop_campaign(id=campaign_id)
    final_state = _poll_until(
        lambda: cc.get_campaign_state(id=campaign_id)["state"],
        lambda s: s == "Stopped",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert final_state == "Stopped", f"expected campaign to reach Stopped directly from Paused, got {final_state!r}"


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
        timeout_s=180.0,
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


def _get_or_create_queue_id(ctx, instance_id):
    connect = ctx.client("connect")
    queues = connect.list_queues(InstanceId=instance_id, QueueTypes=["STANDARD"])["QueueSummaryList"]
    if queues:
        return queues[0]["Id"]
    days = ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"]
    hours_id = connect.create_hours_of_operation(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2realcc-hours-"),
        TimeZone="UTC",
        Config=[
            {"Day": day, "StartTime": {"Hours": 0, "Minutes": 0}, "EndTime": {"Hours": 23, "Minutes": 59}}
            for day in days
        ],
        Tags={"env": "sim2real"},
    )["HoursOfOperationId"]
    return connect.create_queue(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2realcc-queue-"),
        HoursOfOperationId=hours_id,
        Tags={"env": "sim2real"},
    )["QueueId"]


def _create_campaign(ctx, instance_id, contact_flow_id, queue_id, dialer_config=None, name=None):
    cc = ctx.client("connectcampaigns")
    dialer_config = dialer_config or {"progressiveDialerConfig": {"bandwidthAllocation": 0.5}}
    resp = cc.create_campaign(
        name=name or ctx.unique_name("sim2real-camp-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config,
        outboundCallConfig={
            "connectContactFlowId": contact_flow_id,
            "connectQueueId": queue_id,
            "connectSourcePhoneNumber": "+15555550100",
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
