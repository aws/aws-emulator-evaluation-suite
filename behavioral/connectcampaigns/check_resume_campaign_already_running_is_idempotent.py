"""resume-campaign-already-running-is-idempotent."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "resume-campaign-already-running-is-idempotent"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResumeCampaign on an already-Running campaign is accepted as a no-op and it stays Running;
    resuming a genuinely Paused campaign also succeeds, proving the no-op is tolerance and not a
    Resume that never acts."""
    fixture = _provision_campaign_fixture(ctx)
    campaigns = ctx.client("connectcampaigns")

    running = _create_campaign(ctx, fixture)
    campaigns.start_campaign(id=running["id"])
    _poll_until(lambda: _campaign_state(ctx, running["id"]), lambda s: s == "Running")

    campaigns.resume_campaign(id=running["id"])
    assert _campaign_state(ctx, running["id"]) == "Running", (
        "ResumeCampaign on an already-Running campaign must be a no-op that leaves it Running"
    )

    # Control: resuming a genuinely Paused campaign also succeeds.
    control = _create_campaign(ctx, fixture)
    campaigns.start_campaign(id=control["id"])
    _poll_until(lambda: _campaign_state(ctx, control["id"]), lambda s: s == "Running")
    campaigns.pause_campaign(id=control["id"])
    _poll_until(lambda: _campaign_state(ctx, control["id"]), lambda s: s == "Paused")
    campaigns.resume_campaign(id=control["id"])
    state = _poll_until(lambda: _campaign_state(ctx, control["id"]), lambda s: s == "Running")
    assert state == "Running", f"expected Running after resuming a Paused campaign, got {state}"


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last!r}")


def _campaign_state(ctx, campaign_id):
    return ctx.client("connectcampaigns").get_campaign_state(id=campaign_id)["state"]


def _provision_campaign_fixture(ctx):
    connect = ctx.client("connect")
    campaigns = ctx.client("connectcampaigns")
    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-cc-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real:managed": "true"},
    )["Id"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))

    _poll_until(
        lambda: connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=300.0,
        interval_s=5.0,
    )

    flows = connect.list_contact_flows(
        InstanceId=instance_id, ContactFlowTypes=["CONTACT_FLOW"], MaxResults=25
    )["ContactFlowSummaryList"]
    if not flows:
        raise AssertionError("newly created Connect instance has no default contact flows")
    contact_flow_id = flows[0]["Id"]

    hours = connect.list_hours_of_operations(InstanceId=instance_id, MaxResults=25)[
        "HoursOfOperationSummaryList"
    ]
    if not hours:
        raise AssertionError("newly created Connect instance has no default hours of operation")
    queue_id = connect.create_queue(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2real-cc-queue-"),
        HoursOfOperationId=hours[0]["Id"],
        Tags={"sim2real:managed": "true"},
    )["QueueId"]
    ctx.on_cleanup(lambda: connect.delete_queue(InstanceId=instance_id, QueueId=queue_id))

    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn, PhoneNumberCountryCode="US", PhoneNumberType="DID", MaxResults=1
    )["AvailableNumbersList"]
    if not numbers:
        raise AssertionError("no available phone numbers to claim for the test Connect instance")
    phone_number = numbers[0]["PhoneNumber"]
    claim_id = connect.claim_phone_number(TargetArn=instance_arn, PhoneNumber=phone_number)[
        "PhoneNumberId"
    ]
    ctx.on_cleanup(lambda: connect.release_phone_number(PhoneNumberId=claim_id))

    campaigns.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )

    def _cleanup_onboarding():
        _delete_instance_config(campaigns, instance_id, time.monotonic() + _CONFIG_DELETE_S)
        try:
            campaigns.delete_instance_onboarding_job(connectInstanceId=instance_id)
        except (
            campaigns.exceptions.ResourceNotFoundException,
            campaigns.exceptions.InvalidStateException,
        ):
            pass  # only a FAILED job is deletable; a succeeded one goes with its config

    ctx.on_cleanup(_cleanup_onboarding)

    status = _poll_until(
        lambda: campaigns.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ],
        lambda s: s["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    if status["status"] != "SUCCEEDED":
        raise AssertionError(f"instance onboarding job failed: {status}")

    return {
        "connect_instance_id": instance_id,
        "contact_flow_id": contact_flow_id,
        "queue_id": queue_id,
        "phone_number": phone_number,
    }


def _create_campaign(ctx, fixture, *, dialer_config=None, name=None):
    campaigns = ctx.client("connectcampaigns")
    resp = campaigns.create_campaign(
        name=name or ctx.unique_name("sim2real-campaign-"),
        connectInstanceId=fixture["connect_instance_id"],
        dialerConfig=dialer_config or {"progressiveDialerConfig": {"bandwidthAllocation": 0.5}},
        outboundCallConfig={
            "connectContactFlowId": fixture["contact_flow_id"],
            "connectQueueId": fixture["queue_id"],
            "connectSourcePhoneNumber": fixture["phone_number"],
        },
        tags={"sim2real:managed": "true"},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: campaigns.delete_campaign(id=campaign_id))
    return {"id": campaign_id, "arn": resp["arn"]}


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
