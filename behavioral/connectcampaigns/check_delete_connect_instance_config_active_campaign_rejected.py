"""delete-connect-instance-config-active-campaign-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-connect-instance-config-active-campaign-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConnectInstanceConfig is rejected with InvalidStateException while the instance has a
    Running campaign and the config stays readable; it succeeds once no campaigns remain."""
    fixture = _provision_campaign_fixture(ctx)
    campaigns = ctx.client("connectcampaigns")
    instance_id = fixture["connect_instance_id"]

    campaign = _create_campaign(ctx, fixture)
    campaigns.start_campaign(id=campaign["id"])
    _poll_until(lambda: _campaign_state(ctx, campaign["id"]), lambda s: s == "Running")

    code, message = _error_code_and_message(
        lambda: campaigns.delete_connect_instance_config(connectInstanceId=instance_id)
    )
    assert code == "InvalidStateException", f"expected InvalidStateException, got {code}"
    assert message == "This instance still has campaigns", message

    # Effect absent: the config is still there.
    config = campaigns.get_connect_instance_config(connectInstanceId=instance_id)
    got_id = config["connectInstanceConfig"]["connectInstanceId"]
    assert got_id == instance_id, (
        f"config must remain in place while the campaign is Running; expected {instance_id!r}, "
        f"got {got_id!r}"
    )

    # Positive control: once the campaign is stopped and removed, config deletion succeeds.
    campaigns.stop_campaign(id=campaign["id"])
    _poll_until(lambda: _campaign_state(ctx, campaign["id"]), lambda s: s == "Stopped")
    campaigns.delete_campaign(id=campaign["id"])
    campaigns.delete_connect_instance_config(connectInstanceId=instance_id)

    code_after, message_after = _error_code_and_message(
        lambda: campaigns.get_connect_instance_config(connectInstanceId=instance_id)
    )
    assert code_after == "ResourceNotFoundException", f"expected config gone, got code {code_after}"
    assert message_after == f"ConnectInstanceConfig not found {instance_id}.", message_after


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


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


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
        timeout_s=600.0,
        interval_s=5.0,
    )

    flows = connect.list_contact_flows(
        InstanceId=instance_id, ContactFlowTypes=["CONTACT_FLOW"], MaxResults=25
    )["ContactFlowSummaryList"]
    if not flows:
        raise AssertionError("newly created Connect instance has no default contact flows")
    contact_flow_id = flows[0]["Id"]

    queues = connect.list_queues(InstanceId=instance_id, QueueTypes=["STANDARD"])["QueueSummaryList"]
    if not queues:
        raise AssertionError("newly created Connect instance has no default standard queue")
    queue_id = queues[0]["Id"]

    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn, PhoneNumberCountryCode="US", PhoneNumberType="DID", MaxResults=10
    )["AvailableNumbersList"]
    if not numbers:
        raise AssertionError("no available phone numbers to claim for the test Connect instance")
    # A listed number can be claimed by another caller first; that refusal moves on to the next.
    claim_id = None
    for candidate in numbers:
        try:
            claim_id = connect.claim_phone_number(
                TargetArn=instance_arn, PhoneNumber=candidate["PhoneNumber"]
            )["PhoneNumberId"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidParameterException" or "Phone number not available" not in err.get("Message", ""):
                raise
            continue
        phone_number = candidate["PhoneNumber"]
        break
    if claim_id is None:
        raise AssertionError(f"none of the {len(numbers)} listed available phone numbers could be claimed")
    ctx.on_cleanup(lambda: _release_phone_number(connect, claim_id))

    campaigns.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )

    def _cleanup_onboarding():
        _teardown(
            lambda: campaigns.delete_connect_instance_config(connectInstanceId=instance_id),
            busy=_CAMPAIGNS_LEFT,
        )
        _teardown(
            lambda: campaigns.delete_instance_onboarding_job(connectInstanceId=instance_id),
            done=_JOB_NOT_DELETABLE,
        )

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
    ctx.on_cleanup(lambda: _delete_campaign_if_present(campaigns, campaign_id))
    return {"id": campaign_id, "arn": resp["arn"]}


def _delete_campaign_if_present(campaigns, campaign_id):
    # Teardown only: the check itself deletes the campaign on the success path.
    try:
        campaigns.delete_campaign(id=campaign_id)
    except campaigns.exceptions.ResourceNotFoundException:
        pass


# Only a failed onboarding job can be deleted; any other job goes with the instance config.
_JOB_NOT_DELETABLE = ("InvalidStateException",)
# DeleteConnectInstanceConfig refuses while a just-deleted campaign is still being removed.
_CAMPAIGNS_LEFT = ("InvalidStateException",)


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


def _release_phone_number(connect, claim_id):
    # Teardown only: a number Connect already released reads as not-found.
    try:
        connect.release_phone_number(PhoneNumberId=claim_id)
    except connect.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
