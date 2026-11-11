"""create-campaign-dialer-bandwidth-range-not-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-campaign-dialer-bandwidth-range-not-enforced"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCampaign does not enforce the modelled [0, 1] range of
    progressiveDialerConfig.bandwidthAllocation: 1.5 is accepted like an in-range value and
    DescribeCampaign echoes it back unclamped."""
    cc = ctx.client("connectcampaigns")
    instance_id, flow_id, queue_id, phone_number = _create_onboarded_instance_flow_queue_and_phone(ctx)
    outbound_call_config = {
        "connectContactFlowId": flow_id,
        "connectQueueId": queue_id,
        "connectSourcePhoneNumber": phone_number,
    }

    out_of_range_id = _create_campaign(ctx, cc, instance_id, outbound_call_config, 1.5)
    described = cc.describe_campaign(id=out_of_range_id)["campaign"]
    assert described["dialerConfig"]["progressiveDialerConfig"]["bandwidthAllocation"] == 1.5, described

    # same shape, in-range bandwidth, same onboarded instance -- also accepted and echoed
    # verbatim, proving the out-of-range acceptance above is not a fluke of this instance
    in_range_id = _create_campaign(ctx, cc, instance_id, outbound_call_config, 0.5)
    described2 = cc.describe_campaign(id=in_range_id)["campaign"]
    assert described2["dialerConfig"]["progressiveDialerConfig"]["bandwidthAllocation"] == 0.5, described2


# ===== helpers =====
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


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_campaign(ctx, cc, instance_id, outbound_call_config, bandwidth_allocation):
    resp = cc.create_campaign(
        name=ctx.unique_name("sim2real-camp-"),
        connectInstanceId=instance_id,
        dialerConfig={"progressiveDialerConfig": {"bandwidthAllocation": bandwidth_allocation}},
        outboundCallConfig=outbound_call_config,
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: _teardown(lambda: cc.delete_campaign(id=campaign_id)))
    return campaign_id


_FLOW_CONTENT = (
    '{"Version": "2019-10-30", "StartAction": "12345678-1234-1234-1234-123456789012", '
    '"Actions": [{"Identifier": "12345678-1234-1234-1234-123456789012", '
    '"Type": "DisconnectParticipant", "Parameters": {}, "Transitions": {}}]}'
)


def _create_onboarded_instance_flow_queue_and_phone(ctx):
    connect = ctx.client("connect")
    cc = ctx.client("connectcampaigns")
    alias = ctx.unique_name("sim2realcc-")
    resp = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
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

    flow_id = connect.create_contact_flow(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2realcc-flow-"),
        Type="CONTACT_FLOW",
        Content=_FLOW_CONTENT,
    )["ContactFlowId"]

    # A progressiveDialerConfig campaign requires a real connectQueueId, even though the
    # model does not mark it required; a freshly provisioned instance ships a default
    # "Basic Hours" hours-of-operation we can attach a queue to.
    hours_id = connect.list_hours_of_operations(InstanceId=instance_id, MaxResults=1)[
        "HoursOfOperationSummaryList"
    ][0]["Id"]
    queue_id = connect.create_queue(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2realcc-queue-"),
        HoursOfOperationId=hours_id,
    )["QueueId"]
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: connect.delete_queue(InstanceId=instance_id, QueueId=queue_id),
            busy=("ResourceInUseException",),
        )
    )

    # It also requires a real outbound source phone number -- the queue has none by
    # default and connectSourcePhoneNumber must be supplied instead. Claim one and
    # release it on teardown.
    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn,
        PhoneNumberCountryCode="US",
        PhoneNumberType="DID",
        MaxResults=10,
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
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: connect.release_phone_number(PhoneNumberId=claim_id),
            busy=("ResourceInUseException",),
        )
    )

    return instance_id, flow_id, queue_id, phone_number


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
