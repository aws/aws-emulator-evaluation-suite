"""put-dial-request-batch-concurrent-same-client-token-deduplicated."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dial-request-batch-concurrent-same-client-token-deduplicated"
GROUP = "concurrency"
SERVICES = ["connectcampaigns"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Firing several concurrent PutDialRequestBatch calls carrying the identical DialRequest
    (same clientToken) at a Running campaign never produces two distinct dial request ids for
    that clientToken -- the client-token dedup invariant holds under contention."""
    instance_id, flow_id, queue_id, phone_number = _create_onboarded_instance(ctx)
    campaign_id, _arn = _create_campaign(ctx, instance_id, flow_id, queue_id, phone_number)
    cc = ctx.client("connectcampaigns")

    cc.start_campaign(id=campaign_id)
    state = _wait_for_state(ctx, campaign_id, "Running")
    assert state == "Running", f"campaign did not reach Running, saw {state!r}"

    token = ctx.unique_name("sim2real-dialtok-")
    request = {
        "clientToken": token,
        "phoneNumber": "+15555550100",
        "expirationTime": datetime.now(timezone.utc) + timedelta(minutes=10),
        "attributes": {},
    }

    def _fire(_i):
        return cc.put_dial_request_batch(id=campaign_id, dialRequests=[request])

    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(_fire, range(6)))

    success_ids = set()
    rejected = []
    for resp in responses:
        for entry in resp.get("successfulRequests", []):
            if entry.get("clientToken") == token:
                success_ids.add(entry["id"])
        for entry in resp.get("failedRequests", []):
            if entry.get("clientToken") == token:
                rejected.append(entry)

    for entry in rejected:
        assert entry.get("failureCode") == "UnknownError", (
            f"expected a losing racer's failureCode to be UnknownError, got {entry}"
        )
    assert len(success_ids) >= 1, "no racer succeeded at all"
    assert len(success_ids) == 1, f"clientToken dedup violated, saw distinct ids {success_ids}"


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


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


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
            raise AssertionError("instance onboarding job failed")
        time.sleep(3)
    else:
        raise AssertionError(f"onboarding job never reached SUCCEEDED (last status={status})")

    # CreateCampaign rejects an outboundCallConfig carrying only connectContactFlowId with
    # "No queue or connectSourcePhoneNumber is supplied" -- real AWS requires one of the two even
    # though the Smithy model marks neither required. A freshly provisioned instance ships a
    # default "Basic Hours" hours-of-operation we can attach a queue to.
    hours_id = connect.list_hours_of_operations(InstanceId=instance_id, MaxResults=1)[
        "HoursOfOperationSummaryList"
    ][0]["Id"]
    queue_id = connect.create_queue(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2real-cc-queue-"),
        HoursOfOperationId=hours_id,
    )["QueueId"]
    ctx.on_cleanup(lambda: _safe_delete_queue(ctx, instance_id, queue_id))

    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn,
        PhoneNumberCountryCode="US",
        PhoneNumberType="DID",
        MaxResults=1,
    )["AvailableNumbersList"]
    assert numbers, "no available phone numbers to claim for the test Connect instance"
    phone_number = numbers[0]["PhoneNumber"]
    claim_id = connect.claim_phone_number(TargetArn=instance_arn, PhoneNumber=phone_number)[
        "PhoneNumberId"
    ]
    ctx.on_cleanup(lambda: _safe_release_phone_number(ctx, claim_id))

    return instance_id, flow_id, queue_id, phone_number


def _safe_delete_queue(ctx, instance_id, queue_id):
    connect = ctx.client("connect")
    _teardown(
        lambda: connect.delete_queue(InstanceId=instance_id, QueueId=queue_id),
        busy=("ResourceInUseException",),
    )


def _safe_release_phone_number(ctx, claim_id):
    connect = ctx.client("connect")
    _teardown(
        lambda: connect.release_phone_number(PhoneNumberId=claim_id),
        busy=("ResourceInUseException",),
    )


def _safe_delete_instance_config(ctx, instance_id):
    cc = ctx.client("connectcampaigns")
    _teardown(
        lambda: cc.delete_connect_instance_config(connectInstanceId=instance_id),
        busy=_CAMPAIGNS_LEFT,
    )


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
    _teardown(lambda: cc.delete_campaign(id=campaign_id))


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
