"""put-dial-request-batch-invalid-phone-number-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dial-request-batch-invalid-phone-number-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutDialRequestBatch returns 200 for a DialRequest whose phoneNumber violates the pattern,
    reporting it per item in failedRequests (failureCode InvalidInput), while a valid entry in the
    same call lands in successfulRequests."""
    instance_id, flow_id = _create_onboarded_instance(ctx)
    campaign_id, _arn, source_number = _create_campaign(ctx, instance_id, flow_id)
    cc = ctx.client("connectcampaigns")

    cc.start_campaign(id=campaign_id)
    assert _wait_for_state(ctx, campaign_id, "Running") == "Running"

    def _dial_request(prefix):
        return {
            "clientToken": ctx.unique_name(prefix),
            "phoneNumber": source_number,
            "expirationTime": datetime.now(timezone.utc) + timedelta(minutes=10),
            "attributes": {},
        }

    # Warm-up: freshly claimed source numbers take a few seconds to propagate through the
    # dialer, during which an otherwise-valid PutDialRequestBatch also comes back
    # InvalidInput until the freshly claimed number has propagated (typically a few
    # seconds). Retry a real, well-formed request on a bounded schedule until it is
    # accepted, so the test batch below runs only once the campaign is demonstrably ready —
    # this is also the required positive control proving the account and campaign are
    # otherwise healthy before the negative.
    deadline = time.monotonic() + 90
    warm_id = None
    while time.monotonic() < deadline:
        warmup = _dial_request("sim2real-dialtok-warmup-")
        resp = cc.put_dial_request_batch(id=campaign_id, dialRequests=[warmup])
        if resp.get("successfulRequests"):
            warm_id = resp["successfulRequests"][0]["id"]
            break
        time.sleep(5)
    assert warm_id is not None, "campaign never accepted a structurally valid dial request"

    bad_request = {
        "clientToken": ctx.unique_name("sim2real-dialtok-bad-"),
        "phoneNumber": "not-a-number",  # violates the ^[\\d\\-+]*$ pattern
        "expirationTime": datetime.now(timezone.utc) + timedelta(minutes=10),
        "attributes": {},
    }
    # The destination for the good entry is the number this check itself just claimed on the
    # instance, not an arbitrary or reserved-for-fiction number, so a dial actually landing
    # before teardown never reaches an uninvolved third party.
    good_request = _dial_request("sim2real-dialtok-good-")
    try:
        result = cc.put_dial_request_batch(
            id=campaign_id, dialRequests=[bad_request, good_request]
        )
    finally:
        cc.pause_campaign(id=campaign_id)

    failed = result.get("failedRequests", [])
    assert [f["clientToken"] for f in failed] == [bad_request["clientToken"]], failed
    assert failed[0]["failureCode"] == "InvalidInput", failed[0]

    succeeded = result.get("successfulRequests", [])
    assert [s["clientToken"] for s in succeeded] == [good_request["clientToken"]], succeeded

    succeeded = result.get("successfulRequests", [])
    assert [s["clientToken"] for s in succeeded] == [good_request["clientToken"]], succeeded


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
    _teardown(
        lambda: cc.delete_connect_instance_config(connectInstanceId=instance_id),
        busy=_CAMPAIGNS_LEFT,
    )


def _create_campaign(ctx, instance_id, flow_id, dialer_config=None, name=None):
    cc = ctx.client("connectcampaigns")
    connect = ctx.client("connect")
    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn,
        PhoneNumberCountryCode="US",
        PhoneNumberType="DID",
        MaxResults=1,
    )["AvailableNumbersList"]
    assert numbers, "no available phone numbers to claim for the test Connect instance"
    phone_number = numbers[0]["PhoneNumber"]
    claim_id = connect.claim_phone_number(
        TargetArn=instance_arn, PhoneNumber=phone_number, Tags={"sim2real": CHECK}
    )["PhoneNumberId"]
    ctx.on_cleanup(lambda: _teardown(lambda: connect.release_phone_number(PhoneNumberId=claim_id)))

    resp = cc.create_campaign(
        name=name or ctx.unique_name("sim2real-campaign-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config or {"agentlessDialerConfig": {"dialingCapacity": 1.0}},
        outboundCallConfig={
            "connectContactFlowId": flow_id,
            "connectSourcePhoneNumber": phone_number,
        },
        tags={"sim2real": CHECK},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_campaign(ctx, campaign_id))
    return campaign_id, resp["arn"], phone_number


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
