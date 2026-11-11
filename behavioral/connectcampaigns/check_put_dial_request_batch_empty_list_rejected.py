"""put-dial-request-batch-empty-list-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dial-request-batch-empty-list-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutDialRequestBatch with an empty dialRequests list (validation off in the client, so the service
    judges it) fails with ValidationException and its exact message, while one valid request on the same
    Running campaign is accepted with its clientToken."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    instance_id, flow_id = _create_onboarded_instance(ctx, teardown_deadline)
    campaign_id, _arn = _create_campaign(ctx, instance_id, flow_id, teardown_deadline)
    cc = ctx.client("connectcampaigns")
    cc_unvalidated = ctx.client("connectcampaigns", config=Config(parameter_validation=False))

    cc.start_campaign(id=campaign_id)
    assert _wait_for_state(ctx, campaign_id, "Running") == "Running"

    code, message = _error_code(
        lambda: cc_unvalidated.put_dial_request_batch(id=campaign_id, dialRequests=[])
    )
    assert code == "ValidationException", code
    expected = (
        "1 validation error detected: Value '[]' at 'dialRequests' failed to satisfy constraint: "
        "Member must have length greater than or equal to 1"
    )
    assert message == expected, message

    # Positive control: a structurally valid batch on the same campaign still succeeds --
    # the rejected empty batch left no residue that would break a subsequent good call.
    # A campaign just reporting Running can still fail entries while it becomes ready to ingest;
    # each attempt carries a fresh client token, so every attempt is a new dial request.
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else min(120.0, left - 10.0))
    while True:
        good_request = {
            "clientToken": ctx.unique_name("sim2real-dialtok-"),
            "phoneNumber": "+15555550100",
            "expirationTime": datetime.now(timezone.utc) + timedelta(minutes=10),
            "attributes": {},
        }
        result = cc.put_dial_request_batch(id=campaign_id, dialRequests=[good_request])
        if result["successfulRequests"] or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert len(result["successfulRequests"]) == 1, result
    assert result["successfulRequests"][0]["clientToken"] == good_request["clientToken"]


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
    """Call fn(); return (error code, message), raising if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


# budget.cleanup_timeout for behavioral/connectcampaigns, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _teardown(fn, teardown_deadline, busy=()):
    """Run one teardown call. ResourceNotFoundException means nothing is left to delete; a code in
    `busy` (a dependency still being released) is retried every 2 s to the shared cleanup deadline;
    anything else raises."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_onboarded_instance(ctx, teardown_deadline):
    connect = ctx.client("connect")
    cc = ctx.client("connectcampaigns")

    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-cc-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
    )["Id"]
    ctx.on_cleanup(lambda: connect.delete_instance(InstanceId=instance_id))

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
    ctx.on_cleanup(lambda: _safe_delete_instance_config(ctx, instance_id, teardown_deadline))

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

    return instance_id, flow_id


def _safe_delete_instance_config(ctx, instance_id, teardown_deadline):
    """The instance config refuses deletion while a campaign still uses it."""
    cc = ctx.client("connectcampaigns")
    _teardown(
        lambda: cc.delete_connect_instance_config(connectInstanceId=instance_id),
        teardown_deadline,
        busy=("InvalidStateException",),
    )


def _create_campaign(ctx, instance_id, flow_id, teardown_deadline, dialer_config=None, name=None):
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
    claim_id = connect.claim_phone_number(TargetArn=instance_arn, PhoneNumber=phone_number)[
        "PhoneNumberId"
    ]
    ctx.on_cleanup(lambda: _teardown(lambda: connect.release_phone_number(PhoneNumberId=claim_id), teardown_deadline))

    resp = cc.create_campaign(
        name=name or ctx.unique_name("sim2real-campaign-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config or {"agentlessDialerConfig": {"dialingCapacity": 1.0}},
        outboundCallConfig={
            "connectContactFlowId": flow_id,
            "connectSourcePhoneNumber": phone_number,
        },
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_campaign(ctx, campaign_id, teardown_deadline))
    return campaign_id, resp["arn"]


def _safe_delete_campaign(ctx, campaign_id, teardown_deadline):
    cc = ctx.client("connectcampaigns")
    _teardown(lambda: cc.delete_campaign(id=campaign_id), teardown_deadline)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
