"""put-dial-request-batch-idempotent-retry."""
from __future__ import annotations

import datetime
import time
import uuid

from behavioral_harness import tags

CHECK = "put-dial-request-batch-idempotent-retry"
GROUP = "state"
SERVICES = ["connectcampaigns"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Resubmitting a dial request with the same clientToken to a Running campaign returns it in
    successfulRequests again, not as a failure. Both calls resolve to the same dial request id, so a retry
    never places a second call.
    """
    cc = ctx.client("connectcampaigns")
    connect = ctx.client("connect")
    instance_id = _create_onboarded_instance(ctx)
    flow_id = _pick_contact_flow_id(ctx, instance_id)
    source_number = _claim_source_phone_number(ctx, connect, instance_id)
    campaign_id = _create_campaign(ctx, instance_id, flow_id, source_number)
    cc.start_campaign(id=campaign_id)
    _poll_until(
        lambda: _get_state(cc, campaign_id), lambda s: s == "Running", timeout_s=60.0, interval_s=3.0
    )

    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)
    token = str(uuid.uuid4())
    dial_request = {
        "clientToken": token,
        "phoneNumber": "+12065550100",
        "expirationTime": expiration,
        "attributes": {},
    }

    first = cc.put_dial_request_batch(id=campaign_id, dialRequests=[dial_request])
    assert first.get("failedRequests", []) == [], f"first submission failed: {first}"
    first_successful = {r["clientToken"]: r["id"] for r in first["successfulRequests"]}
    assert token in first_successful, (
        f"expected token {token!r} in first submission's successfulRequests, got {first_successful}"
    )

    second = cc.put_dial_request_batch(id=campaign_id, dialRequests=[dial_request])
    assert second.get("failedRequests", []) == [], f"idempotent retry failed: {second}"
    second_successful = {r["clientToken"]: r["id"] for r in second["successfulRequests"]}
    assert token in second_successful, (
        f"expected token {token!r} in idempotent retry's successfulRequests, got {second_successful}"
    )
    assert second_successful[token] == first_successful[token], (
        "idempotent retry allocated a different dial request id: "
        f"{first_successful[token]!r} vs {second_successful[token]!r}"
    )


def _get_state(cc, campaign_id):
    return cc.get_campaign_state(id=campaign_id)["state"]


def _safe(fn):
    try:
        fn()
    except Exception:
        pass


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
    alias = ctx.unique_name("s2rcc-")
    resp = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"simparity-audit": CHECK},
    )
    instance_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: connect.delete_instance(InstanceId=instance_id)))
    _poll_until(
        lambda: connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
    )
    cc.start_instance_onboarding_job(connectInstanceId=instance_id, encryptionConfig={"enabled": False})
    ctx.on_cleanup(lambda: _safe(lambda: cc.delete_instance_onboarding_job(connectInstanceId=instance_id)))
    status = _poll_until(
        lambda: cc.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ]["status"],
        lambda s: s in ("SUCCEEDED", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    if status != "SUCCEEDED":
        raise AssertionError(f"instance onboarding job ended in {status}, expected SUCCEEDED")
    return instance_id


_FLOW_CONTENT = (
    '{"Version": "2019-10-30", "StartAction": "12345678-1234-1234-1234-123456789012", '
    '"Actions": [{"Identifier": "12345678-1234-1234-1234-123456789012", '
    '"Type": "DisconnectParticipant", "Parameters": {}, "Transitions": {}}]}'
)


def _pick_contact_flow_id(ctx, instance_id):
    connect = ctx.client("connect")
    return connect.create_contact_flow(
        InstanceId=instance_id,
        Name=ctx.unique_name("s2rcc-flow-"),
        Type="CONTACT_FLOW",
        Content=_FLOW_CONTENT,
        Tags={"simparity-audit": CHECK},
    )["ContactFlowId"]


def _claim_source_phone_number(ctx, connect, instance_id):
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
    claim_id = connect.claim_phone_number(
        TargetArn=instance_arn, PhoneNumber=phone_number, Tags={"simparity-audit": CHECK}
    )["PhoneNumberId"]
    ctx.on_cleanup(lambda: _safe(lambda: connect.release_phone_number(PhoneNumberId=claim_id)))
    return phone_number


def _create_campaign(ctx, instance_id, contact_flow_id, source_number, dialer_config=None, name=None):
    cc = ctx.client("connectcampaigns")
    dialer_config = dialer_config or {"agentlessDialerConfig": {"dialingCapacity": 1.0}}
    resp = cc.create_campaign(
        name=name or ctx.unique_name("sim2real-camp-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config,
        outboundCallConfig={
            "connectContactFlowId": contact_flow_id,
            "connectSourcePhoneNumber": source_number,
        },
        tags={"simparity-audit": CHECK},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: _safe(lambda: cc.delete_campaign(id=campaign_id)))
    return campaign_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
