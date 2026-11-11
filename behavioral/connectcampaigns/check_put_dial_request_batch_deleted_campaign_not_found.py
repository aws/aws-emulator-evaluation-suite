"""put-dial-request-batch-deleted-campaign-not-found."""
from __future__ import annotations

import datetime
import json
import time
import uuid

from behavioral_harness import tags

CHECK = "put-dial-request-batch-deleted-campaign-not-found"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]

_LIVE_DIAL_S = 120.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutDialRequestBatch on a deleted campaign fails with ResourceNotFoundException or returns the request
    as its one failed entry, never as successful, while the same request on a live Running campaign is
    accepted."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    cc = ctx.client("connectcampaigns")
    instance_id = _create_onboarded_instance(ctx, teardown_deadline)
    flow_id = _pick_or_create_flow(ctx, instance_id)
    phone_number = _claim_phone_number(ctx, instance_id, teardown_deadline)

    doomed_campaign_id = _create_campaign(ctx, instance_id, flow_id, phone_number, teardown_deadline)
    live_campaign_id = _create_campaign(ctx, instance_id, flow_id, phone_number, teardown_deadline)

    cc.start_campaign(id=live_campaign_id)
    _poll_until(
        lambda: cc.get_campaign_state(id=live_campaign_id)["state"],
        lambda s: s == "Running",
        timeout_s=60.0,
        interval_s=3.0,
    )

    cc.delete_campaign(id=doomed_campaign_id)
    _poll_until(
        lambda: _describe_code(cc, doomed_campaign_id),
        lambda c: c == "ResourceNotFoundException",
        timeout_s=60.0,
        interval_s=2.0,
    )

    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)

    def _dial_request(token):
        return {
            "clientToken": token,
            "phoneNumber": "+12065550100",
            "expirationTime": expiration,
            "attributes": {},
        }

    code, doomed_resp = _call(
        lambda: cc.put_dial_request_batch(
            id=doomed_campaign_id, dialRequests=[_dial_request(str(uuid.uuid4()))]
        )
    )
    if code is not None:
        assert code == "ResourceNotFoundException", f"unexpected code: {code}"
    else:
        # A deleted campaign id is not always rejected up front: some accounts report it as a
        # failed entry in the 200 response. Either shape is accepted; a successful entry is not.
        successful = doomed_resp.get("successfulRequests", [])
        failed = doomed_resp.get("failedRequests", [])
        assert successful == [], f"expected no successful requests against a deleted campaign, got {successful}"
        assert len(failed) == 1, f"expected exactly one failed request, got {doomed_resp}"

    # positive control: the same shape of request against a live campaign succeeds. A campaign
    # freshly reporting state=Running is not always immediately ready to ingest dial requests, so
    # this is a bounded retry on that readiness lag, not a mask for a real rejection. Each attempt
    # carries a fresh client token, so every attempt is a new dial request.
    live_tokens: list[str] = []

    def _dial_live():
        live_tokens.append(str(uuid.uuid4()))
        return cc.put_dial_request_batch(id=live_campaign_id, dialRequests=[_dial_request(live_tokens[-1])])

    resp = _poll_until(
        _dial_live,
        lambda r: live_tokens[-1] in {x["clientToken"] for x in r.get("successfulRequests", [])},
        timeout_s=_LIVE_DIAL_S if ctx.time_left() is None else min(_LIVE_DIAL_S, ctx.time_left() - 10.0),
        interval_s=2.0,
    )
    successful_tokens = {r["clientToken"] for r in resp.get("successfulRequests", [])}
    assert live_tokens[-1] in successful_tokens, resp


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


_CALL_SUCCEEDED = "<call succeeded>"


def _describe_code(cc, campaign_id):
    """For polling: DescribeCampaign's error code, or _CALL_SUCCEEDED (no code equals it) on success."""
    from botocore.exceptions import ClientError

    try:
        cc.describe_campaign(id=campaign_id)
        return _CALL_SUCCEEDED
    except ClientError as err:
        return err.response["Error"]["Code"]


def _call(fn):
    from botocore.exceptions import ClientError

    try:
        return None, fn()
    except ClientError as err:
        return err.response["Error"]["Code"], None


# Only a failed onboarding job can be deleted; any other job goes with the instance.
_JOB_NOT_DELETABLE = ("InvalidStateException",)


# budget.cleanup_timeout for behavioral/connectcampaigns, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _teardown(fn, teardown_deadline, done=(), busy=()):
    """Run one teardown call. ResourceNotFoundException or a code in `done` means nothing is left to
    delete; a code in `busy` (a dependency still being released) is retried every 2 s to the shared
    cleanup deadline; anything else raises."""
    from botocore.exceptions import ClientError

    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
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


def _create_onboarded_instance(ctx, teardown_deadline):
    connect = ctx.client("connect")
    cc = ctx.client("connectcampaigns")
    alias = ctx.unique_name("s2rcc-")
    resp = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real:managed": "true"},
    )
    instance_id = resp["Id"]
    ctx.on_cleanup(lambda: _teardown(lambda: connect.delete_instance(InstanceId=instance_id), teardown_deadline))
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
            teardown_deadline,
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
        raise AssertionError(f"instance onboarding job ended in {status}, expected SUCCEEDED")
    return instance_id


def _pick_or_create_flow(ctx, instance_id):
    connect = ctx.client("connect")
    return connect.create_contact_flow(
        InstanceId=instance_id,
        Name=ctx.unique_name("s2rcc-flow-"),
        Type="CONTACT_FLOW",
        Content=_FLOW_CONTENT,
        Status="PUBLISHED",
        Tags={"sim2real:managed": "true"},
    )["ContactFlowId"]


def _claim_phone_number(ctx, instance_id, teardown_deadline):
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
    claim_id = connect.claim_phone_number(TargetArn=instance_arn, PhoneNumber=phone_number)["PhoneNumberId"]
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: connect.release_phone_number(PhoneNumberId=claim_id),
            teardown_deadline,
            busy=("ResourceInUseException",),
        )
    )
    return phone_number


def _pick_queue(ctx, instance_id):
    connect = ctx.client("connect")
    resp = connect.list_queues(InstanceId=instance_id, QueueTypes=["STANDARD"])
    queues = resp["QueueSummaryList"]
    if not queues:
        raise AssertionError(f"instance {instance_id} has no STANDARD queue to attach the campaign to")
    return queues[0]["Id"]


def _create_campaign(ctx, instance_id, contact_flow_id, phone_number, teardown_deadline, dialer_config=None, name=None):
    cc = ctx.client("connectcampaigns")
    dialer_config = dialer_config or {"agentlessDialerConfig": {"dialingCapacity": 1.0}}
    queue_id = _pick_queue(ctx, instance_id)
    resp = cc.create_campaign(
        name=name or ctx.unique_name("sim2real-camp-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config,
        outboundCallConfig={
            "connectContactFlowId": contact_flow_id,
            "connectQueueId": queue_id,
            "connectSourcePhoneNumber": phone_number,
        },
        tags={"sim2real:managed": "true"},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: _teardown(lambda: cc.delete_campaign(id=campaign_id), teardown_deadline))
    return campaign_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
