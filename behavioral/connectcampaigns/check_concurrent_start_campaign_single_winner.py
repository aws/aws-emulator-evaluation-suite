"""concurrent-start-campaign-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-start-campaign-single-winner"
GROUP = "concurrency"
SERVICES = ["connectcampaigns"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartCampaign never rejects a repeat call: concurrent racers on an Initialized campaign and a
    later sequential call all succeed, and the campaign converges to and holds Running."""
    cc = ctx.client("connectcampaigns")
    instance_id = _create_onboarded_instance(ctx)
    flow_id = _pick_contact_flow_id(ctx, instance_id)
    queue_id = _create_queue(ctx, instance_id)
    campaign_id = _create_campaign(ctx, instance_id, flow_id, queue_id)

    racer_count = 8

    def _racer(_i):
        try:
            cc.start_campaign(id=campaign_id)
            return ("ok", None)
        except Exception as err:
            return ("error", _code_of(err))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    failures = [r for r in results if r[0] == "error"]
    assert not failures, f"StartCampaign rejected a racer instead of the idempotent success real AWS gives every one: {results}"

    final_state = _poll_until(
        lambda: _get_state(cc, campaign_id), lambda s: s == "Running", timeout_s=60.0, interval_s=3.0
    )
    assert final_state == "Running", f"expected the campaign to converge on Running, got {final_state!r}"

    # freeze detector: N consecutive independent reads must agree -- the burst of racers must not
    # leave the state machine oscillating or self-correcting away from Running after the fact.
    for _ in range(3):
        time.sleep(2.0)
        held = _get_state(cc, campaign_id)
        assert held == "Running", f"state drifted off Running after settling: {held!r}"

    # a further Start against the already-settled campaign must stay idempotent too, not become
    # a state-machine trap once the race is long over.
    status, code = _racer(999)
    assert status == "ok", f"expected a post-settle StartCampaign to remain idempotent, got error {code!r}"
    assert _get_state(cc, campaign_id) == "Running", "a post-settle StartCampaign must not disturb the state"


# ===== helpers =====
def _get_state(cc, campaign_id):
    return cc.get_campaign_state(id=campaign_id)["state"]


def _code_of(err):
    from botocore.exceptions import ClientError

    if isinstance(err, ClientError):
        return err.response["Error"]["Code"]
    return None


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
        Tags={"sim2real-check": CHECK},
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
        Name=ctx.unique_name("sim2realcc-flow-"),
        Type="CONTACT_FLOW",
        Content=_FLOW_CONTENT,
        Tags={"sim2real-check": CHECK},
    )["ContactFlowId"]


_ALL_DAY_HOURS = [
    {"Day": day, "StartTime": {"Hours": 0, "Minutes": 0}, "EndTime": {"Hours": 23, "Minutes": 59}}
    for day in (
        "SUNDAY",
        "MONDAY",
        "TUESDAY",
        "WEDNESDAY",
        "THURSDAY",
        "FRIDAY",
        "SATURDAY",
    )
]


def _create_queue(ctx, instance_id):
    """A campaign's outboundCallConfig requires a real connectQueueId (real AWS rejects
    CreateCampaign with "Missing required parameter ConnectQueueId" for a freshly onboarded
    instance, which starts with none) -- so provision an hours-of-operation and a queue for it."""
    connect = ctx.client("connect")
    hours_id = connect.create_hours_of_operation(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2realcc-hours-"),
        TimeZone="UTC",
        Config=_ALL_DAY_HOURS,
    )["HoursOfOperationId"]
    return connect.create_queue(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2realcc-queue-"),
        HoursOfOperationId=hours_id,
        Tags={"sim2real-check": CHECK},
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
            # measured: CreateCampaign does not verify this number is actually claimed to the
            # instance, so the NANP fictional-use range (555-0100...0199) is safe here.
            "connectSourcePhoneNumber": "+15555550100",
        },
        tags={"sim2real-check": CHECK},
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
