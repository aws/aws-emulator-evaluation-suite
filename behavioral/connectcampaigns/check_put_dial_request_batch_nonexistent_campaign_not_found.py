"""put-dial-request-batch-nonexistent-campaign-not-found."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dial-request-batch-nonexistent-campaign-not-found"
GROUP = "error-semantics"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutDialRequestBatch for a never-created campaign id raises ResourceNotFoundException or
    reports it as the only failed entry, while the identical call against a real campaign is not
    refused as not-found, so the rejection is specific to the unknown id."""
    instance_id, flow_id = _create_onboarded_instance(ctx)
    campaign_id, _arn = _create_campaign(ctx, instance_id, flow_id)
    campaigns = ctx.client("connectcampaigns")

    state = campaigns.get_campaign_state(id=campaign_id)["state"]
    assert state == "Initialized", f"expected a freshly created campaign to be Initialized, got {state!r}"

    control_code, control_message, _resp = _call(
        lambda: campaigns.put_dial_request_batch(id=campaign_id, dialRequests=[_dial_request(ctx)])
    )
    assert control_code != "ResourceNotFoundException", (
        f"expected a real campaign id to be resolved by PutDialRequestBatch (not rejected as "
        f"not-found, the code under test), got code={control_code!r} message={control_message!r}"
    )

    bogus_campaign_id = ctx.unique_name("nonexistent-campaign-")
    code, message, resp = _call(
        lambda: campaigns.put_dial_request_batch(
            id=bogus_campaign_id, dialRequests=[_dial_request(ctx)]
        )
    )
    if code is not None:
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException, got code={code!r} message={message!r}"
        )
    else:
        # no exception raised -- the nonexistent campaign must show up as a failure in the
        # response body, not be silently treated as a successful dial request.
        successful = resp.get("successfulRequests", [])
        failed = resp.get("failedRequests", [])
        assert successful == [], f"expected no successful requests, got {successful}"
        assert len(failed) == 1, f"expected exactly one failed request, got {failed}"


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


def _dial_request(ctx):
    # +1 202 555 01xx: the NANPA-reserved fictional-use block (a real area code, the
    # 555 exchange conventionally non-assigned) -- syntactically valid, never routed.
    return {
        "clientToken": ctx.unique_name("sim2real-dialtok-"),
        "phoneNumber": "+12025550100",
        "expirationTime": datetime.now(timezone.utc) + timedelta(hours=1),
        "attributes": {"customerId": "12345"},
    }


def _call(fn):
    try:
        resp = fn()
        return None, None, resp
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message"), None


def _create_onboarded_instance(ctx):
    connect = ctx.client("connect")
    cc = ctx.client("connectcampaigns")

    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-cc-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
    )["Id"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))
    _tag(ctx, lambda tags_: connect.tag_resource(resourceArn=_instance_arn(connect, instance_id), tags=tags_))

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


def _instance_arn(connect, instance_id):
    return connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]


def _tag(ctx, apply):
    try:
        apply({"sim2real-check": CHECK})
    except ClientError:
        pass


def _safe_delete_instance_config(ctx, instance_id):
    cc = ctx.client("connectcampaigns")
    _teardown(
        lambda: cc.delete_connect_instance_config(connectInstanceId=instance_id),
        busy=_CAMPAIGNS_LEFT,
    )
    _teardown(
        lambda: cc.delete_instance_onboarding_job(connectInstanceId=instance_id),
        done=_JOB_NOT_DELETABLE,
    )


def _create_campaign(ctx, instance_id, flow_id, dialer_config=None, name=None):
    cc = ctx.client("connectcampaigns")
    resp = cc.create_campaign(
        name=name or ctx.unique_name("sim2real-campaign-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config or {"agentlessDialerConfig": {"dialingCapacity": 1.0}},
        outboundCallConfig={
            "connectContactFlowId": flow_id,
            # CreateCampaign requires a source caller ID but does not verify it is claimed to
            # the instance, so the NANPA fictional-use placeholder avoids claiming a real number.
            "connectSourcePhoneNumber": "+12025550100",
        },
        tags={"sim2real-check": CHECK},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_campaign(ctx, campaign_id))
    return campaign_id, resp["arn"]


def _safe_delete_campaign(ctx, campaign_id):
    cc = ctx.client("connectcampaigns")
    _teardown(lambda: cc.delete_campaign(id=campaign_id))


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
