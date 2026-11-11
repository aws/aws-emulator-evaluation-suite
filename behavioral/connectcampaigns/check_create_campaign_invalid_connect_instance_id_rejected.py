"""create-campaign-invalid-connect-instance-id-rejected."""
from __future__ import annotations
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-campaign-invalid-connect-instance-id-rejected"
GROUP = "error-semantics"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCampaign rejects a UUID-shaped connectInstanceId not onboarded for Campaigns with
    ValidationException and creates nothing, while the identical request succeeds against an
    onboarded instance (control)."""
    cc = ctx.client("connectcampaigns")
    instance_id = _create_onboarded_instance(ctx)
    call_config = _provision_outbound_call_config(ctx, instance_id)
    dialer_config = {"agentlessDialerConfig": {"dialingCapacity": 1.0}}

    # positive control: the exact same dialer/outbound call config succeeds against the real,
    # onboarded instance -- without this, "rejects an un-onboarded instance id" is
    # indistinguishable from "rejects every CreateCampaign call".
    control_campaign_id = _create_campaign(ctx, instance_id, call_config, dialer_config)
    described = cc.describe_campaign(id=control_campaign_id)["campaign"]
    assert described["connectInstanceId"] == instance_id, described

    # a real Connect instance id is a UUID; a UUID-shaped-but-unonboarded id exercises the
    # "not onboarded" validation path, distinct from a malformed-pattern rejection. Every other
    # field is held identical to the positive control above -- only connectInstanceId is broken.
    fake_instance_id = str(uuid.uuid4())
    bad_name = ctx.unique_name("sim2real-campaign-")

    def _create():
        cc.create_campaign(
            name=bad_name,
            connectInstanceId=fake_instance_id,
            dialerConfig=dialer_config,
            outboundCallConfig=call_config,
        )

    code, message = _error_code_and_message(_create)
    assert code == "ValidationException", f"{code}: {message}"
    assert message == "Connect Instance does not exist or is not enabled to use Campaigns.", message

    # effect absent: no campaign with the rejected name shows up anywhere listable
    found = [c for page in _paginate_list_campaigns(cc) for c in page if c["name"] == bad_name]
    assert found == [], f"a campaign was created despite the rejected request: {found}"

    # consistent behavior: filtering ListCampaigns by the same un-onboarded instance id also
    # rejects with ValidationException rather than silently returning an empty list.
    list_code, list_message = _error_code_and_message(
        lambda: cc.list_campaigns(
            filters={"instanceIdFilter": {"value": fake_instance_id, "operator": "Eq"}}
        )
    )
    assert list_code == "ValidationException", f"{list_code}: {list_message}"
    assert list_message == _NOT_ONBOARDED, list_message


#: ListCampaigns' refusal for an instance id with no onboarding job: a property of the id this
#: check sends, not of the account.
_NOT_ONBOARDED = "Instance is not onboarded"

# ===== helpers =====
def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


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


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
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
    resp = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2realcc-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"env": "sim2real"},
    )
    instance_id = resp["Id"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))
    _poll_until(
        lambda: connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=600.0,
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


def _provision_outbound_call_config(ctx, instance_id):
    connect = ctx.client("connect")
    flow_id = connect.create_contact_flow(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2realcc-flow-"),
        Type="CONTACT_FLOW",
        Content=_FLOW_CONTENT,
        Tags={"env": "sim2real"},
    )["ContactFlowId"]

    # CreateCampaign requires a claimed source phone number in outboundCallConfig -- real AWS
    # rejects connectContactFlowId alone with a missing-parameter error.
    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn, PhoneNumberCountryCode="US", PhoneNumberType="DID", MaxResults=5
    )["AvailableNumbersList"]
    assert numbers, "no available phone numbers to claim for the test Connect instance"
    # A listed number can be claimed by another account between search and claim; try the next.
    claim_id = phone_number = None
    for candidate in numbers:
        try:
            claim_id = connect.claim_phone_number(
                TargetArn=instance_arn, PhoneNumber=candidate["PhoneNumber"]
            )["PhoneNumberId"]
        except connect.exceptions.InvalidParameterException:
            continue
        phone_number = candidate["PhoneNumber"]
        break
    assert claim_id, f"none of the available phone numbers could be claimed: {numbers}"
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: connect.release_phone_number(PhoneNumberId=claim_id),
            busy=("ResourceInUseException",),
        )
    )

    return {"connectContactFlowId": flow_id, "connectSourcePhoneNumber": phone_number}


def _create_campaign(ctx, instance_id, call_config, dialer_config, name=None):
    cc = ctx.client("connectcampaigns")
    resp = cc.create_campaign(
        name=name or ctx.unique_name("sim2real-camp-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config,
        outboundCallConfig=call_config,
        tags={"env": "sim2real"},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: _teardown(lambda: cc.delete_campaign(id=campaign_id)))
    return campaign_id


def _paginate_list_campaigns(cc):
    next_token = None
    while True:
        kwargs = {"maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = cc.list_campaigns(**kwargs)
        yield resp.get("campaignSummaryList", [])
        next_token = resp.get("nextToken")
        if not next_token:
            break


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
