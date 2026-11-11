"""get-connect-instance-config-not-onboarded."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-connect-instance-config-not-onboarded"
GROUP = "error-semantics"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetConnectInstanceConfig returns ResourceNotFoundException for an instance id with no
    onboarding record, while the identical call succeeds for an onboarded instance (control)."""
    connect = ctx.client("connect")
    cc = ctx.client("connectcampaigns")

    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-cc-notonb-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"simparity-audit": CHECK},
    )["Id"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))

    _wait_until(
        lambda: connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"],
        "ACTIVE",
        "FAILED",
        "connect instance",
        timeout_s=600.0,
    )

    cc.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: cc.delete_instance_onboarding_job(connectInstanceId=instance_id),
            done=_JOB_NOT_DELETABLE,
        )
    )

    try:
        _wait_until(
            lambda: cc.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
                "connectInstanceOnboardingJobStatus"
            ]["status"],
            "SUCCEEDED",
            "FAILED",
            "onboarding job",
            timeout_s=180.0,
        )
    except AssertionError as e:
        failure_code = _onboarding_failure_code(cc, instance_id)
        raise AssertionError(f"{e} (failureCode={failure_code})") from None

    # positive control: a real, onboarded instance's config is retrievable
    config = cc.get_connect_instance_config(connectInstanceId=instance_id)["connectInstanceConfig"]
    assert config["connectInstanceId"] == instance_id, config
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: cc.delete_connect_instance_config(connectInstanceId=instance_id),
            busy=_CAMPAIGNS_LEFT,
        )
    )

    # the negative: an id with no matching onboarding record is rejected specifically
    never_onboarded_instance_id = str(uuid.uuid4())
    code, message = _error_code_and_message(
        lambda: cc.get_connect_instance_config(connectInstanceId=never_onboarded_instance_id)
    )
    assert code == "ResourceNotFoundException", f"unexpected code: {code}"
    assert message == f"ConnectInstanceConfig not found {never_onboarded_instance_id}.", message


# ===== helpers =====
def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


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


def _wait_until(probe, success_value, failure_value, subject, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last == success_value:
            return last
        if last == failure_value:
            raise AssertionError(f"{subject} reached {failure_value} (expected {success_value})")
        time.sleep(interval_s)
    raise AssertionError(f"{subject} never reached {success_value} within {timeout_s}s (last={last!r})")


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
