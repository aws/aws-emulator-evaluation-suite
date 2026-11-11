"""deployment-events-to-sqs-extension-delivers-lifecycle-messages."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-events-to-sqs-extension-delivers-lifecycle-messages"
GROUP = 'extension'
SERVICES = ['appconfig', 'sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-sqs-notifications"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_EXPECTED_ACTION_POINTS = {
    "ON_DEPLOYMENT_START",
    "ON_DEPLOYMENT_COMPLETE",
    "ON_DEPLOYMENT_ROLLED_BACK",
}
# A deployment with zero duration and bake time invokes no action point.
_DEPLOY_MINUTES = 1
# Absence is held for this multiple of the delivery latency measured in the same run.
_ABSENCE_MULTIPLIER = 3
_NOTIFICATION_BUDGET_S = 900
_DEPLOY_TIMEOUT_S = 300


# DeletionProtection may be enabled account-wide, so teardown passes
# DeletionProtectionCheck="BYPASS" explicitly.


def _ignore_not_found(fn):
    """Run a teardown whose target may already be gone; any other failure still raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items."""
    return [item for page in pages for item in page.get("Items", [])]


def _purge_application(ac, app_id, timeout_s=300):
    """Delete an application and everything beneath it, bottom-up. Raises rather than leaking."""
    try:
        environments = _purge_items(
            ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    for env in environments:
        env_id = env["Id"]
        deadline = time.monotonic() + timeout_s
        for dep in _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id, EnvironmentId=env_id
            )
        ):
            if dep.get("State") in _TERMINAL:
                continue
            try:
                ac.stop_deployment(
                    ApplicationId=app_id,
                    EnvironmentId=env_id,
                    DeploymentNumber=dep["DeploymentNumber"],
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in (
                    "BadRequestException",
                    "ResourceNotFoundException",
                ):
                    raise
        state = None
        while time.monotonic() < deadline:
            state = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id).get("State")
            if state not in _ENV_TRANSITIONAL:
                break
            time.sleep(2.0)
        else:
            raise AssertionError(f"environment {env_id} never left {state!r} during cleanup")
    for profile in _purge_items(
        ac.get_paginator("list_configuration_profiles").paginate(ApplicationId=app_id)
    ):
        cp_id = profile["Id"]
        for version in _purge_items(
            ac.get_paginator("list_hosted_configuration_versions").paginate(
                ApplicationId=app_id, ConfigurationProfileId=cp_id
            )
        ):
            ac.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
                VersionNumber=version["VersionNumber"],
            )
        ac.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            DeletionProtectionCheck="BYPASS",
        )
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeletionProtectionCheck="BYPASS"
        )
    ac.delete_application(ApplicationId=app_id)


def _find_aws_authored_sqs_extension(ac):
    """Discover the AWS-authored SQS notification extension rather than hardcoding its name.

    AWS-authored extension ARNs have an empty account field; exactly one may mention SQS.
    """
    everything = _purge_items(ac.get_paginator("list_extensions").paginate())
    aws_authored = [
        e for e in everything if ":extension/" in e.get("Arn", "") and "::extension/" in e["Arn"]
    ]
    assert aws_authored, (
        f"no AWS-authored extension is visible to this account; ListExtensions returned "
        f"{[e.get('Name') for e in everything]!r}"
    )
    matches = [e for e in aws_authored if "sqs" in e.get("Name", "").lower()]
    assert len(matches) == 1, (
        f"exactly one AWS-authored extension must mention SQS; matched "
        f"{[e.get('Name') for e in matches]!r} out of AWS-authored "
        f"{[e.get('Name') for e in aws_authored]!r}"
    )
    return matches[0]


def _drain(sqs, queue_url, want, timeout_s=240):
    """Long-poll until `want` messages are collected or the deadline passes; return what arrived."""
    collected = []
    deadline = time.monotonic() + timeout_s
    while len(collected) < want and time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=20, MaxNumberOfMessages=10
        ).get("Messages", [])
        for msg in msgs:
            collected.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return collected


def _purge_queue(sqs, queue_url, timeout_s=30):
    """Drain whatever is already queued so a later leg reads only new messages."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=1, MaxNumberOfMessages=10
        ).get("Messages", [])
        if not msgs:
            return
        for msg in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version,
                              timeout_s=_DEPLOY_TIMEOUT_S):
    """Start a deployment and poll until COMPLETE. Deliberately NOT tolerant of ROLLED_BACK."""
    dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
        Tags=_TAGS,
    )["DeploymentNumber"]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        if last.get("State") in _TERMINAL:
            break
        time.sleep(3.0)
    assert last is not None and last.get("State") == "COMPLETE", (
        f"deployment {dep_num} of version {version} did not reach COMPLETE within {timeout_s}s; "
        f"last state {(last or {}).get('State')!r}"
    )
    return dep_num


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=240):
    """Poll fresh configuration sessions until one serves exactly `expect`; return the last payload.

    A next-poll token used too early is refused, so each attempt opens a new session.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        token = acd.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=cp_id,
        )["InitialConfigurationToken"]
        body = acd.get_latest_configuration(ConfigurationToken=token)["Configuration"].read()
        if body == expect or time.monotonic() >= deadline:
            return body
        time.sleep(3.0)


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-deployment-strategy.html
@tags("axis:negative-delivery", "cap:c3", "concern:eventing", "dp:api", "plane:control", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Associating the AWS-authored deployment-events-to-SQS extension delivers start and complete
    messages naming the deployment; removing it stops delivery, and re-associating restores it.

    Reference: https://docs.aws.amazon.com/appconfig/latest/userguide/working-with-appconfig-extensions-about-predefined-notification-sqs.html
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    v1_bytes = b'{"tier":"one"}'
    v2_bytes = b'{"tier":"two"}'
    v3_bytes = b'{"tier":"three"}'

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-q-"), tags=_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowAppConfigSendMessage",
                            "Effect": "Allow",
                            "Principal": {"Service": "appconfig.amazonaws.com"},
                            "Action": "SQS:SendMessage",
                            "Resource": queue_arn,
                            # The docs are explicit that omitting this condition lets another
                            # account point its extension at this queue.
                            "Condition": {"StringEquals": {"aws:SourceAccount": account}},
                        }
                    ],
                }
            )
        },
    )

    # --- Discover the AWS-authored extension, and hold its documented contract.
    summary = _find_aws_authored_sqs_extension(ac)
    ext_arn = summary["Arn"]
    extension = ac.get_extension(ExtensionIdentifier=ext_arn)
    action_points = set(extension["Actions"])
    assert action_points == _EXPECTED_ACTION_POINTS, (
        f"the AWS-authored SQS notification extension is documented as invoked by exactly "
        f"{sorted(_EXPECTED_ACTION_POINTS)} and as NOT customizable; this account's copy declares "
        f"{sorted(action_points)}"
    )
    parameter_names = sorted(extension.get("Parameters", {}))

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]
    versions = [
        ac.create_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            Content=payload,
            ContentType="application/json",
        )["VersionNumber"]
        for payload in (v1_bytes, v2_bytes, v3_bytes)
    ]
    assert versions == [1, 2, 3], f"hosted version numbering: got {versions!r}"
    v1, v2, v3 = versions
    env_arn = f"arn:aws:appconfig:{ctx.region}:{account}:application/{app_id}/environment/{env_id}"
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=_DEPLOY_MINUTES,
        GrowthFactor=100,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))

    def _associate():
        created = ac.create_extension_association(
            ExtensionIdentifier=ext_arn,
            ResourceIdentifier=env_arn,
            # The documented sample message names the queue parameter queueArn.
            Parameters={"queueArn": queue_arn},
            Tags=_TAGS,
        )
        assert created["ResourceArn"] == env_arn, (
            f"the association must bind to the environment ARN it was given; got "
            f"{created['ResourceArn']!r}. The extension declares parameters "
            f"{parameter_names!r} — if the queueArn parameter name was refused, that list is where "
            f"the real name is."
        )
        return created["Id"]

    assoc_id = _associate()
    # The check deletes this association itself; the teardown covers a run that stops earlier.
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: ac.delete_extension_association(ExtensionAssociationId=assoc_id)
        )
    )
    bound = ac.get_extension_association(ExtensionAssociationId=assoc_id)
    assert bound["Parameters"]["queueArn"] == queue_arn, (
        f"the association must carry the queue ARN it was given; got {bound.get('Parameters')!r}"
    )

    # --- Positive leg: read delivery at the consumer; its latency sizes the absence window.
    _purge_queue(sqs, queue_url)
    started_at = time.monotonic()
    dep1 = _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, v1)
    messages = _drain(sqs, queue_url, want=2)
    latency_s = time.monotonic() - started_at
    assert len(messages) == 2, (
        f"a completed deployment must enqueue a start message AND a complete message; got "
        f"{len(messages)}: {[m.get('Type') for m in messages]!r}"
    )
    types = {m["Type"] for m in messages}
    assert types == {"OnDeploymentStart", "OnDeploymentComplete"}, (
        f"the two messages must be the start and complete notifications, PascalCase — NOT the "
        f"SCREAMING_SNAKE action-point keys; got {sorted(types)!r}"
    )
    for message in messages:
        # The documented sample payload shows these as strings, so compare after str().
        assert str(message["DeploymentNumber"]) == str(dep1), (
            f"every notification must name the deployment it describes ({dep1}); got "
            f"{message.get('DeploymentNumber')!r} on the {message.get('Type')!r} message"
        )
        assert str(message["ConfigurationVersion"]) == str(v1), (
            f"every notification must name the configuration version deployed ({v1}); got "
            f"{message.get('ConfigurationVersion')!r} on the {message.get('Type')!r} message"
        )
        assert message["Application"]["Id"] == app_id, (
            f"the notification must name the application; got {message.get('Application')!r}"
        )
        assert message["Environment"]["Id"] == env_id, (
            f"the notification must name the environment the association was bound to; got "
            f"{message.get('Environment')!r}"
        )
        assert message["ConfigurationProfile"]["Id"] == cp_id, (
            f"the notification must name the configuration profile; got "
            f"{message.get('ConfigurationProfile')!r}"
        )
        assert message["Parameters"]["queueArn"] == queue_arn, (
            f"the notification must echo the association parameter that routed it; got "
            f"{message.get('Parameters')!r}"
        )
    served_v1 = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
    assert served_v1 == v1_bytes, (
        f"the deployment that produced these notifications must also have reached the data plane; "
        f"served {served_v1!r}"
    )

    # --- Negative leg: remove the association and NOTHING must arrive.
    ac.delete_extension_association(ExtensionAssociationId=assoc_id)
    gone = gone_message = None
    try:
        ac.get_extension_association(ExtensionAssociationId=assoc_id)
    except ClientError as exc:
        gone = exc.response.get("Error", {}).get("Code")
        gone_message = exc.response.get("Error", {}).get("Message")
    assert gone == "ResourceNotFoundException", (
        f"the deleted association must be gone by an independent read; GetExtensionAssociation "
        f"answered {gone!r}"
    )
    expected_message = f"ExtensionAssociation could not be found for account {account}."
    assert gone_message == expected_message, (
        f"expected message {expected_message!r}, got {gone_message!r}"
    )
    _purge_queue(sqs, queue_url)
    dep2 = _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, v2)
    # The deployment REALLY happened — asserted at the data plane — so an empty queue cannot be
    # explained by "nothing was deployed".
    served_v2 = _serve_until(acd, app_id, env_id, cp_id, expect=v2_bytes)
    assert served_v2 == v2_bytes, (
        f"the un-notified deployment {dep2} must still have deployed, or the absence below proves "
        f"nothing; served {served_v2!r}"
    )
    absence_window_s = _ABSENCE_MULTIPLIER * latency_s
    withheld = _drain(sqs, queue_url, want=1, timeout_s=absence_window_s)
    assert withheld == [], (
        f"with the association deleted, a completed deployment must enqueue NOTHING; after "
        f"{absence_window_s:.0f}s (3x the {latency_s:.0f}s delivery latency measured on this same "
        f"wiring) the queue held {[m.get('Type') for m in withheld]!r}"
    )
    depth = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert depth == "0", (
        f"the second independent observable must agree that nothing was delivered: "
        f"ApproximateNumberOfMessages is {depth!r}"
    )

    # --- Restore: re-associate and delivery must come back, so a target with no delivery
    #     path at all cannot pass the absence leg above.
    restored_id = _associate()
    ctx.on_cleanup(lambda: ac.delete_extension_association(ExtensionAssociationId=restored_id))
    _purge_queue(sqs, queue_url)
    dep3 = _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, v3)
    reinstated = _drain(sqs, queue_url, want=2)
    assert len(reinstated) == 2, (
        f"with the association restored the notifications must come back; got {len(reinstated)}: "
        f"{[m.get('Type') for m in reinstated]!r} — if this is empty the absence asserted above was "
        f"a broken delivery path, not a withheld one"
    )
    assert {m["Type"] for m in reinstated} == {"OnDeploymentStart", "OnDeploymentComplete"}, (
        f"the restored notifications must be the same two types; got "
        f"{sorted(m.get('Type') for m in reinstated)!r}"
    )
    assert {str(m["DeploymentNumber"]) for m in reinstated} == {str(dep3)}, (
        f"the restored notifications must describe the NEW deployment {dep3}, not a replay of an "
        f"earlier one; got {[m.get('DeploymentNumber') for m in reinstated]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
