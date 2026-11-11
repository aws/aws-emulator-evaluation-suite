"""at-deployment-tick-directive-rollback-reverts-the-deployment."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "at-deployment-tick-directive-rollback-reverts-the-deployment"
GROUP = 'extension'
SERVICES = ['appconfig', 'lambda']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-deployment-tick"}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
# AWS attributes a rollback requested by an extension's ROLL_BACK directive to "EXTENSION".
_TICK_TRIGGERED_BY = "EXTENSION"
# A 0-minute deployment invokes no action point at all, so the strategy must not be instant.
_DEPLOY_MINUTES = 2
_TICK_BUDGET_S = 900
_DEPLOY_TIMEOUT_S = 300

# Forwards each tick event to SQS (the only way to observe it) and returns the Directive named by
# an environment variable the check flips between deployments.
_TICK_SRC = '''
import json, os, boto3

_SQS = boto3.client("sqs")


def handler(event, context):
    _SQS.send_message(QueueUrl=os.environ["QUEUE_URL"],
                      MessageBody=json.dumps(event, default=str))
    return {"Directive": os.environ["DIRECTIVE"], "Description": os.environ["REASON"]}
'''


def _error_code(fn):
    """Return (code, message) of the ClientError fn() raises; fail if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        "the call under test SUCCEEDED where real AWS refuses it — this is an "
        "over-permissiveness failure, not an error-code mismatch"
    )


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
        # Account-level deletion protection can be enabled, so bypass it explicitly.
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


def _zip_handler(src: str) -> bytes:
    """Build a one-file deployment package in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handler.py", src)
    return buf.getvalue()


def _make_role(ctx, iam, trusted_service, statements):
    """Create a role trusted by one AWS service with one inline policy, registering cleanup."""
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": trusted_service},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=_TAGLIST,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return arn


def _create_function(lam, name, role_arn, src, env_vars, timeout_s=180):
    """Create a Lambda, retrying InvalidParameterValueException until the new role has propagated."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": _zip_handler(src)},
                Environment={"Variables": env_vars},
                Timeout=20,
                Tags=_TAGS,
            )["FunctionArn"]
        except ClientError as exc:
            last = exc.response.get("Error", {})
            if last.get("Code") != "InvalidParameterValueException":
                raise
            time.sleep(5.0)
    raise AssertionError(f"Lambda {name} never became creatable within {timeout_s}s: {last!r}")


def _set_directive(lam, fn_name, directive, reason, queue_url):
    """Flip the target's Directive and wait until it is in force.

    Without the wait the next deployment can race the update and be ticked by the old directive.
    """
    lam.update_function_configuration(
        FunctionName=fn_name,
        Environment={
            "Variables": {"QUEUE_URL": queue_url, "DIRECTIVE": directive, "REASON": reason}
        },
    )
    lam.get_waiter("function_updated_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    live = lam.get_function_configuration(FunctionName=fn_name)["Environment"]["Variables"]
    assert live["DIRECTIVE"] == directive and live["REASON"] == reason, (
        f"the target's directive must be in force before the deployment under test; expected "
        f"{directive!r}/{reason!r}, live {live!r}"
    )


def _drain_one(sqs, queue_url, timeout_s=180):
    """Long-poll the observation queue until one message arrives; return its parsed body, or None."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=20, MaxNumberOfMessages=1
        ).get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return json.loads(msgs[0]["Body"])
    return None


def _purge_queue(sqs, queue_url, timeout_s=30):
    """Drain whatever is already in the observation queue so the next leg reads only new ticks."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=1, MaxNumberOfMessages=10
        ).get("Messages", [])
        if not msgs:
            return
        for msg in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _wait_terminal(ac, app_id, env_id, dep_num, timeout_s=_DEPLOY_TIMEOUT_S):
    """Poll GetDeployment until the deployment reaches a terminal state. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        if last.get("State") in _TERMINAL:
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"deployment {dep_num} never reached a terminal state within {timeout_s}s; last state "
        f"{(last or {}).get('State')!r} at {(last or {}).get('PercentageComplete')!r}%"
    )


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=240):
    """Poll fresh configuration sessions until one serves exactly `expect`; return the last payload.

    Each attempt opens a new session because a next-poll token used before NextPollIntervalInSeconds
    is refused.
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


# timing:real-time — schedule: 120 s https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-deployment-strategy.html
@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A ROLL_BACK directive from an AT_DEPLOYMENT_TICK extension rolls the deployment back.

    The deployment ends ROLLED_BACK with this run's reason in its EventLog and the data plane serves
    the previous version, while the identical deployment ticked with CONTINUE completes.

    Reference: https://docs.aws.amazon.com/appconfig/latest/userguide/working-with-appconfig-extensions-creating-custom-lambda.html
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    v1_bytes = b'{"tier":"one"}'
    v2_bytes = b'{"tier":"two"}'
    # A run-unique reason proves the EventLog text came from the extension.
    reason = ctx.unique_name("tick-rollback-reason-")
    continue_reason = ctx.unique_name("tick-continue-reason-")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-q-"), tags=_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    exec_role_arn = _make_role(
        ctx,
        iam,
        "lambda.amazonaws.com",
        [
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    )
    fn_name = ctx.unique_name("sim2real-behav-tick-")
    fn_arn = _create_function(
        lam,
        fn_name,
        exec_role_arn,
        _TICK_SRC,
        {"QUEUE_URL": queue_url, "DIRECTIVE": "CONTINUE", "REASON": continue_reason},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    # The log group appears on first invocation; cleanup tolerates it not existing.
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    )
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="appconfig-invoke",
        Action="lambda:InvokeFunction",
        Principal="appconfig.amazonaws.com",
        SourceAccount=account,
    )
    invoke_role_arn = _make_role(
        ctx,
        iam,
        "appconfig.amazonaws.com",
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}],
    )

    extension = ac.create_extension(
        Name=ctx.unique_name("sim2real-behav-ext-"),
        Actions={
            "AT_DEPLOYMENT_TICK": [
                {"Name": "steer", "Uri": fn_arn, "RoleArn": invoke_role_arn}
            ]
        },
        Tags=_TAGS,
    )
    ext_id = extension["Id"]
    ctx.on_cleanup(lambda: ac.delete_extension(ExtensionIdentifier=ext_id))
    assert extension["Actions"]["AT_DEPLOYMENT_TICK"][0]["Uri"] == fn_arn, (
        f"the action's target URI must round-trip on the extension; got {extension['Actions']!r}"
    )

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
    v1 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=v1_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    v2 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=v2_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    assert (v1, v2) == (1, 2), f"hosted version numbering: got {v1!r}, {v2!r}"

    env_arn = f"arn:aws:appconfig:{ctx.region}:{account}:application/{app_id}/environment/{env_id}"
    association = ac.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=env_arn, Tags=_TAGS
    )
    assoc_id = association["Id"]
    ctx.on_cleanup(lambda: ac.delete_extension_association(ExtensionAssociationId=assoc_id))
    assert association["ResourceArn"] == env_arn, (
        f"the association must bind to the environment ARN it was given; got "
        f"{association['ResourceArn']!r}"
    )

    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=_DEPLOY_MINUTES,
        GrowthFactor=25,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))

    # Control: CONTINUE completes. Retried while AppConfig cannot yet assume the new invoke role,
    # which would otherwise also produce a non-COMPLETE outcome.
    baseline = None
    attempts = 0
    deadline = time.monotonic() + _TICK_BUDGET_S / 2
    while time.monotonic() < deadline:
        attempts += 1
        _purge_queue(sqs, queue_url)
        dep = ac.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=str(v1),
            Tags=_TAGS,
        )["DeploymentNumber"]
        settled = _wait_terminal(ac, app_id, env_id, dep)
        if settled["State"] == "COMPLETE":
            baseline = settled
            break
        time.sleep(2.0)
    assert baseline is not None, (
        f"no CONTINUE-directive deployment reached COMPLETE in {attempts!r} attempts, so AppConfig "
        f"could not invoke the tick target at all; without that control a later ROLLED_BACK would "
        f"be unattributable to the directive"
    )
    tick_event = _drain_one(sqs, queue_url)
    assert tick_event is not None, (
        "the AT_DEPLOYMENT_TICK action point never invoked the Lambda — nothing reached the "
        "observation queue, so no tick was routed through the extension"
    )
    assert tick_event["DeploymentNumber"] == baseline["DeploymentNumber"], (
        f"the tick event must name the deployment it is ticking; event says "
        f"{tick_event.get('DeploymentNumber')!r}, deployment is "
        f"{baseline['DeploymentNumber']!r}"
    )
    assert tick_event["Environment"]["Id"] == env_id, (
        f"the tick event must name the environment under deployment; got "
        f"{tick_event.get('Environment')!r}"
    )
    assert "PercentageComplete" in tick_event, (
        f"an AT_DEPLOYMENT_TICK event must report the rollout position it is asking about; keys "
        f"were {sorted(tick_event)!r}"
    )
    served_v1 = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
    assert served_v1 == v1_bytes, (
        f"version 1 must be in service before the rollback under test; got {served_v1!r}"
    )

    # The tick now answers ROLL_BACK.
    _purge_queue(sqs, queue_url)
    _set_directive(lam, fn_name, "ROLL_BACK", reason, queue_url)

    dep2 = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(v2),
        Tags=_TAGS,
    )["DeploymentNumber"]
    final = _wait_terminal(ac, app_id, env_id, dep2)

    assert final["State"] == "ROLLED_BACK", (
        f"a deployment whose AT_DEPLOYMENT_TICK action answered Directive=ROLL_BACK must terminate "
        f"ROLLED_BACK, got {final['State']!r} — COMPLETE means the target ignored the response "
        f"body, which is exactly what a notification-only extension model does"
    )
    kinds = [e.get("EventType") for e in final.get("EventLog", [])]
    assert "ROLLBACK_STARTED" in kinds and "ROLLBACK_COMPLETED" in kinds, (
        f"the EventLog must record both ROLLBACK_STARTED and ROLLBACK_COMPLETED; got {kinds!r}"
    )
    assert "DEPLOYMENT_COMPLETED" not in kinds, (
        f"a rolled-back deployment must not also log DEPLOYMENT_COMPLETED; got {kinds!r}"
    )
    descriptions = [e.get("Description") or "" for e in final.get("EventLog", [])]
    assert any(reason in d for d in descriptions), (
        f"the Description the tick action returned ({reason!r}) must appear in the deployment's "
        f"EventLog — the docs call it the 'Deployment event log description'; the log said "
        f"{descriptions!r}"
    )
    assert continue_reason not in " ".join(descriptions), (
        f"the EventLog carries the CONTINUE leg's reason {continue_reason!r}, so the target is "
        f"replaying a stale directive rather than the one in force"
    )
    rollbacks = [
        e for e in final.get("EventLog", []) if e.get("EventType") == "ROLLBACK_STARTED"
    ]
    assert rollbacks, f"ROLLBACK_STARTED must be present as an entry, not just a kind: {kinds!r}"
    for event in rollbacks:
        assert event["TriggeredBy"] == _TICK_TRIGGERED_BY, (
            f"an AT_DEPLOYMENT_TICK extension's ROLL_BACK directive must attribute the rollback to "
            f"{_TICK_TRIGGERED_BY!r} (measured on real AWS); got {event['TriggeredBy']!r} — nobody "
            f"called StopDeployment, so the extension asked for this rollback, not the caller"
        )

    restored = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
    assert restored == v1_bytes, (
        f"after the directive-driven rollback the data plane must serve version 1's exact bytes "
        f"again; got {restored!r}"
    )
    assert restored != v2_bytes, (
        "the data plane is still serving the rolled-back version, so the rollback changed only the "
        "deployment record and not what clients receive"
    )
    confirm = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
    assert confirm == v1_bytes, (
        f"the restoration must be settled, not a transient: a second fresh session was served "
        f"{confirm!r}"
    )
    code, message = _error_code(
        lambda: ac.stop_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep2
        )
    )
    assert code == "BadRequestException", (
        f"a rolled-back deployment is terminal, so StopDeployment on it must answer "
        f"BadRequestException; got {code!r}"
    )
    assert message == f"Deployment {dep2} for App {baseline['ApplicationId']} and Environment {baseline['EnvironmentId']} cannot be stopped, it has a status of {final['State']}.", (
        f"expected the exact BadRequestException message AWS returns, got {message!r}"
    )

    # With CONTINUE restored, the identical deployment completes.
    _purge_queue(sqs, queue_url)
    _set_directive(lam, fn_name, "CONTINUE", continue_reason, queue_url)
    dep3 = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(v2),
        Tags=_TAGS,
    )["DeploymentNumber"]
    reinstated = _wait_terminal(ac, app_id, env_id, dep3)
    assert reinstated["State"] == "COMPLETE", (
        f"with the directive back to CONTINUE the IDENTICAL deployment of version 2 must COMPLETE; "
        f"got {reinstated['State']!r} — if it rolls back again the rollback was not the directive"
    )
    served_v2 = _serve_until(acd, app_id, env_id, cp_id, expect=v2_bytes)
    assert served_v2 == v2_bytes, (
        f"the reinstated deployment must reach the data plane: expected version 2's exact bytes, "
        f"served {served_v2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
