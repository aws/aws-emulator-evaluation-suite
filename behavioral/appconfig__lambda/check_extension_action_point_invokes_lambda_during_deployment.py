"""extension-action-point-invokes-lambda-during-deployment."""
from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "extension-action-point-invokes-lambda-during-deployment"
GROUP = 'extension'
SERVICES = ['appconfig', 'lambda']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-extension-action-point"}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
# The sts:AssumeRole propagation retry below can need more than 300s.
_ACTION_POINT_TIMEOUT_S = 600

# The extension's target. It forwards the event AppConfig handed it to an SQS queue — the queue is
# the observation sink, since nothing in the AppConfig API reports the event's contents — and then
# either returns or raises, according to an environment variable the check flips. The invocation's
# request id rides along as a message attribute, because AppConfig quotes it in its refusal message.
_ACTION_SRC = '''
import json, os, boto3

_SQS = boto3.client("sqs")


def handler(event, context):
    _SQS.send_message(QueueUrl=os.environ["QUEUE_URL"],
                      MessageBody=json.dumps(event, default=str),
                      MessageAttributes={"RequestId": {"DataType": "String",
                                                       "StringValue": context.aws_request_id}})
    if os.environ.get("REFUSE") == "1":
        raise Exception("the extension action refuses this deployment")
    return {}
'''

# DeletionProtectionCheck="BYPASS" because account-level deletion protection may be enabled.


def _client_error(fn):
    """Return (Error.Code, Error.Message) from a ClientError; raise if fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        "the call under test SUCCEEDED where real AWS refuses it — this is an "
        "over-permissiveness failure, not an error-code mismatch"
    )


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


def _purge_application(ac, app_id, timeout_s=240):
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
    for env in _purge_items(
        ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
    ):
        ac.delete_environment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeletionProtectionCheck="BYPASS"
        )
    ac.delete_application(ApplicationId=app_id)


def _zip_handler(src: str) -> bytes:
    """Build a one-file deployment package in memory — no host tooling, no temp files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handler.py", src)
    return buf.getvalue()


def _make_role(ctx, iam, trusted_service, statements):
    """Create a role trusted by one AWS service with one inline policy. Registers cleanup for the
    policy and the role immediately after each create, in LIFO order."""
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
    """Create a Lambda, retrying the InvalidParameterValueException a freshly-created execution
    role produces until IAM has propagated. The bounded retry is at FIRST USE of the role."""
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


def _drain_one(sqs, queue_url, timeout_s=180, with_request_id=False):
    """Long-poll the observation queue until one message arrives; return its parsed body.

    With ``with_request_id`` the return is ``(body, lambda_request_id)``; ``(None, None)`` when
    nothing arrives.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=queue_url,
            WaitTimeSeconds=20,
            MaxNumberOfMessages=1,
            MessageAttributeNames=["RequestId"],
        ).get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            body = json.loads(msgs[0]["Body"])
            if with_request_id:
                attr = msgs[0].get("MessageAttributes", {}).get("RequestId", {})
                return body, attr.get("StringValue")
            return body
    return (None, None) if with_request_id else None


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=240):
    """Poll fresh sessions until one is served exactly `expect`; return the last payload seen.

    The data plane lags COMPLETE by seconds; a next-poll token used too early is refused.
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
@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A PRE_START_DEPLOYMENT extension action runs its Lambda with an event naming the app, env,
    action point and base64 candidate content; a raising target blocks the deployment entirely
    (no deployment record, old version still served), and restoring the target unblocks it.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    v1_bytes = b'{"tier":"one"}'
    v2_bytes = b'{"tier":"two"}'

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
    fn_name = ctx.unique_name("sim2real-behav-action-")
    fn_arn = _create_function(
        lam, fn_name, exec_role_arn, _ACTION_SRC, {"QUEUE_URL": queue_url, "REFUSE": "0"}
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    # The log group is created by the FIRST invocation, so it may not exist when this is registered
    # and may materialise after the function is gone. Registered anyway: an un-deleted log group is
    # a real leak and _ignore_not_found tolerates the not-found race.
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
        )
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

    extension_name = ctx.unique_name("sim2real-behav-ext-")
    extension = ac.create_extension(
        Name=extension_name,
        Actions={
            "PRE_START_DEPLOYMENT": [
                {"Name": "gate", "Uri": fn_arn, "RoleArn": invoke_role_arn}
            ]
        },
        Tags=_TAGS,
    )
    ext_id = extension["Id"]
    ctx.on_cleanup(lambda: ac.delete_extension(ExtensionIdentifier=ext_id))
    assert extension["VersionNumber"] == 1, (
        f"a new extension starts at version 1, got {extension['VersionNumber']!r}"
    )
    assert extension["Actions"]["PRE_START_DEPLOYMENT"][0]["Uri"] == fn_arn, (
        f"the action's target URI must round-trip, got {extension['Actions']!r}"
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

    env_arn = (
        f"arn:aws:appconfig:{ctx.region}:{account}:application/{app_id}/environment/{env_id}"
    )
    association = ac.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=env_arn, Tags=_TAGS
    )
    assoc_id = association["Id"]
    ctx.on_cleanup(lambda: ac.delete_extension_association(ExtensionAssociationId=assoc_id))
    assert association["ResourceArn"] == env_arn, (
        f"the association must bind to the environment ARN it was given, got "
        f"{association['ResourceArn']!r}"
    )

    # A NON-instant strategy: a 0-minute/0-bake deployment "completes instantly" and invokes no
    # action point at all.
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=1,
        GrowthFactor=100,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))

    # --- THE BARRIER: start a deployment through the action point, retrying only until AppConfig
    #     can assume the invoke role. While trust propagates, StartDeployment fails with the same
    #     BadRequestException as a genuine action refusal, so success must come first.
    dep1 = None
    last_error = None
    left = ctx.time_left()
    deadline = time.monotonic() + (_ACTION_POINT_TIMEOUT_S if left is None else min(_ACTION_POINT_TIMEOUT_S, left))
    while time.monotonic() < deadline:
        try:
            dep1 = ac.start_deployment(
                ApplicationId=app_id,
                EnvironmentId=env_id,
                DeploymentStrategyId=ds_id,
                ConfigurationProfileId=cp_id,
                ConfigurationVersion=str(v1),
                Tags=_TAGS,
            )["DeploymentNumber"]
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "BadRequestException":
                raise
            last_error = exc.response.get("Error", {})
            time.sleep(2.0)
    assert dep1 is not None, (
        f"the PRE_START_DEPLOYMENT action never let a deployment start within "
        f"{_ACTION_POINT_TIMEOUT_S}s; last error {last_error!r}"
    )

    # --- The Lambda really ran: the only evidence is the event it forwarded.
    event = _drain_one(sqs, queue_url)
    assert event is not None, (
        "the PRE_START_DEPLOYMENT action point did not invoke the Lambda — nothing reached the "
        "observation queue, so the extension association is decorative"
    )
    assert event["Application"]["Id"] == app_id, (
        f"the extension event named the wrong application: {event['Application']!r}, expected "
        f"{app_id!r}"
    )
    assert event["Environment"]["Id"] == env_id, (
        f"the extension event named the wrong environment: {event['Environment']!r}, expected "
        f"{env_id!r}"
    )
    assert event["Type"] == "PreStartDeployment", (
        f"the event declares its action point as CamelCase 'PreStartDeployment' against the "
        f"SCREAMING_SNAKE 'PRE_START_DEPLOYMENT' key used on the request; got {event['Type']!r}"
    )
    assert event["ContentVersion"] == str(v1), (
        f"the event must name the configuration version being deployed; got "
        f"{event['ContentVersion']!r} for version {v1!r}"
    )
    # The strongest leg: the action point is handed the actual configuration payload, base64'd.
    assert base64.b64decode(event["Content"]) == v1_bytes, (
        f"the event's Content must base64-decode to the exact candidate configuration; got "
        f"{base64.b64decode(event['Content'])!r} for {v1_bytes!r}"
    )
    assert event["ConfigurationProfile"]["Id"] == cp_id, (
        f"the event named the wrong configuration profile: {event['ConfigurationProfile']!r}"
    )
    assert event["TriggeredBy"] == "USER", (
        f"a StartDeployment call the customer made reports TriggeredBy 'USER', got "
        f"{event['TriggeredBy']!r}"
    )

    final = None
    deadline = time.monotonic() + _ACTION_POINT_TIMEOUT_S
    while time.monotonic() < deadline:
        final = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep1
        )
        if final.get("State") in _TERMINAL:
            break
        time.sleep(4.0)
    assert final is not None and final["State"] == "COMPLETE", (
        f"the deployment the action point allowed must reach COMPLETE, got "
        f"{(final or {}).get('State')!r}"
    )
    served = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
    assert served == v1_bytes, (
        f"the allowed deployment's bytes must be served byte-exactly; got {served!r}"
    )

    # --- Break exactly one thing: the same target, at the same action point, now raises.
    lam.update_function_configuration(
        FunctionName=fn_name,
        Environment={"Variables": {"QUEUE_URL": queue_url, "REFUSE": "1"}},
    )
    lam.get_waiter("function_updated_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    code, message = _client_error(
        lambda: ac.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=str(v2),
            Tags=_TAGS,
        )
    )
    assert code == "BadRequestException", (
        f"a PRE_START_DEPLOYMENT action that raises must block StartDeployment with "
        f"BadRequestException, got {code!r} — an emulator that treats action points as "
        f"fire-and-forget deploys this successfully and is over-permissive on the one hook a "
        f"customer uses to veto a release"
    )

    # --- The refused deployment invoked the target (so the block really came from the target) ...
    refused_event, refused_request_id = _drain_one(sqs, queue_url, with_request_id=True)
    assert refused_event is not None, (
        "the blocked StartDeployment did not invoke the action point at all, so the refusal came "
        "from somewhere other than the target"
    )
    expected_message = (
        f"Error invoking extension {extension_name}: Unhandled error, "
        f"Lambda Request ID: {refused_request_id}"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )
    assert refused_event["ContentVersion"] == str(v2), (
        f"the blocked attempt's event must name version {v2!r}, got "
        f"{refused_event['ContentVersion']!r}"
    )

    # --- ... and left NO trace: no deployment record, and the old version still in service.
    deployments = _purge_items(
        ac.get_paginator("list_deployments").paginate(
            ApplicationId=app_id, EnvironmentId=env_id
        )
    )
    assert [d["DeploymentNumber"] for d in deployments] == [dep1], (
        f"a StartDeployment blocked at PRE_START_DEPLOYMENT must create no deployment record; the "
        f"environment now holds "
        f"{[(d['DeploymentNumber'], d.get('ConfigurationVersion'), d.get('State')) for d in deployments]!r}"
    )
    served_after = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
    assert served_after == v1_bytes, (
        f"after the blocked deployment the data plane must still serve version 1's exact bytes; "
        f"got {served_after!r}"
    )
    assert served_after != v2_bytes, (
        "the vetoed configuration reached the data plane anyway — the action point's refusal was "
        "cosmetic"
    )

    # --- Restore the one thing that was broken, and demand the IDENTICAL call now succeeds: this
    #     is what makes the block attributable to the target's behaviour rather than to some other
    #     side effect (a stuck environment, a consumed strategy) that a partial repro could hide.
    lam.update_function_configuration(
        FunctionName=fn_name,
        Environment={"Variables": {"QUEUE_URL": queue_url, "REFUSE": "0"}},
    )
    lam.get_waiter("function_updated_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    dep2 = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(v2),
        Tags=_TAGS,
    )["DeploymentNumber"]

    restored_event = _drain_one(sqs, queue_url)
    assert restored_event is not None, (
        "restoring the action's target did not cause the retried deployment to invoke it at all"
    )
    assert restored_event["ContentVersion"] == str(v2), (
        f"the restored attempt's event must name version {v2!r}, got "
        f"{restored_event['ContentVersion']!r}"
    )

    final2 = None
    deadline = time.monotonic() + _ACTION_POINT_TIMEOUT_S
    while time.monotonic() < deadline:
        final2 = ac.get_deployment(ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep2)
        if final2.get("State") in _TERMINAL:
            break
        time.sleep(4.0)
    assert final2 is not None and final2["State"] == "COMPLETE", (
        f"the identical call, retried after the target was restored, must reach COMPLETE, got "
        f"{(final2 or {}).get('State')!r}"
    )
    served_restored = _serve_until(acd, app_id, env_id, cp_id, expect=v2_bytes)
    assert served_restored == v2_bytes, (
        f"once the action point stops refusing, the SAME configuration it previously vetoed must "
        f"reach the data plane; got {served_restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
