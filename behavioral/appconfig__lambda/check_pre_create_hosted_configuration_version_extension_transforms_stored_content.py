"""pre-create-hosted-configuration-version-extension-transforms-stored-content."""
from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pre-create-hosted-configuration-version-extension-transforms-stored-content"
GROUP = 'extension'
SERVICES = ['appconfig', 'lambda']

# A PRE_CREATE_HOSTED_CONFIGURATION_VERSION action may return {"Content": "<base64>"} to replace
# the stored bytes; associating to a configuration profile ARN applies to its hosted versions.

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-pre-create-transform"}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
# Two Lambda/IAM first-use propagation retries dominate the wall clock.
_TRANSFORM_BUDGET_S = 600

# The extension's target. It forwards the event AppConfig handed it to an SQS queue — the queue is
# the only way to observe the event's CONTENTS, since no AppConfig API reports them — and then
# either transforms the content or returns nothing, according to an environment variable.
#
# The stamp value is generated per run and passed in as an environment variable.
_ACTION_SRC = '''
import base64, json, os, boto3

_SQS = boto3.client("sqs")


def handler(event, context):
    _SQS.send_message(QueueUrl=os.environ["QUEUE_URL"],
                      MessageBody=json.dumps(event, default=str))
    if os.environ.get("TRANSFORM") != "1":
        return {}
    original = base64.b64decode(event["Content"])
    document = json.loads(original.decode("utf-8"))
    document["stamped"] = os.environ["STAMP"]
    replacement = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"Content": base64.b64encode(replacement).decode("ascii")}
'''


# DeletionProtection may be enabled account-wide, so DeleteEnvironment/DeleteConfigurationProfile
# pass DeletionProtectionCheck="BYPASS" explicitly.


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
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
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


def _create_version_when_extension_is_live(ac, app_id, cp_id, content, timeout_s=300):
    """Create a hosted configuration version, retrying (bounded) while the extension's invoke role
    has not propagated: that failure is the same BadRequestException a refusing action returns.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return ac.create_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
                Content=content,
                ContentType="application/json",
            )
        except ClientError as exc:
            last = exc.response.get("Error", {})
            time.sleep(5.0)
    raise AssertionError(
        f"CreateHostedConfigurationVersion never succeeded through the "
        f"PRE_CREATE_HOSTED_CONFIGURATION_VERSION action point within {timeout_s}s; last error "
        f"{last!r}"
    )


def _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version, timeout_s=180):
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
        time.sleep(2.0)
    assert last is not None and last.get("State") == "COMPLETE", (
        f"deployment {dep_num} of version {version} did not reach COMPLETE within {timeout_s}s; "
        f"last state {(last or {}).get('State')!r}"
    )
    return dep_num


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=180):
    """Poll FRESH configuration sessions until one serves exactly `expect`; return the last payload.
    New sessions, because a next-poll token used before NextPollIntervalInSeconds is refused.
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PRE_CREATE_HOSTED_CONFIGURATION_VERSION extension rewrites the stored bytes, receives the
    new and previous content, and its output is what appconfigdata serves; without the association
    the same bytes are stored verbatim.

    Reference: https://docs.aws.amazon.com/appconfig/latest/userguide/working-with-appconfig-extensions-creating-custom-lambda.html
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # The stamp is derived from ctx.unique_name so it is unique per run.
    stamp = ctx.unique_name("stamp-")
    sent_document = {"tier": "one"}
    sent_bytes = json.dumps(sent_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    transformed_bytes = json.dumps(
        {**sent_document, "stamped": stamp}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert transformed_bytes != sent_bytes, (
        f"the check's own expectation is degenerate: the transformed document equals the sent one "
        f"({sent_bytes!r})"
    )

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
    fn_name = ctx.unique_name("sim2real-behav-transform-")
    fn_arn = _create_function(
        lam,
        fn_name,
        exec_role_arn,
        _ACTION_SRC,
        {"QUEUE_URL": queue_url, "TRANSFORM": "1", "STAMP": stamp},
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

    extension = ac.create_extension(
        Name=ctx.unique_name("sim2real-behav-ext-"),
        Actions={
            "PRE_CREATE_HOSTED_CONFIGURATION_VERSION": [
                {"Name": "stamp", "Uri": fn_arn, "RoleArn": invoke_role_arn}
            ]
        },
        Tags=_TAGS,
    )
    ext_id = extension["Id"]
    ctx.on_cleanup(lambda: ac.delete_extension(ExtensionIdentifier=ext_id))
    assert extension["Actions"]["PRE_CREATE_HOSTED_CONFIGURATION_VERSION"][0]["Uri"] == fn_arn, (
        f"the action's target URI must round-trip on the extension; got "
        f"{extension['Actions']!r}"
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
    cp_arn = (
        f"arn:aws:appconfig:{ctx.region}:{account}:application/{app_id}"
        f"/configurationprofile/{cp_id}"
    )
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))

    # --- BEAT 1, the control: with no association, the store is byte-faithful.
    v1 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=sent_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    assert v1 == 1, f"the first hosted version must be 1, got {v1!r}"
    stored_v1 = ac.get_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=v1
    )["Content"].read()
    assert stored_v1 == sent_bytes, (
        f"with NO extension association the hosted store must keep the request bytes verbatim; "
        f"sent {sent_bytes!r}, stored {stored_v1!r} — without this control the transformation "
        f"below could not be attributed to the extension"
    )

    # --- BEAT 2, the act: associate the extension, then send the IDENTICAL bytes again.
    association = ac.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=cp_arn, Tags=_TAGS
    )
    assoc_id = association["Id"]
    # The check deletes this association itself; the teardown covers a run that stops earlier.
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: ac.delete_extension_association(ExtensionAssociationId=assoc_id)
        )
    )
    assert association["ResourceArn"] == cp_arn, (
        f"the association must bind to the configuration profile ARN it was given; got "
        f"{association['ResourceArn']!r}"
    )

    created_v2 = _create_version_when_extension_is_live(ac, app_id, cp_id, sent_bytes)
    v2 = created_v2["VersionNumber"]
    assert v2 == 2, f"the second hosted version must be 2, got {v2!r}"

    # The event the action point received, read off the independent SQS side-channel — no
    # AppConfig API reports it.
    event = _drain_one(sqs, queue_url)
    assert event is not None, (
        "the PRE_CREATE_HOSTED_CONFIGURATION_VERSION action point did not invoke the Lambda — "
        "nothing reached the observation queue, so the create was never routed through the "
        "extension at all"
    )
    assert event["Type"] == "PreCreateHostedConfigurationVersion", (
        f"the action point's event Type is PascalCase, NOT the SCREAMING_SNAKE "
        f"'PRE_CREATE_HOSTED_CONFIGURATION_VERSION' key used on the CreateExtension request; got "
        f"{event['Type']!r}"
    )
    assert event["ContentVersion"] == str(v2), (
        f"the event must describe the version being created ({v2}) as a STRING; got "
        f"{event.get('ContentVersion')!r}"
    )
    assert event["ContentType"] == "application/json", (
        f"the event must carry the request's ContentType; got {event.get('ContentType')!r}"
    )
    assert base64.b64decode(event["Content"]) == sent_bytes, (
        f"the action point must receive the UNMODIFIED request bytes, base64-encoded; decoded to "
        f"{base64.b64decode(event['Content'])!r}, sent {sent_bytes!r}"
    )
    assert event["ConfigurationProfile"]["Id"] == cp_id, (
        f"the event must name the configuration profile under change; got "
        f"{event.get('ConfigurationProfile')!r}"
    )
    # PreviousContent is derived state no single request carries: AppConfig has to look up the
    # version that came before this one and hand its bytes to the action point too.
    previous = event["PreviousContent"]
    assert previous["ContentVersion"] == str(v1), (
        f"the event's PreviousContent must describe version {v1}, the version that existed before "
        f"this create; got {previous.get('ContentVersion')!r}"
    )
    assert base64.b64decode(previous["Content"]) == stored_v1, (
        f"the event's PreviousContent must carry version {v1}'s STORED bytes; decoded to "
        f"{base64.b64decode(previous['Content'])!r}, stored {stored_v1!r}"
    )

    # THE POINT: the same request body produced a DIFFERENT stored artifact.
    stored_v2 = ac.get_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=v2
    )["Content"].read()
    assert stored_v2 == transformed_bytes, (
        f"the PRE_CREATE_HOSTED_CONFIGURATION_VERSION action returned a replacement Content, so "
        f"the STORED version {v2} must be the transformed document, not the request body; "
        f"expected {transformed_bytes!r}, stored {stored_v2!r}"
    )
    assert stored_v2 != sent_bytes, (
        f"version {v2} was stored byte-identically to the request, so the extension's Content "
        f"response was ignored: {stored_v2!r}"
    )
    assert created_v2["Content"].read() == stored_v2, (
        "CreateHostedConfigurationVersion's own response body must agree with the independent "
        "GetHostedConfigurationVersion read about the post-transform content"
    )

    # --- BEAT 3, the destination: the rewritten bytes are what clients actually receive.
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, v2)
    served = _serve_until(acd, app_id, env_id, cp_id, expect=transformed_bytes)
    assert served == transformed_bytes, (
        f"appconfigdata must serve the TRANSFORMED bytes for the deployed version {v2}; expected "
        f"{transformed_bytes!r}, served {served!r} — a rewrite visible only on the control plane "
        f"is not the contract"
    )
    assert served != sent_bytes, (
        "the data plane is serving the pre-transform request bytes, so the extension's rewrite "
        "never reached the configuration that clients read"
    )

    # --- BEAT 4, restore: remove the association and the transformation stops.
    ac.delete_extension_association(ExtensionAssociationId=assoc_id)
    code = message = None
    try:
        ac.get_extension_association(ExtensionAssociationId=assoc_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "ResourceNotFoundException", (
        f"the deleted association must be gone by an independent read; GetExtensionAssociation "
        f"answered {code!r}"
    )
    expected_message = f"ExtensionAssociation could not be found for account {account}."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    v3 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=sent_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    assert v3 == 3, f"the third hosted version must be 3, got {v3!r}"
    stored_v3 = ac.get_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=v3
    )["Content"].read()
    assert stored_v3 == sent_bytes, (
        f"with the association removed the IDENTICAL request must be stored verbatim again; sent "
        f"{sent_bytes!r}, stored {stored_v3!r} — a target that keeps transforming is applying an "
        f"extension that no longer exists"
    )
    assert stamp.encode("utf-8") not in stored_v3, (
        f"version {v3} still carries this run's stamp {stamp!r}, so the transformation outlived "
        f"the association that caused it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
