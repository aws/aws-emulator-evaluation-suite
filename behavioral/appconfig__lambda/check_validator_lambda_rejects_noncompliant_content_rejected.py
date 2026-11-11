"""validator-lambda-rejects-noncompliant-content-rejected."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validator-lambda-rejects-noncompliant-content-rejected"
GROUP = 'validate-configuration'
SERVICES = ['appconfig', 'lambda']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-lambda-validator"}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_BASIC_EXECUTION = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
# Covers the IAM-propagation retry plus three deployments.
_VALIDATOR_TIMEOUT_S = 600

# The validator AppConfig invokes. It receives the candidate configuration as base64 in the
# event's `content` key and refuses anything whose schema_version is not 2. Raising is how a
# LAMBDA validator says "invalid" — there is no structured refusal envelope.
_VALIDATOR_SRC = '''
import base64, json


def handler(event, context):
    doc = json.loads(base64.b64decode(event["content"]).decode())
    if doc.get("schema_version") != 2:
        raise Exception("schema_version must be 2, got %r" % (doc.get("schema_version"),))
    return {}
'''


def _error_of(fn):
    """Return the botocore (Error.Code, Error.Message) if fn() raises ClientError; raise if fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
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
    """Delete an application and everything beneath it, bottom-up."""
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
        # Account-level deletion protection may be enabled, so deletes bypass it explicitly.
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
    """Build a one-file deployment package in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handler.py", src)
    return buf.getvalue()


def _create_function(lam, name, role_arn, src, timeout_s=180):
    """Create a Lambda, retrying the InvalidParameterValueException a fresh execution role raises
    until IAM has propagated."""
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
                Timeout=20,
                Tags=_TAGS,
            )["FunctionArn"]
        except ClientError as exc:
            last = exc.response.get("Error", {})
            if last.get("Code") != "InvalidParameterValueException":
                raise
            time.sleep(5.0)
    raise AssertionError(f"Lambda {name} never became creatable within {timeout_s}s: {last!r}")


def _deploy_to_complete(ac, app_id, env_id, ds_id, cp_id, version, timeout_s=240):
    """Start a deployment and poll until COMPLETE; ROLLED_BACK fails."""
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
        f"deployment {dep_num} of version {version} did not reach COMPLETE within "
        f"{timeout_s}s; last state {(last or {}).get('State')!r}"
    )
    return dep_num


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=240):
    """Poll fresh configuration sessions until one serves exactly `expect`; return the last payload.

    The data plane lags a deployment reaching COMPLETE by a few seconds. A new session per attempt
    avoids next-poll tokens, which are refused before NextPollIntervalInSeconds elapses.
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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A LAMBDA validator that raises makes StartDeployment fail with BadRequestException, creating no
    deployment and never serving the rejected bytes (which CreateHostedConfigurationVersion stored),
    while compliant content on the same profile deploys and is served.

    Reference: https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-configuration-and-profile-validators.html
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    v1_bytes = json.dumps({"schema_version": 2, "flavour": "vanilla"}, sort_keys=True).encode()
    bad_bytes = json.dumps({"schema_version": 1, "flavour": "vanilla"}, sort_keys=True).encode()
    v3_bytes = json.dumps({"schema_version": 2, "flavour": "pistachio"}, sort_keys=True).encode()

    role_name = ctx.unique_name("sim2real-behav-vrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=_TAGLIST,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXECUTION)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXECUTION)
    )

    fn_name = ctx.unique_name("sim2real-behav-validator-")
    fn_arn = _create_function(lam, fn_name, role_arn, _VALIDATOR_SRC)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    # The log group is created by the FIRST invocation, so it may not exist yet when this is
    # registered and may appear only after the function is gone. Registered here anyway: an
    # un-deleted log group is a real leak, and _ignore_not_found tolerates the not-found race.
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

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Validators=[{"Type": "LAMBDA", "Content": fn_arn}],
        Tags=_TAGS,
    )["Id"]
    profile = ac.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    assert profile["Validators"] == [{"Type": "LAMBDA", "Content": fn_arn}], (
        f"the LAMBDA validator must round-trip on the profile, got {profile.get('Validators')!r}"
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

    v1 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=v1_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    assert v1 == 1, f"first hosted version must be 1, got {v1!r}"

    # Deploy the compliant version first: while AppConfig's invoke grant propagates, StartDeployment
    # fails with the same BadRequestException as a real validator refusal. Once this succeeds,
    # later refusals are about the content.
    deadline = time.monotonic() + min(_VALIDATOR_TIMEOUT_S, ctx.time_left())
    dep1 = None
    last_error = None
    while time.monotonic() < deadline:
        try:
            dep1 = _deploy_to_complete(ac, app_id, env_id, ds_id, cp_id, v1)
            break
        except ClientError as exc:
            last_error = exc.response.get("Error", {})
            if last_error.get("Code") != "BadRequestException":
                raise
            time.sleep(2.0)
    assert dep1 is not None, (
        f"AppConfig never managed to invoke the validator for the COMPLIANT version within "
        f"{_VALIDATOR_TIMEOUT_S}s; last error {last_error!r} — without a successful validated "
        f"deployment the refusal below would be indistinguishable from a propagation delay"
    )
    served_v1 = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
    assert served_v1 == v1_bytes, (
        f"the validated version 1 must be served byte-exactly; got {served_v1!r}"
    )

    # A LAMBDA validator gates StartDeployment, not CreateHostedConfigurationVersion.
    bad_version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=bad_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    assert bad_version == 2, f"the second hosted version must be 2, got {bad_version!r}"
    stored_bad = ac.get_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=bad_version
    )["Content"].read()
    assert stored_bad == bad_bytes, (
        f"a LAMBDA validator does NOT gate CreateHostedConfigurationVersion, so the "
        f"non-compliant bytes must be stored verbatim; got {stored_bad!r}"
    )

    code, message = _error_of(
        lambda: ac.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=str(bad_version),
            Tags=_TAGS,
        )
    )
    assert code == "BadRequestException", (
        f"StartDeployment of content the LAMBDA validator refuses must answer "
        f"BadRequestException, got {code!r} — an emulator that ignores Validators deploys this "
        f"successfully and is over-permissive on AppConfig's only customer-code safety gate"
    )
    # AppConfig relays the Lambda error payload, which carries the invocation's runtime-assigned
    # requestId the check never sees: mask only that id.
    assert re.sub(r'"requestId": "[0-9a-f-]+"', '"requestId": "<id>"', message) == (
        "Function Error: Unhandled, Log Result: null, Payload: "
        '{"errorMessage": "schema_version must be 2, got 1", "errorType": "Exception", '
        '"requestId": "<id>", "stackTrace": ["  File \\"/var/task/handler.py\\", line 8, in handler'
        '\\n    raise Exception(\\"schema_version must be 2, got %r\\" % (doc.get(\\"schema_version\\"),))'
        '\\n"]}'
    ), (
        f"StartDeployment must relay the validator's own error, got {message!r}"
    )

    # The refused StartDeployment created no deployment record.
    deployments = _purge_items(
        ac.get_paginator("list_deployments").paginate(
            ApplicationId=app_id, EnvironmentId=env_id
        )
    )
    assert [d["DeploymentNumber"] for d in deployments] == [dep1], (
        f"the refused deployment must leave no record; the environment now holds deployments "
        f"{[(d['DeploymentNumber'], d.get('ConfigurationVersion'), d.get('State')) for d in deployments]!r}"
    )
    # The rejected bytes were never served.
    served_after = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
    assert served_after == v1_bytes, (
        f"after a refused deployment the data plane must still serve version 1's exact bytes; got "
        f"{served_after!r}"
    )
    assert served_after != bad_bytes, (
        "the data plane served the content the validator rejected — the refusal was cosmetic"
    )

    # Different compliant content still deploys and is served: the validator is not refusing all.
    v3 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=v3_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    assert v3 == 3, f"the third hosted version must be 3, got {v3!r}"
    dep3 = _deploy_to_complete(ac, app_id, env_id, ds_id, cp_id, v3)
    assert dep3 == dep1 + 1, (
        f"deployment numbers are a per-environment sequence and the refused attempt must not have "
        f"consumed one: after deployment {dep1} the next is {dep3}"
    )
    served_v3 = _serve_until(acd, app_id, env_id, cp_id, expect=v3_bytes)
    assert served_v3 == v3_bytes, (
        f"the control deployment's bytes must be served byte-exactly; got {served_v3!r}"
    )
    assert served_v3 != v1_bytes, (
        "the data plane is still serving version 1 after the control deployment completed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
