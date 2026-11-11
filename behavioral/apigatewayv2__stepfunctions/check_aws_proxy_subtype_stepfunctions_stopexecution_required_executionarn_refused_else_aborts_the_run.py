"""aws-proxy-subtype-stepfunctions-stopexecution-required-executionarn-refused-else-aborts-the-run."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import quote

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aws-proxy-subtype-stepfunctions-stopexecution-required-executionarn-refused-else-aborts-the-run"

GROUP = "integrations"

SERVICES = ["apigatewayv2", "stepfunctions"]

#: Long enough that the run is still waiting when the gateway stops it; teardown stops it otherwise.
_DEFINITION = {"StartAt": "Wait", "States": {"Wait": {"Type": "Wait", "Seconds": 900, "End": True}}}


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """CreateIntegration refuses a StepFunctions-StopExecution subtype integration missing the
    required ExecutionArn parameter, and the same subtype with ExecutionArn mapped from the
    client's request stops a running execution, which reaches ABORTED.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-aws-services-reference.html
    """
    sfn = ctx.client("stepfunctions")
    # A single Wait state calls no other service, so the execution role needs no permissions
    # beyond the trust policy that lets States assume it.
    sfn_role_arn = _create_role(ctx, "states.amazonaws.com")
    sm_name = _xname(ctx, "sm")
    state_machine_arn = _poll_until(
        ctx,
        lambda: _try_create_state_machine(sfn, sm_name, sfn_role_arn),
        lambda r: r is not None,
        timeout_s=90.0,
        interval_s=4.0,
        description=f"state machine {sm_name} created once its execution role became assumable",
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=state_machine_arn))

    execution_arn = sfn.start_execution(
        stateMachineArn=state_machine_arn, name=ctx.unique_name("sim2real-xsvc-exec-"), input="{}"
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, execution_arn))
    status = sfn.describe_execution(executionArn=execution_arn)["status"]
    assert status == "RUNNING", (
        f"the execution must still be RUNNING before the subtype can stop it, got {status!r}"
    )

    credentials_arn = _create_role(
        ctx,
        "apigateway.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["states:StopExecution"], "Resource": execution_arn}
            ],
        },
    )

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_xname(ctx, "httpapi-sfnstop"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    # --- the required-parameter refusal: ExecutionArn is the only required field, and it is
    # absent.
    code, message = _error(
        lambda: agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationSubtype="StepFunctions-StopExecution",
            PayloadFormatVersion="1.0",
            CredentialsArn=credentials_arn,
            RequestParameters={},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message!r}"
    assert message == (
        "Operation: StepFunctions-StopExecution requires enabling passthrough, or defining all "
        "of the following parameters in the parameter mapping: [ExecutionArn]"
    ), f"unexpected message {message!r}"

    # --- the positive control: ExecutionArn mapped from the client's querystring.
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationSubtype="StepFunctions-StopExecution",
        PayloadFormatVersion="1.0",
        CredentialsArn=credentials_arn,
        RequestParameters={"ExecutionArn": "$request.querystring.exec"},
    )["IntegrationId"]
    # The route stops an execution, so only a SigV4-signed caller of this account reaches it.
    agw.create_route(
        ApiId=api_id,
        RouteKey="GET /stop",
        Target=f"integrations/{integration_id}",
        AuthorizationType="AWS_IAM",
    )
    agw.create_stage(
        ApiId=api_id, StageName="$default", AutoDeploy=True, Tags=_xsvc_resource_tags()
    )
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )

    stored = agw.get_integration(ApiId=api_id, IntegrationId=integration_id)
    assert stored.get("RequestParameters", {}).get("ExecutionArn") == "$request.querystring.exec", (
        f"the ExecutionArn mapping must be stored as authored, got "
        f"{stored.get('RequestParameters', {}).get('ExecutionArn')!r}"
    )

    url = (f"{ctx.stage_url(api['ApiEndpoint'], '$default')}"
           f"/stop?exec={quote(execution_arn, safe='')}")
    http_status, _, text = _poll_http(
        ctx,
        url,
        accept=lambda s: s == 200,
        description="GET /stop reaching the StepFunctions-StopExecution integration",
    )
    assert http_status == 200, (
        f"expected 200 from the StepFunctions-StopExecution subtype, got {http_status}: "
        f"{text[:300]!r}"
    )
    assert "stopDate" in json.loads(text), (
        f"expected a StopExecution-shaped response carrying stopDate, got {text[:300]!r}"
    )

    final = _poll_until(
        ctx,
        lambda: sfn.describe_execution(executionArn=execution_arn)["status"],
        lambda s: s == "ABORTED",
        timeout_s=60.0,
        interval_s=2.0,
        description="the execution reaching ABORTED after the mapped StopExecution",
    )
    assert final == "ABORTED", (
        f"the mapped StepFunctions-StopExecution must leave the execution ABORTED, got {final!r}"
    )


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-xsvc-{kind}-")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _try_create_state_machine(sfn, name, role_arn):
    try:
        return sfn.create_state_machine(
            name=name,
            definition=json.dumps(_DEFINITION),
            roleArn=role_arn,
            type="STANDARD",
            tags=[{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()],
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "AccessDeniedException":
            return None  # brand-new role not yet assumable by States
        raise


def _stop_if_running(sfn, execution_arn):
    """Teardown: stop the execution unless it already finished."""
    if sfn.describe_execution(executionArn=execution_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=execution_arn)


def _budget_s(ctx, want_s):
    """``want_s`` capped by the time the runner leaves this check."""
    left = ctx.time_left()
    return want_s if left is None else max(1.0, min(want_s, left - 10.0))


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _signed_http(ctx, method, url, body=None, headers=None, timeout_s=20):
    """(status, headers, text) of one SigV4-signed request; status None on a transport error."""
    creds = ctx.client("sts")._request_signer._credentials.get_frozen_credentials()
    req = AWSRequest(method=method, url=url, data=body, headers=headers or {})
    SigV4Auth(creds, "execute-api", ctx.region).add_auth(req)
    raw = urllib.request.Request(url, data=body, method=method, headers=dict(req.headers))
    try:
        with urllib.request.urlopen(
            raw, timeout=timeout_s, context=_ssl_context(ctx.http_verify)
        ) as resp:
            return resp.status, dict(resp.getheaders()), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read().decode("utf-8", "replace")
    except OSError as exc:
        return None, {}, f"connection error: {exc}"


def _poll_http(ctx, url, *, accept, method="GET", body=None, headers=None, timeout_s=90.0,
               interval_s=3.0, description="invoke URL"):
    """Signed requests to ``url`` until ``accept(status)``; TimeoutError with the last answer."""
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    while True:
        last = _signed_http(ctx, method, url, body=body, headers=headers)
        if accept(last[0]):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise TimeoutError(
        f"{description} ({url}) never reached an accepted status within {budget:.0f}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {budget:.0f}s. Last result: {last!r}")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx, trust_service, inline_policy=None):
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
