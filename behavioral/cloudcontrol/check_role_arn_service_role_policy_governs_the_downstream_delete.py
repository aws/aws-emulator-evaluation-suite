"""role-arn-service-role-policy-governs-the-downstream-delete."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-arn-service-role-policy-governs-the-downstream-delete"
GROUP = "overly-permissive"
SERVICES = ["cloudcontrol"]

SSM_PARAM_TYPE = "AWS::SSM::Parameter"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
POLICY_NAME = "sim2real-ssm-no-delete"
VALUE = "created-by-the-service-role"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Cloud Control RoleArn's policy is evaluated per downstream action: the same role creates
    the SSM parameter but is denied its delete, and the caller's own session then deletes it.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations.html
    """
    cc = ctx.client("cloudcontrol")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    identity = ctx.client("sts").get_caller_identity()
    account = identity["Account"]
    partition = identity["Arn"].split(":")[1]
    name = ctx.unique_name("sim2real-behav-ccrole-param-")
    # SSM parameter names created without a leading slash are addressed as parameter/<name>.
    parameter_arn = f"arn:{partition}:ssm:{ctx.region}:{account}:parameter/{name}"

    role_arn = _create_service_role(ctx, iam, parameter_arn)

    # ---- positive control: the ROLE itself can create ----------------------------------------
    create_event = _create_with_role_arn(ctx, cc, name, role_arn)
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, name))
    before = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]
    assert before["Value"] == VALUE, (
        f"SSM holds Value {before['Value']!r} after the role's create, expected {VALUE!r}"
    )

    # ---- break exactly one thing (the DELETE action is denied), assert the code -----------------
    denied = cc.delete_resource(
        TypeName=SSM_PARAM_TYPE,
        Identifier=name,
        RoleArn=role_arn,
        ClientToken=str(uuid.uuid4()),
    )
    denied_event = _wait_terminal(cc, denied["ProgressEvent"]["RequestToken"])
    assert denied_event["OperationStatus"] == "FAILED", (
        f"DeleteResource under a role explicitly denied ssm:DeleteParameter terminated "
        f"{denied_event['OperationStatus']!r}, expected FAILED; a facade that forwards with its "
        f"own privileges deletes here"
    )
    # The handler's Delete path reports the downstream AccessDenied as the generic
    # GeneralServiceException; the StatusMessage ties it to DeleteParameter.
    assert denied_event.get("ErrorCode") == "GeneralServiceException", (
        f"the denied delete reports ErrorCode {denied_event.get('ErrorCode')!r} / StatusMessage "
        f"{denied_event.get('StatusMessage')!r}, expected GeneralServiceException -- the "
        f"AWS::SSM::Parameter handler's documented catch-all for a downstream error its Delete path "
        f"does not map to a specific HandlerErrorCode (unlike its Create path, which maps the same "
        f"underlying AccessDeniedException to AccessDenied)"
    )
    status_message = denied_event.get("StatusMessage")
    assert status_message == "Error occurred during operation 'DeleteParameter'.", (
        f"the denied delete's StatusMessage {status_message!r} does not name the DeleteParameter "
        f"operation, so the generic ErrorCode cannot be tied to this call rather than to an "
        f"unrelated handler fault"
    )

    # ---- the effect is absent, read independently at SSM --------------------------------------
    survivor = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]
    assert survivor["Value"] == VALUE, (
        f"SSM reports Value {survivor['Value']!r} after the denied delete, expected the untouched "
        f"{VALUE!r}"
    )
    assert survivor["Version"] == 1, (
        f"SSM reports Version {survivor['Version']!r} after the denied delete, expected 1"
    )

    # ---- without RoleArn Cloud Control uses the caller's session, so the same delete succeeds --
    restored = cc.delete_resource(
        TypeName=SSM_PARAM_TYPE, Identifier=name, ClientToken=str(uuid.uuid4())
    )
    restored_event = _wait_terminal(cc, restored["ProgressEvent"]["RequestToken"])
    assert restored_event["OperationStatus"] == "SUCCESS", (
        f"the identical DeleteResource using the CALLER's own session terminated "
        f"{restored_event['OperationStatus']!r} with ErrorCode "
        f"{restored_event.get('ErrorCode')!r}, expected SUCCESS; if this fails, the refusal above "
        f"was not attributable to the role's policy"
    )
    gone_code, gone_message = _error(lambda: ssm.get_parameter(Name=name))
    assert gone_code == "ParameterNotFound", (
        f"SSM answers {gone_code!r} for {name!r} after the caller's own delete reported SUCCESS, "
        f"expected ParameterNotFound"
    )
    assert gone_message == "", (
        f"SSM's ParameterNotFound carries an empty message, got {gone_message!r}"
    )


def _create_service_role(ctx, iam, parameter_arn):
    """A service role trusted by cloudformation.amazonaws.com, carrying Allow ssm:* AND an
    explicit Deny on ssm:DeleteParameter for exactly this parameter.

    Allow ssm:* covers whatever the handler's create path calls; an explicit Deny always wins.
    """
    role_name = ctx.unique_name("sim2real-behav-ccsvcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_quiet(iam, role_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "ssm:*", "Resource": "*"},
            {
                "Effect": "Deny",
                "Action": "ssm:DeleteParameter",
                "Resource": parameter_arn,
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=POLICY_NAME, PolicyDocument=json.dumps(policy)
    )
    return role_arn


def _create_with_role_arn(ctx, cc, name, role_arn):
    """CreateResource under the service role, retrying IAM-propagation failures for up to 120s.

    A fresh role or inline policy is not instantly effective, synchronously or in the async handler.
    """
    desired_state = json.dumps(
        {"Name": name, "Type": "String", "Value": VALUE, "Tags": {"sim2real": CHECK}}
    )
    deadline = time.monotonic() + 120.0
    last_error = None
    last_event = None
    while time.monotonic() < deadline:
        try:
            progress = cc.create_resource(
                TypeName=SSM_PARAM_TYPE,
                DesiredState=desired_state,
                RoleArn=role_arn,
                ClientToken=str(uuid.uuid4()),
            )["ProgressEvent"]
        except ClientError as exc:
            last_error = exc
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            transient = code == "InvalidCredentialsException" or (
                code == "AccessDeniedException" and "Unable to assume role" in message
            )
            if not transient:
                raise
            time.sleep(4.0)
            continue

        event = _wait_terminal(cc, progress["RequestToken"])
        if event["OperationStatus"] == "SUCCESS":
            return event
        last_event = event
        async_code = event.get("ErrorCode")
        async_message = event.get("StatusMessage") or ""
        # Async propagation shapes: inline policy not yet visible (GeneralServiceException naming
        # PutParameter), a not-yet-valid session token, or the trust policy not yet visible.
        transient_async = (
            async_code == "GeneralServiceException" and "PutParameter" in async_message
        ) or (
            async_code == "AccessDenied"
            and "security token included in the request is invalid" in async_message
        ) or (
            async_code == "AccessDenied" and "Unable to assume role" in async_message
        )
        if not transient_async:
            raise AssertionError(
                f"the service role could not CREATE: status {event['OperationStatus']!r}, "
                f"ErrorCode {event.get('ErrorCode')!r}, StatusMessage {event.get('StatusMessage')!r}. "
                f"The role holds Allow ssm:* with a Deny only on ssm:DeleteParameter, so a create "
                f"failure means the RoleArn is not being honoured in the positive direction and the "
                f"denial below would prove nothing"
            )
        time.sleep(4.0)
    raise AssertionError(
        f"waited 120s for the freshly created service role {role_arn!r} to become effective for "
        f"CreateResource; last ClientError {last_error!r}, last terminal ProgressEvent {last_event!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    """Bounded retry with a deadline and a stated reason. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"waited {timeout_s}s for {reason} and it never happened; last observation {last!r}"
    )


def _wait_terminal(cc, request_token, *, timeout_s=90.0, interval_s=2.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda event: event is not None and event["OperationStatus"] in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        reason=f"request {request_token} to reach a terminal OperationStatus",
    )


def _error(fn):
    """The AWS error (code, message) raised by fn(). RAISES if the call unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _delete_role_quiet(iam, role_name):
    """Teardown, scoped to the one role this check created. The inline policy must go first or the
    role delete is refused."""
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=POLICY_NAME)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_parameter_quiet(ssm, name):
    """Teardown, scoped to the one parameter this check created."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
