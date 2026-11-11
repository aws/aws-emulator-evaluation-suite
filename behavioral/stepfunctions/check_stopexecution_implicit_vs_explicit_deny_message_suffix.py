"""stopexecution-implicit-vs-explicit-deny-message-suffix."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stopexecution-implicit-vs-explicit-deny-message-suffix"
GROUP = "authorization-denial"
SERVICES = ["stepfunctions"]

_STATES_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_DEFINITION = {"StartAt": "Wait", "States": {"Wait": {"Type": "Wait", "Seconds": 300, "End": True}}}
_SESSION_NAME = "sim2real-behav-stop"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopExecution refused by an implicit deny and refused by an explicit Deny on the
    identical action and resource carry the same code and prefix, but a different suffix
    naming which kind of deny it was.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/security_iam_troubleshoot.html
    """
    sfn = ctx.client("stepfunctions")
    account = ctx.account

    exec_role_arn = _create_role(ctx, "sim2real-behav-execrole-", _STATES_TRUST)
    sm_arn = _create_state_machine(ctx, exec_role_arn, _DEFINITION)

    implicit_exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(sfn, implicit_exec_arn))
    explicit_exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(sfn, explicit_exec_arn))
    control_exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(sfn, control_exec_arn))

    trust = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": account}, "Action": "sts:AssumeRole"}]})
    implicit_arn = _create_role(ctx, "sim2real-behav-implicit-", trust)
    explicit_arn = _create_role(
        ctx, "sim2real-behav-explicit-", trust,
        statements=[
            {"Effect": "Allow", "Action": "states:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "states:StopExecution", "Resource": "*"},
        ],
    )
    granted_arn = _create_role(
        ctx, "sim2real-behav-granted-", trust,
        statements=[{"Effect": "Allow", "Action": "states:StopExecution", "Resource": "*"}],
    )

    implicit_client = _assume_as_client(ctx, "stepfunctions", implicit_arn)
    explicit_client = _assume_as_client(ctx, "stepfunctions", explicit_arn)

    implicit_code, implicit_message = _error(
        lambda: implicit_client.stop_execution(executionArn=implicit_exec_arn)
    )
    explicit_code, explicit_message = _error(
        lambda: explicit_client.stop_execution(executionArn=explicit_exec_arn)
    )

    assert implicit_code == "AccessDeniedException", implicit_code
    assert explicit_code == "AccessDeniedException", explicit_code

    implicit_identity = f"arn:aws:sts::{account}:assumed-role/{implicit_arn.rsplit('/', 1)[-1]}/{_SESSION_NAME}"
    explicit_identity = f"arn:aws:sts::{account}:assumed-role/{explicit_arn.rsplit('/', 1)[-1]}/{_SESSION_NAME}"
    prefix_implicit = (
        f"User: {implicit_identity} is not authorized to perform: states:StopExecution "
        f"on resource: {implicit_exec_arn}"
    )
    prefix_explicit = (
        f"User: {explicit_identity} is not authorized to perform: states:StopExecution "
        f"on resource: {explicit_exec_arn}"
    )
    assert implicit_message == prefix_implicit + " because no identity-based policy allows the " \
        "states:StopExecution action", implicit_message
    assert explicit_message == prefix_explicit + " with an explicit deny in an identity-based " \
        "policy", explicit_message

    # The two refusals name the SAME code and the same ACTION/RESOURCE clause; only the
    # deny-kind suffix differs. Strip each one's own prefix and confirm the remainder diverges.
    implicit_suffix = implicit_message[len(prefix_implicit):]
    explicit_suffix = explicit_message[len(prefix_explicit):]
    assert implicit_suffix != explicit_suffix, (
        f"implicit and explicit denials must carry different suffixes; both were {implicit_suffix!r}"
    )

    # Effect absent for both: neither denied call stopped its execution.
    assert sfn.describe_execution(executionArn=implicit_exec_arn)["status"] == "RUNNING"
    assert sfn.describe_execution(executionArn=explicit_exec_arn)["status"] == "RUNNING"

    # Positive control: a caller actually granted the action stops its own execution.
    granted_client = _assume_as_client(ctx, "stepfunctions", granted_arn)
    _retry_while_denied(lambda: granted_client.stop_execution(executionArn=control_exec_arn))
    final = _poll_until(
        lambda: sfn.describe_execution(executionArn=control_exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60.0, description="the granted StopExecution to take effect",
    )
    assert final["status"] == "ABORTED", final


def _best_effort_stop(sfn, exec_arn):
    try:
        sfn.stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _create_role(ctx, prefix, trust_policy, *, statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)
    if statements:
        iam.put_role_policy(
            RoleName=role_name, PolicyName=f"{role_name}-policy",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return role_arn


def _create_state_machine(ctx, role_arn, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90
    arn = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
            )["stateMachineArn"]
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            time.sleep(3)
    if arn is None:
        raise AssertionError(f"create_state_machine never succeeded: {last_err!r}")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _assume_as_client(ctx, service, role_arn, *, timeout_s=90.0):
    """A ctx client signed with role_arn's credentials. A just-minted STS session can be
    rejected by other services for a few seconds after STS itself accepts it; that warm-up
    is retried on its one documented code before the client is handed back."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
        except ClientError as exc:
            last = exc
            time.sleep(3)
            continue
        boto_creds = {
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        }
        warmup = ctx.client("sts", creds=boto_creds)
        while time.monotonic() < deadline:
            try:
                warmup.get_caller_identity()
                return ctx.client(service, creds=boto_creds)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "UnrecognizedClientException":
                    raise
                last = exc
                time.sleep(2)
    raise AssertionError(f"could not assume {role_arn!r} within {timeout_s}s: {last!r}")


def _retry_while_denied(fn, *, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"still denied after {timeout_s}s of IAM propagation: {last!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


def _error(fn) -> tuple[str, str]:
    """The AWS error (code, message) ``fn`` raised; raises if ``fn`` unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"call was expected to be refused but SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
