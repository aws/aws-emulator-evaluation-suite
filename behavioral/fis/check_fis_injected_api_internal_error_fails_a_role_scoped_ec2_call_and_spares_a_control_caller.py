"""fis-injected-api-internal-error-fails-a-role-scoped-ec2-call-and-spares-a-control-caller."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "fis-injected-api-internal-error-fails-a-role-scoped-ec2-call-and-spares-a-control-caller"
GROUP = "fault-injection"
SERVICES = ["fis"]

# AWS behavior for this exact template
# (service=ec2, operations=DescribeAvailabilityZones, percentage=100, duration=PT2M):
#   Error.Code                            -> 'InternalError'
#   Error.Message                         -> 'An internal error has occurred'
#   ResponseMetadata.HTTPStatusCode        -> 500
#   10/10 sequential calls failed          (percentage=100 is deterministic per call)
#   fault first observed 26.5s after the experiment reported state.status == 'running'
#   the caller's own identity and DescribeRegions were BOTH unaffected in the same window
#   recovery was immediate (0.1s) once the experiment reached 'completed'
_INJECTED_ERROR_CODE = "InternalError"
_INJECTED_ERROR_MESSAGE = "An internal error has occurred"
_INJECTED_HTTP_STATUS = 500

# `max_attempts` in botocore means RETRIES, so the normalized `total_max_attempts` is N+1 and the
# before-send hook counts exactly that many HTTP sends. Both numbers are asserted, never assumed.
_RETRY_MAX_ATTEMPTS = 4
_RETRY_TOTAL_ATTEMPTS = 5
_NORETRY_MAX_ATTEMPTS = 1
_NORETRY_TOTAL_ATTEMPTS = 2

_DETERMINISM_CALLS = 10

# Deadlines. The longest single wait is the PT2M action running to completion, ~72s from
# `running` on AWS, but it is a service-side timer, so it gets real headroom.
_IAM_PROPAGATION_BUDGET_S = 120.0
_EXPERIMENT_RUNNING_TIMEOUT_S = 180.0
_FAULT_VISIBLE_TIMEOUT_S = 240.0
_EXPERIMENT_COMPLETE_TIMEOUT_S = 600.0
_RECOVERY_TIMEOUT_S = 180.0


# timing:real-time — workflow: 120 s https://docs.aws.amazon.com/fis/latest/userguide/fis-actions-reference.html
@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data", "resource:account-singleton:fis-active-experiment-quota", "timing:real-time")
def run(ctx) -> None:
    """A live FIS inject-api-internal-error experiment makes the targeted EC2 operation return 500 to
    the targeted role's credentials only: another operation and another caller are untouched, and
    the 500 stops once the action's duration elapses."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")
    sts = ctx.client("sts")
    ec2_caller = ctx.client("ec2")

    account = sts.get_caller_identity()["Account"]
    caller_arn = sts.get_caller_identity()["Arn"]
    fis_trust = {
        "Effect": "Allow",
        "Principal": {"Service": "fis.amazonaws.com"},
        "Action": "sts:AssumeRole",
        # aws:SourceAccount / aws:SourceArn confused-deputy conditions, as FIS documents them.
        "Condition": {
            "StringEquals": {"aws:SourceAccount": account},
            "ArnLike": {"aws:SourceArn": f"arn:aws:fis:{ctx.region}:{account}:experiment/*"},
        },
    }

    # Role R -- the fault's target. Dual trust: FIS (so it can be named in an aws:iam:role target)
    # and the caller's principal (so THIS check can hold R's credentials and be the faulted caller).
    # FIS does NOT require the trust policy to be exclusively fis.amazonaws.com.
    target_role = _create_role(
        ctx, iam,
        trust=[fis_trust, {"Effect": "Allow", "Principal": {"AWS": caller_arn},
                           "Action": "sts:AssumeRole"}],
        actions=["ec2:DescribeAvailabilityZones", "ec2:DescribeRegions"],
    )
    # Role E -- FIS's own execution role.
    exec_role = _create_role(
        ctx, iam, trust=[fis_trust],
        actions=["fis:InjectApiInternalError", "iam:GetRole", "iam:ListRoles", "tag:GetResources"],
    )

    action_targets = fis.get_action(id="aws:fis:inject-api-internal-error")["action"]["targets"]
    assert set(action_targets) == {"Roles"}, (
        f"aws:fis:inject-api-internal-error target keys were {sorted(action_targets)!r}, "
        "expected exactly ['Roles'] -- the fault is scoped by IAM ROLE, not by resource tag"
    )

    template_id = _create_template(
        ctx, fis, role_arn=exec_role,
        targets={"roleTarget": {"resourceType": "aws:iam:role", "resourceArns": [target_role],
                                "selectionMode": "ALL"}},
        actions={"fault": {
            "actionId": "aws:fis:inject-api-internal-error",
            "parameters": {"duration": "PT2M", "service": "ec2", "percentage": "100",
                           "operations": "DescribeAvailabilityZones"},
            "targets": {"Roles": "roleTarget"},
        }},
    )

    # ---- the faulted caller and its attempt counter -------------------------------------------
    role_creds = _assume(ctx, sts, target_role, timeout_s=_IAM_PROPAGATION_BUDGET_S)
    retrying_attempts: list[float] = []
    ec2_retrying = _counted_client(ctx, role_creds, _RETRY_MAX_ATTEMPTS, retrying_attempts)
    plain_attempts: list[float] = []
    ec2_plain = _counted_client(ctx, role_creds, _NORETRY_MAX_ATTEMPTS, plain_attempts)

    assert ec2_retrying.meta.config.retries["total_max_attempts"] == _RETRY_TOTAL_ATTEMPTS, (
        f"max_attempts={_RETRY_MAX_ATTEMPTS} normalized to "
        f"{ec2_retrying.meta.config.retries['total_max_attempts']!r}, expected "
        f"{_RETRY_TOTAL_ATTEMPTS} -- botocore's max_attempts counts RETRIES, not sends"
    )
    assert ec2_plain.meta.config.retries["total_max_attempts"] == _NORETRY_TOTAL_ATTEMPTS, (
        f"max_attempts={_NORETRY_MAX_ATTEMPTS} normalized to "
        f"{ec2_plain.meta.config.retries['total_max_attempts']!r}, "
        f"expected {_NORETRY_TOTAL_ATTEMPTS}"
    )

    # ---- baseline: the operation works for R before any fault exists ---------------------------
    del retrying_attempts[:]
    baseline = _describe_azs_when_permitted(ec2_retrying, timeout_s=_IAM_PROPAGATION_BUDGET_S)
    assert baseline["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"baseline DescribeAvailabilityZones returned "
        f"{baseline['ResponseMetadata']['HTTPStatusCode']!r} before any experiment existed"
    )
    assert len(baseline["AvailabilityZones"]) >= 3, (
        f"baseline returned {len(baseline['AvailabilityZones'])} AZs; us-west-2 has at least 3, "
        "so this is not a real payload"
    )

    # ---- start the experiment -------------------------------------------------------------------
    experiment_id = _start_experiment(ctx, fis, template_id)
    status = _poll_experiment(fis, experiment_id, {"running", "completed", "failed"},
                              timeout_s=_EXPERIMENT_RUNNING_TIMEOUT_S)
    assert status == "running", (
        f"experiment reached {status!r}, not 'running' -- the fault never became live"
    )

    # ---- the fault is real, and it is a 500 with the exact code AWS uses -----------------------
    del plain_attempts[:]
    err = _poll_for_injected_error(ec2_plain, plain_attempts, timeout_s=_FAULT_VISIBLE_TIMEOUT_S)
    observed_code = err.response["Error"]["Code"]
    assert observed_code == _INJECTED_ERROR_CODE, (
        f"injected EC2 failure reported Error.Code {observed_code!r}, expected "
        f"{_INJECTED_ERROR_CODE!r} -- a different code changes botocore's retry classification"
    )
    observed_message = err.response["Error"].get("Message")
    assert observed_message == _INJECTED_ERROR_MESSAGE, (
        f"injected EC2 failure reported Error.Message {observed_message!r}, expected "
        f"{_INJECTED_ERROR_MESSAGE!r}"
    )
    assert err.response["ResponseMetadata"]["HTTPStatusCode"] == _INJECTED_HTTP_STATUS, (
        f"injected failure carried HTTP "
        f"{err.response['ResponseMetadata']['HTTPStatusCode']!r}, expected "
        f"{_INJECTED_HTTP_STATUS} -- a 4xx would not be retryable"
    )

    # The fault is attributed to a LIVE action, not to a flaky endpoint.
    action_state = fis.get_experiment(id=experiment_id)["experiment"]["actions"]["fault"]["state"]
    assert action_state["status"] == "running", (
        f"the action's own state was {action_state!r} at the moment the 500 was observed -- "
        "the failure cannot be attributed to the injected fault"
    )

    # ---- effect-absent: at percentage=100 EVERY call fails, none returns AZ data ---------------
    del plain_attempts[:]
    outcomes = []
    for _ in range(_DETERMINISM_CALLS):
        outcomes.append(_call_outcome(ec2_plain))
    codes = {o for o in outcomes if isinstance(o, tuple)}
    successes = [o for o in outcomes if not isinstance(o, tuple)]
    assert not successes, (
        f"{len(successes)} of {_DETERMINISM_CALLS} calls SUCCEEDED at percentage=100 "
        f"(first payload had {len(successes[0]) if successes else 0} AZs) -- the fault is not "
        "applied per call"
    )
    assert codes == {(_INJECTED_ERROR_CODE, _INJECTED_ERROR_MESSAGE)}, (
        f"the {_DETERMINISM_CALLS} faulted calls produced errors {sorted(codes)!r}, expected only "
        f"[{(_INJECTED_ERROR_CODE, _INJECTED_ERROR_MESSAGE)!r}]"
    )
    assert len(plain_attempts) == _DETERMINISM_CALLS * _NORETRY_TOTAL_ATTEMPTS, (
        f"{_DETERMINISM_CALLS} calls on a total_max_attempts={_NORETRY_TOTAL_ATTEMPTS} client made "
        f"{len(plain_attempts)} HTTP sends, expected "
        f"{_DETERMINISM_CALLS * _NORETRY_TOTAL_ATTEMPTS} -- the 500 must be retried by botocore"
    )

    # The retry count is config-driven, not fixed: the same faulted call on the other client.
    del retrying_attempts[:]
    retried = _call_outcome(ec2_retrying)
    assert retried == (_INJECTED_ERROR_CODE, _INJECTED_ERROR_MESSAGE), (
        f"the retrying client's faulted call ended as {retried!r}, expected "
        f"{(_INJECTED_ERROR_CODE, _INJECTED_ERROR_MESSAGE)!r}"
    )
    assert len(retrying_attempts) == _RETRY_TOTAL_ATTEMPTS, (
        f"a total_max_attempts={_RETRY_TOTAL_ATTEMPTS} client made {len(retrying_attempts)} HTTP "
        f"sends against the injected 500, while the "
        f"total_max_attempts={_NORETRY_TOTAL_ATTEMPTS} client made "
        f"{_NORETRY_TOTAL_ATTEMPTS} -- the retry count is not driven by the client config"
    )

    # ---- positive control 1: identity scoping. The caller's own principal is untouched. -------
    control_identity = ec2_caller.describe_availability_zones()
    assert control_identity["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        "the caller's own DescribeAvailabilityZones ALSO failed during the experiment -- the "
        "fault is account-wide, not scoped to the targeted role, and every sibling check sharing "
        "this account is collateral"
    )
    assert len(control_identity["AvailabilityZones"]) >= 3, (
        f"the control caller got {len(control_identity['AvailabilityZones'])} AZs, not a real payload"
    )

    # ---- positive control 2: operation scoping. An unnamed operation on the SAME client works. --
    control_op = ec2_plain.describe_regions()
    assert control_op["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        "DescribeRegions ALSO failed on the faulted client -- the fault is not scoped to the "
        "`operations` parameter"
    )
    assert len(control_op["Regions"]) >= 10, (
        f"the control operation returned {len(control_op['Regions'])} regions, not a real payload"
    )

    # ---- recovery: the fault stops when the action's duration elapses --------------------------
    final = _poll_experiment(fis, experiment_id, {"completed", "stopped", "failed"},
                             timeout_s=_EXPERIMENT_COMPLETE_TIMEOUT_S)
    assert final == "completed", (
        f"the PT2M experiment ended as {final!r}, not 'completed' -- recovery cannot be attributed "
        "to the duration elapsing"
    )
    recovered = _poll_for_recovery(ec2_plain, plain_attempts, timeout_s=_RECOVERY_TIMEOUT_S)
    assert len(recovered["AvailabilityZones"]) >= 3, (
        f"after the experiment completed the call returned "
        f"{len(recovered['AvailabilityZones'])} AZs -- an empty shell, not a real payload"
    )
    assert len(plain_attempts) == 1, (
        f"the recovered call took {len(plain_attempts)} HTTP sends, expected 1 -- it is still "
        "being retried, so the fault has not really been withdrawn"
    )

    # ---- verified teardown, inline ---------------------------------------------------------------
    fis.delete_experiment_template(id=template_id)
    gone, gone_message = _error(lambda: fis.get_experiment_template(id=template_id))
    assert gone == "ResourceNotFoundException", (
        f"after DeleteExperimentTemplate, GetExperimentTemplate reported {gone!r}, expected "
        "'ResourceNotFoundException'"
    )
    assert gone_message == "ExperimentTemplate not found.", (
        f"after DeleteExperimentTemplate, GetExperimentTemplate said {gone_message!r}, expected "
        "'ExperimentTemplate not found.'"
    )


# ===== helpers =====
def _error(fn):
    """Call fn() and return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises AssertionError: a target accepting a call real AWS refuses must never be mistaken
    for a falsy code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _call_outcome(client):
    """The (code, message) tuple of the error, or the AvailabilityZones list -- never a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        return client.describe_availability_zones()["AvailabilityZones"]
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")


def _create_role(ctx, iam, trust, actions):
    name = ctx.unique_name("sim2real-g1-fisrole-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": trust}),
        Tags=[{"Key": "sim2real", "Value": "g1-fault-injection"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = f"{name}-inline"
    iam.put_role_policy(RoleName=name, PolicyName=policy, PolicyDocument=json.dumps(
        {"Version": "2012-10-17",
         "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy))
    return arn


def _counted_client(ctx, creds, max_attempts, sink):
    """A harness-built EC2 client signing as the TARGETED role, counting its HTTP sends."""
    from botocore.config import Config

    client = ctx.client(
        "ec2",
        config=Config(retries={"mode": "standard", "max_attempts": max_attempts}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    client.meta.events.register("before-send.ec2.*", lambda **kwargs: sink.append(time.time()))
    return client


def _assume(ctx, sts, role_arn, timeout_s):
    """Assume the target role, retrying the IAM trust-policy propagation window. Returns STS's own
    Credentials shape, untouched."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn,
                                   RoleSessionName="sim2real-g1-fault")["Credentials"]
        except ClientError as err:
            last = err.response["Error"]["Code"]
            time.sleep(3)
    raise AssertionError(f"could not assume {role_arn!r} within {timeout_s}s (last code {last!r})")


def _describe_azs_when_permitted(client, timeout_s):
    """The baseline call, retrying only the IAM propagation denial at first use of the permission."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return client.describe_availability_zones()
        except ClientError as err:
            last = err.response["Error"]["Code"]
            if last != "UnauthorizedOperation":
                raise
            time.sleep(3)
    raise AssertionError(f"baseline call never became permitted in {timeout_s}s (last {last!r})")


def _create_template(ctx, fis, role_arn, targets, actions, timeout_s=180.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            template_id = fis.create_experiment_template(
                clientToken=ctx.unique_name("sim2real-g1-tok-"),
                description=ctx.unique_name("sim2real-g1-fis-"),
                stopConditions=[{"source": "none"}],
                targets=targets, actions=actions, roleArn=role_arn,
                tags={"sim2real": "g1-fault-injection"},
            )["experimentTemplate"]["id"]
            ctx.on_cleanup(lambda: _delete_template_quiet(fis, template_id))
            return template_id
        except ClientError as err:
            last = err.response["Error"]["Code"]
            time.sleep(3)
    raise AssertionError(f"CreateExperimentTemplate never succeeded in {timeout_s}s (last {last!r})")


def _delete_template_quiet(fis, template_id):
    from botocore.exceptions import ClientError

    try:
        fis.delete_experiment_template(id=template_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _start_experiment(ctx, fis, template_id, timeout_s=180.0):
    """StartExperiment, retrying the documented transient 'Unable to assume role' window."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            experiment_id = fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-g1-start-"),
                experimentTemplateId=template_id,
                tags={"sim2real": "g1-fault-injection"},
            )["experiment"]["id"]
            ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, experiment_id))
            return experiment_id
        except ClientError as err:
            last = err.response["Error"]["Code"]
            time.sleep(4)
    raise AssertionError(f"StartExperiment never succeeded in {timeout_s}s (last {last!r})")


def _stop_experiment_quiet(fis, experiment_id):
    from botocore.exceptions import ClientError

    try:
        fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # an experiment already in a final state rejects StopExperiment; it needs no stop
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
            raise


def _poll_experiment(fis, experiment_id, stop_on, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if last in stop_on:
            return last
        time.sleep(2)
    return last


def _poll_for_injected_error(client, sink, timeout_s):
    """Wait for the fault to become effective. Measured at 26.5s after state.status == 'running'."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        del sink[:]
        try:
            client.describe_availability_zones()
        except ClientError as err:
            return err
        time.sleep(2)
    raise AssertionError(
        f"the experiment reported 'running' but DescribeAvailabilityZones kept returning 200 for "
        f"{timeout_s}s -- the FIS control plane is not coupled to the EC2 request path"
    )


def _poll_for_recovery(client, sink, timeout_s):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        del sink[:]
        try:
            return client.describe_availability_zones()
        except ClientError as err:
            last = err.response["Error"]["Code"]
            time.sleep(3)
    raise AssertionError(
        f"the call was still failing {timeout_s}s after the experiment completed (last {last!r}) -- "
        "the injected fault was never withdrawn"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
