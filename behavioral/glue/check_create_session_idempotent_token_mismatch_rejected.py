"""create-session-idempotent-token-mismatch-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-session-idempotent-token-mismatch-rejected"
GROUP = "negative-classes"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateSession reusing an existing session Id with different parameters is rejected with
    AlreadyExistsException and leaves the original session unchanged; a fresh Id still creates normally."""
    glue = ctx.client("glue")
    role_arn = _create_glue_session_role(ctx)

    session_id = ctx.unique_name("sim2real-sess-")
    _retry_until_role_usable(
        lambda: glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3"},
            GlueVersion="5.0",
            NumberOfWorkers=2,
            WorkerType="G.1X",
            Tags={"sim2real:managed": "true"},
        )
    )
    ctx.on_cleanup(lambda: _best_effort_stop_and_delete_session(ctx, glue, session_id))

    original = glue.get_session(Id=session_id)["Session"]
    assert original["NumberOfWorkers"] == 2, f"expected NumberOfWorkers=2, got {original!r}"

    code, message = _error(
        lambda: glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3"},
            GlueVersion="5.0",
            NumberOfWorkers=10,
            WorkerType="G.1X",
        )
    )
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code!r}"
    expected_message = f"Session already created, sessionId={session_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected create did not mutate the existing
    # session's worker count.
    unchanged = glue.get_session(Id=session_id)["Session"]
    assert unchanged["NumberOfWorkers"] == 2, (
        f"expected NumberOfWorkers to remain 2 after the rejected create, got {unchanged!r}"
    )

    # Positive control: a fresh, distinct Id is accepted normally.
    other_id = ctx.unique_name("sim2real-sess-ctrl-")
    glue.create_session(
        Id=other_id,
        Role=role_arn,
        Command={"Name": "glueetl", "PythonVersion": "3"},
        GlueVersion="5.0",
        NumberOfWorkers=2,
        WorkerType="G.1X",
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _best_effort_stop_and_delete_session(ctx, glue, other_id))
    created = glue.get_session(Id=other_id)["Session"]
    assert created["Id"] == other_id, f"expected Id={other_id!r}, got {created!r}"
    assert created["NumberOfWorkers"] == 2, (
        f"expected the fresh Id's own params to be honored, got {created!r}"
    )


# ===== helpers =====
def _error(fn):
    """Return (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _retry_until_role_usable(fn, *, timeout_s: float = 150.0, interval_s: float = 10.0):
    """Retry fn() while Glue reports the just-created role as not yet assumable.

    IAM role/policy propagation to Glue lags create_role/attach_role_policy by a few
    seconds; that lag, not an unconditional sleep, is the thing being waited out.
    """
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("AccessDeniedException", "InvalidInputException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    last_detail = last_exc.response.get("Error", {}) if last_exc is not None else {}
    raise AssertionError(
        f"role never became usable within {timeout_s}s; last error "
        f"{last_detail.get('Code')}: {last_detail.get('Message')}"
    ) from last_exc


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _best_effort_stop_and_delete_session(ctx, glue, session_id: str) -> None:
    # A session still PROVISIONING cannot be deleted: wait for a deletable state, then delete.
    try:
        _poll_until(
            lambda: glue.get_session(Id=session_id)["Session"]["Status"],
            lambda status: status in ("READY", "FAILED", "TIMEOUT", "STOPPED"),
            timeout_s=300,
            interval_s=2,
        )
        glue.delete_session(Id=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _create_glue_session_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-sess-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
