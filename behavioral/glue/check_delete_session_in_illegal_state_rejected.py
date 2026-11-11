"""delete-session-in-illegal-state-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-session-in-illegal-state-rejected"
GROUP = "negative-classes"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSession on a session still PROVISIONING raises IllegalSessionStateException and leaves it in
    place; once the same session is READY, DeleteSession succeeds and GetSession then 404s."""
    glue = ctx.client("glue")
    role_arn = _create_glue_session_role(ctx)

    def _create_session():
        session_id = ctx.unique_name("sim2real-sess-")
        _retry_on_role_propagation(
            lambda: glue.create_session(
                Id=session_id,
                Role=role_arn,
                Command={"Name": "glueetl", "PythonVersion": "3"},
                GlueVersion="5.0",
                Tags={"simparity-check": CHECK},
            )
        )

        def _cleanup():
            # DeleteSession refuses a PROVISIONING session, so retry that refusal to a deadline.
            deadline = time.monotonic() + 300.0
            while True:
                try:
                    glue.delete_session(Id=session_id)
                    return
                except ClientError as exc:
                    code = exc.response["Error"]["Code"]
                    if code == "EntityNotFoundException":
                        return
                    if code != "IllegalSessionStateException" or time.monotonic() >= deadline:
                        raise
                time.sleep(2)

        ctx.on_cleanup(_cleanup)
        return session_id

    # The refusal is probed on a session read PROVISIONING right before it; a session already
    # past PROVISIONING is replaced by a fresh one (bounded).
    seen = []
    for _ in range(3):
        session_id = _create_session()
        status = glue.get_session(Id=session_id)["Session"]["Status"]
        if status == "PROVISIONING":
            break
        seen.append(status)
    else:
        raise AssertionError(f"no new session was ever read PROVISIONING; statuses seen: {seen!r}")

    code = _refusal(lambda: glue.delete_session(Id=session_id))
    assert code == ("IllegalSessionStateException", "Session is in PROVISIONING status"), (
        f"expected IllegalSessionStateException, got {code!r}"
    )

    # Effect absent: the session still exists and was not torn down by the
    # rejected delete.
    status_after_reject = glue.get_session(Id=session_id)["Session"]["Status"]
    assert status_after_reject in ("PROVISIONING", "READY"), (
        f"expected PROVISIONING or READY after rejected delete, got {status_after_reject!r}"
    )

    # Positive control: once the session reaches READY, deleting it
    # succeeds.
    _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"]["Status"],
        lambda status: status in ("READY", "FAILED", "TIMEOUT"),
        timeout_s=300,
        interval_s=10,
    )
    ready_status = glue.get_session(Id=session_id)["Session"]["Status"]
    assert ready_status == "READY", f"session never became READY (got {ready_status!r})"

    glue.delete_session(Id=session_id)
    final_code = _poll_until(
        lambda: _outcome(lambda: glue.get_session(Id=session_id)),
        lambda outcome: outcome != _SUCCEEDED,
        timeout_s=60,
        interval_s=5,
    )
    assert final_code == ("EntityNotFoundException", f"Session {session_id} not found."), (
        f"expected EntityNotFoundException, got {final_code!r}"
    )


# ===== helpers =====
_SUCCEEDED = ("<call succeeded>", "")


def _outcome(fn):
    """Return the (code, message) of the ClientError fn raises, or _SUCCEEDED (a value no
    error code equals) when the call is accepted."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _SUCCEEDED


def _refusal(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    outcome = _outcome(fn)
    if outcome == _SUCCEEDED:
        raise AssertionError("expected a ClientError, but the call succeeded")
    return outcome


def _retry_on_role_propagation(fn, *, timeout_s: float = 90.0, interval_s: float = 5.0):
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
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


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
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
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
