"""session-lifecycle-create-get-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "session-lifecycle-create-get-delete"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSession reaches READY in GetSession; after DeleteSession GetSession reports
    EntityNotFoundException rather than a STOPPED session, and a repeated DeleteSession on the
    gone id is a no-op.
    """
    glue = ctx.client("glue")
    role_arn = _create_glue_role(ctx)
    session_id = ctx.unique_name("sim2real-behav-session-")

    def _create():
        glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3.9"},
            GlueVersion="3.0",
            WorkerType="G.1X",
            NumberOfWorkers=2,
            Timeout=15,
            IdleTimeout=5,
        )

    _retry_on_role_propagation(_create)
    ctx.on_cleanup(lambda: _stop_session_ignore_missing(glue, session_id))

    session = _poll_until(
        probe=lambda: _get_session_or_none(glue, session_id),
        predicate=lambda s: s is not None and s["Status"] in ("READY", "FAILED", "TIMEOUT"),
        timeout_s=300,
        interval_s=10,
    )
    assert session["Status"] == "READY", f"session reached {session['Status']} instead of READY: {session.get('ErrorMessage')}"
    assert session["Id"] == session_id

    glue.delete_session(Id=session_id)

    gone = _poll_until(
        probe=lambda: _get_session_or_none(glue, session_id),
        predicate=lambda s: s is None,
        timeout_s=180,
        interval_s=10,
    )
    assert gone is None, f"session {session_id} still visible via GetSession after DeleteSession: {gone}"

    _assert_repeat_delete_is_idempotent_noop(glue, session_id)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s; last value={value!r}")


def _retry_on_role_propagation(fn, timeout_s: float = 90.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _assert_repeat_delete_is_idempotent_noop(glue, session_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_session(Id=session_id)
    except ClientError as e:
        raise AssertionError(
            f"repeat DeleteSession on an already-deleted session raised "
            f"{e.response['Error']['Code']!r}; expected an idempotent no-op"
        ) from e


def _get_session_or_none(glue, session_id: str):
    from botocore.exceptions import ClientError

    try:
        return glue.get_session(Id=session_id)["Session"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityNotFoundException":
            return None
        raise


def _stop_session_ignore_missing(glue, session_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_session(Id=session_id)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("EntityNotFoundException", "IllegalSessionStateException"):
            raise


def _create_glue_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-glue-sessrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
