"""session-timestamp-precision-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "session-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The CreatedOn timestamp returned by CreateSession is the exact same value (to
    sub-second precision) when read back moments later via GetSession -- an emulator
    that re-derives the timestamp per call (or truncates to whole seconds) will disagree."""
    glue = ctx.client("glue")
    role_arn = _create_glue_role(ctx)

    session_id = ctx.unique_name("sim2real-behav-sess-")
    created = _create_session_with_retry(
        glue,
        Id=session_id,
        Role=role_arn,
        Command={"Name": "glueetl", "PythonVersion": "3"},
        GlueVersion="4.0",
        NumberOfWorkers=2,
        WorkerType="G.1X",
        IdleTimeout=5,
    )
    create_created_on = created["Session"]["CreatedOn"]

    def _cleanup_fallback():
        # Best-effort only: DeleteSession rejects a session still PROVISIONING
        # (IllegalSessionStateException), and the on_cleanup budget is too tight to
        # wait out real AWS's 1-3 minute provisioning here. The normal path deletes
        # the session below, in-body, under the check's larger timeout; this fallback
        # only matters if the body raises before reaching that point, and the
        # session's own IdleTimeout bounds the worst case regardless.
        from botocore.exceptions import ClientError

        try:
            glue.delete_session(Id=session_id)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") not in (
                "EntityNotFoundException",
                "IllegalSessionStateException",
            ):
                raise

    ctx.on_cleanup(_cleanup_fallback)

    fetched = glue.get_session(Id=session_id)
    get_created_on = fetched["Session"]["CreatedOn"]

    assert create_created_on == get_created_on, (
        f"CreatedOn differs between CreateSession ({create_created_on!r}) and "
        f"GetSession ({get_created_on!r}) moments later"
    )

    status = _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"]["Status"],
        lambda status: status in {"READY", "FAILED", "TIMEOUT", "STOPPED"},
        timeout_s=240.0,
        interval_s=5.0,
    )
    if status in ("READY", "STOPPED"):
        glue.delete_session(Id=session_id)


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sessrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    )
    return role_arn


def _create_session_with_retry(glue, *, max_attempts=6, retry_interval_s=5.0, **kwargs):
    from botocore.exceptions import ClientError

    last_error = None
    for _ in range(max_attempts):
        try:
            return glue.create_session(**kwargs)
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "InvalidInputException"):
                last_error = err
                time.sleep(retry_interval_s)
                continue
            raise
    raise last_error


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
