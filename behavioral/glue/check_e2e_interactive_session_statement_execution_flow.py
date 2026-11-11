"""e2e-interactive-session-statement-execution-flow."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "e2e-interactive-session-statement-execution-flow"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A statement submitted to a Glue interactive session actually executes on a real
    Spark REPL: the polled GetStatement result contains the real computed output
    before the session is torn down, and the session is confirmed gone afterward."""
    glue = ctx.client("glue")
    role_arn = _create_glue_role(ctx)

    session_id = ctx.unique_name("sim2real-session-")
    _retry_role_propagation(
        lambda: glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3"},
            GlueVersion="4.0",
            WorkerType="G.1X",
            NumberOfWorkers=2,
            Timeout=15,
            IdleTimeout=10,
            Tags={"sim2real": CHECK},
        )
    )
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_session(Id=session_id), f"glue session {session_id}"))

    session = _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"],
        lambda s: s["Status"] in ("READY", "FAILED", "TIMEOUT"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert session["Status"] == "READY", f"session did not become READY: {session}"

    # Two runtime-random factors: no recording, and no stub answering a fixed literal like "42", can
    # carry the product across runs.
    factor_a = random.randint(1000, 9999)
    factor_b = random.randint(1000, 9999)
    expected = str(factor_a * factor_b)
    run_resp = glue.run_statement(SessionId=session_id, Code=f"print({factor_a} * {factor_b})")
    statement_id = run_resp["Id"]

    statement = _poll_until(
        lambda: glue.get_statement(SessionId=session_id, Id=statement_id)["Statement"],
        lambda s: s["State"] in ("AVAILABLE", "ERROR", "CANCELLED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert statement["State"] == "AVAILABLE", f"statement did not complete: {statement}"
    text_output = statement["Output"]["Data"]["TextPlain"]
    assert text_output.strip() == expected, (
        f"expected computed output {expected!r} from {factor_a} * {factor_b}, got: {text_output!r}"
    )

    glue.delete_session(Id=session_id)
    assert _session_gone(glue, session_id), (
        f"GetSession still resolves {session_id!r} after DeleteSession returned; "
        "the delete was acknowledged but not performed"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={last!r})")


def _session_gone(glue, session_id, *, timeout_s=180.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            glue.get_session(Id=session_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "EntityNotFoundException":
                return True
            raise
        time.sleep(interval_s)
    return False


def _retry_delete(fn, label, *, timeout_s=120.0):
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions:
    a throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "ResourceNotFoundException")
    transient = (
        "ThrottlingException",
        "Throttling",
        "TooManyRequestsException",
        "OperationTimeoutException",
        "ConcurrentModificationException",
        "IllegalSessionStateException",
        "DeleteConflict",
        "RequestLimitExceeded",
    )
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)
        except Exception as exc:  # noqa: BLE001 - re-raised
            raise RuntimeError(f"{label}: {type(exc).__name__}: {exc}") from exc


def _retry_role_propagation(fn, *, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException"):
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("retry_role_propagation exhausted without an error to raise")


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-session-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _retry_delete(lambda: iam.delete_role(RoleName=role_name), f"iam role {role_name}"))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
            f"detach {policy_arn} from {role_name}",
        )
    )
    return role["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
