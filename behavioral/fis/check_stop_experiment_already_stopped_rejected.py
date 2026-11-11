"""stop-experiment-already-stopped-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-experiment-already-stopped-rejected"
GROUP = "error-semantics"
SERVICES = ["fis"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """StopExperiment on an experiment that has ALREADY been stopped (a second StopExperiment
    call on the same id, distinct from the naturally-completed case another check covers) is
    rejected, not silently accepted or treated as idempotent."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_wait_template(ctx, role_arn, duration="PT5M")

    resp = _start_with_retry(ctx, fis, template_id)
    experiment_id = resp["experiment"]["id"]
    ctx.on_cleanup(lambda: _safe_stop(ctx, experiment_id))

    _poll_until(
        lambda: fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"],
        lambda s: s == "running",
        timeout_s=90,
        interval_s=3,
    )

    # first stop: succeeds, and an independent read confirms the terminal state
    first_stop_resp = fis.stop_experiment(id=experiment_id)
    assert first_stop_resp["experiment"]["state"]["status"] in ("stopping", "stopped"), (
        f"first StopExperiment expected stopping/stopped, got "
        f"{first_stop_resp['experiment']['state']['status']!r}"
    )
    status_after_first_stop = _poll_until(
        lambda: fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"],
        lambda s: s in ("stopped", "failed", "cancelled", "completed"),
        timeout_s=60,
        interval_s=3,
    )
    assert status_after_first_stop == "stopped", (
        f"expected the experiment to reach stopped, got {status_after_first_stop!r}"
    )

    # second stop on the now-already-stopped experiment: rejected, not idempotent
    code, message = _error(lambda: fis.stop_experiment(id=experiment_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = f"Cannot modify the state of an experiment in final state: {experiment_id}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: an independent read confirms the experiment is still just stopped
    status_after_second_stop = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
    assert status_after_second_stop == "stopped", (
        f"rejected second StopExperiment must not change state, got {status_after_second_stop!r}"
    )

    # positive control: stopping a genuinely running (not-yet-stopped) experiment succeeds,
    # confirmed by an independent read at the terminal state
    template_id2 = _create_wait_template(ctx, role_arn, duration="PT5M")
    resp2 = _start_with_retry(ctx, fis, template_id2)
    experiment_id2 = resp2["experiment"]["id"]
    ctx.on_cleanup(lambda: _safe_stop(ctx, experiment_id2))
    _poll_until(
        lambda: fis.get_experiment(id=experiment_id2)["experiment"]["state"]["status"],
        lambda s: s == "running",
        timeout_s=90,
        interval_s=3,
    )
    stop_resp = fis.stop_experiment(id=experiment_id2)
    assert stop_resp["experiment"]["state"]["status"] in ("stopping", "stopped"), (
        f"positive control StopExperiment expected stopping/stopped, got "
        f"{stop_resp['experiment']['state']['status']!r}"
    )
    final_status = _poll_until(
        lambda: fis.get_experiment(id=experiment_id2)["experiment"]["state"]["status"],
        lambda s: s in ("stopped", "failed", "cancelled", "completed"),
        timeout_s=60,
        interval_s=3,
    )
    assert final_status == "stopped", (
        f"positive control expected the experiment to stop, got {final_status!r}"
    )


# ===== helpers =====

def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    emulator accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _start_with_retry(ctx, fis, template_id, *, timeout_s=60.0):
    """A freshly created IAM role can take a while to propagate before FIS can assume it;
    retry the role-assume failure (not a real experiment outcome) rather than surfacing it."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fis.start_experiment(clientToken=ctx.unique_name("start-"), experimentTemplateId=template_id)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume role" in msg.lower():
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_fis_role(ctx, policy_statements=None):
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fis-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "fis.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]

    def _cleanup_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    if policy_statements:
        policy_name = ctx.unique_name("sim2real-fis-policy-")
        doc = {"Version": "2012-10-17", "Statement": policy_statements}
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))

        def _cleanup_policy():
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        ctx.on_cleanup(_cleanup_policy)
    return role_arn


def _delete_template_safe(ctx, template_id):
    fis = ctx.client("fis")
    try:
        fis.delete_experiment_template(id=template_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_wait_template(ctx, role_arn, *, duration="PT1M", account_targeting=None):
    fis = ctx.client("fis")
    kwargs = dict(
        clientToken=ctx.unique_name("tmpl-"),
        description="sim2real fis behavioral check (wait action)",
        stopConditions=[{"source": "none"}],
        actions={"waitAction": {"actionId": "aws:fis:wait", "parameters": {"duration": duration}}},
        targets={},
        roleArn=role_arn,
    )
    if account_targeting:
        kwargs["experimentOptions"] = {"accountTargeting": account_targeting}

    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = fis.create_experiment_template(**kwargs)
            template_id = resp["experimentTemplate"]["id"]
            ctx.on_cleanup(lambda: _delete_template_safe(ctx, template_id))
            return template_id
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ValidationException", "ResourceNotFoundException"):
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


def _safe_stop(ctx, experiment_id):
    fis = ctx.client("fis")
    try:
        fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # an experiment already in a final state rejects StopExperiment; it needs no stop
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
