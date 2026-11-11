"""start-experiment-service-quota-exceeded."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-experiment-service-quota-exceeded"
GROUP = "concurrency"
SERVICES = ["fis"]

# Per https://docs.aws.amazon.com/fis/latest/userguide/fis-quotas.html the
# "Active experiments" quota is a fixed (non-adjustable) 5 per account per region.
ACTIVE_EXPERIMENTS_QUOTA = 5

_QUOTA_MESSAGE = f"The number of active experiments cannot exceed {ACTIVE_EXPERIMENTS_QUOTA}."

_ACTIVE_STATUSES = {"pending", "initiating", "running", "stopping"}
_TERMINAL_STATUSES = {"completed", "stopped", "failed", "cancelled"}


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """A StartExperiment over the active-experiment quota raises ServiceQuotaExceededException and
    creates nothing, and stopping an active experiment frees a slot for the identical call."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)

    started_ids: list[str] = []
    last_error_code: str | None = None
    last_error_message: str | None = None
    rejected_template_id: str | None = None

    for _ in range(ACTIVE_EXPERIMENTS_QUOTA + 1):
        template_id = _create_wait_template(ctx, fis, role_arn)
        try:
            experiment = _start_experiment_with_retry(fis, ctx, template_id)
        except ClientError as exc:
            last_error_code = exc.response["Error"]["Code"]
            last_error_message = exc.response["Error"].get("Message", "")
            rejected_template_id = template_id
            break
        eid = experiment["id"]
        started_ids.append(eid)
        ctx.on_cleanup(lambda e=eid: _best_effort_stop(fis, e))

    assert last_error_code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException after filling the active-experiment "
        f"quota, got {last_error_code!r} having started {len(started_ids)} experiment(s) "
        f"against a quota of {ACTIVE_EXPERIMENTS_QUOTA}"
    )
    assert last_error_message == _QUOTA_MESSAGE, (
        f"expected FIS's exact quota refusal {_QUOTA_MESSAGE!r}, got {last_error_message!r}"
    )

    # effect absent, via an independent read scoped to the template this check owns: the
    # rejected StartExperiment must not have created a partial experiment from it.
    from_rejected = _experiments_of_template(fis, rejected_template_id)
    assert from_rejected == [], (
        f"expected no experiment from the rejected template {rejected_template_id!r}, "
        f"got {from_rejected!r}"
    )
    for eid in started_ids:
        status = _experiment_status(fis, eid)
        assert status in _ACTIVE_STATUSES, (
            f"expected experiment {eid} that filled the quota to still be active after the "
            f"rejection, got {status!r}"
        )

    # restore: stop one of the experiments that filled the quota, freeing a slot, then
    # demand the identical call (fresh template + StartExperiment) now succeeds.
    assert started_ids, "no experiment was started to free a slot from for the restore leg"
    freed_id = started_ids.pop()
    _stop_and_wait_stopped(fis, freed_id)

    retry_template_id = _create_wait_template(ctx, fis, role_arn)
    retried = _start_once_slot_frees(fis, ctx, retry_template_id)
    retried_id = retried["id"]
    ctx.on_cleanup(lambda e=retried_id: _best_effort_stop(fis, e))
    assert retried["state"]["status"] in _ACTIVE_STATUSES, (
        f"expected the identical StartExperiment to succeed into an active status once "
        f"a slot was freed, got state {retried['state']!r}"
    )

    from_retry = [e["id"] for e in _experiments_of_template(fis, retry_template_id)]
    assert from_retry == [retried_id], (
        f"expected exactly the retried experiment {retried_id!r} from its template, got {from_retry!r}"
    )
    for eid in started_ids:
        status = _experiment_status(fis, eid)
        assert status in _ACTIVE_STATUSES, (
            f"expected experiment {eid} to stay active across the restore, got {status!r}"
        )


# ===== helpers =====

def _create_fis_role(ctx, policy_statements: list[dict[str, Any]] | None = None) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fis-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if policy_statements:
        policy_name = ctx.unique_name("sim2real-fis-policy-")
        iam.put_role_policy(
            RoleName=name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return role_arn


def _create_experiment_template(ctx, fis, **kwargs) -> dict[str, Any]:
    # A freshly created IAM role can take a few seconds to become visible to FIS's
    # cross-service roleArn validation; retry on ResourceNotFoundException.
    deadline = time.monotonic() + 45.0
    while True:
        try:
            return fis.create_experiment_template(**kwargs)["experimentTemplate"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException" and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise


def _create_wait_template(ctx, fis, role_arn: str) -> str:
    template = _create_experiment_template(
        ctx,
        fis,
        clientToken=ctx.unique_name("sim2real-fis-tok-"),
        description="sim2real fis active-experiment quota concurrency check",
        stopConditions=[{"source": "none"}],
        actions={"wait1": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT5M"}}},
        targets={},
        roleArn=role_arn,
        tags={"sim2real-check": CHECK},
    )
    template_id = template["id"]
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))
    return template_id


def _experiments_of_template(fis, template_id: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"maxResults": 100, "experimentTemplateId": template_id}
        if token:
            kwargs["nextToken"] = token
        resp = fis.list_experiments(**kwargs)
        found.extend(resp.get("experiments", []))
        token = resp.get("nextToken")
        if not token:
            break
    return found


def _experiment_status(fis, experiment_id: str) -> str:
    return fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]


def _best_effort_stop(fis, experiment_id: str) -> None:
    try:
        fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # an experiment already in a final state rejects StopExperiment; it needs no stop
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
            raise


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _stop_and_wait_stopped(fis, experiment_id: str, *, timeout_s: float = 60.0) -> None:
    fis.stop_experiment(id=experiment_id)

    def _status() -> str:
        return fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]

    status = _poll_until(_status, lambda s: s in _TERMINAL_STATUSES, timeout_s=timeout_s)
    assert status == "stopped", (
        f"expected experiment {experiment_id} to reach terminal status 'stopped' after "
        f"StopExperiment (to free its active-experiment quota slot), got {status!r}"
    )


def _start_experiment_with_retry(fis, ctx, template_id: str, deadline_s: float = 45.0) -> dict[str, Any]:
    # A freshly created IAM role can take a few seconds to propagate before FIS's
    # STS AssumeRole succeeds; retry on the transient "Unable to assume role" error.
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-fis-tok-"),
                experimentTemplateId=template_id,
            )["experiment"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (
                err["Code"] == "ValidationException"
                and "unable to assume role" in err.get("Message", "").lower()
                and time.monotonic() < deadline
            ):
                time.sleep(3.0)
                continue
            raise


def _start_once_slot_frees(fis, ctx, template_id: str, timeout_s: float = 60.0) -> dict[str, Any]:
    """StartExperiment, retried every 2 s while the quota refusal persists: a stopped experiment
    releases its slot once its stop settles."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))
    while True:
        try:
            return _start_experiment_with_retry(fis, ctx, template_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ServiceQuotaExceededException":
                raise
            if time.monotonic() >= deadline:
                left = ctx.time_left()
                if left is not None and left <= 6.0:
                    raise TimeoutError("run budget ended before the freed slot was released; not graded") from exc
                raise
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
