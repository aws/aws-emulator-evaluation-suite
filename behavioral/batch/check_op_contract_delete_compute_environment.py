"""op-contract-deleteComputeEnvironment."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteComputeEnvironment"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteComputeEnvironment removes a DISABLED CE, but is rejected while the CE is
    still ENABLED (positive control shows the same delete succeeds once disabled)."""
    batch = ctx.client("batch")

    # Negative: an ENABLED compute environment cannot be deleted.
    enabled_ce = _create_unmanaged_ce_no_cleanup(ctx)
    code, message = _error(lambda: batch.delete_compute_environment(computeEnvironment=enabled_ce["name"]))
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    expected_message = "Cannot delete an enabled compute environment, set the state to DISABLED first."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    still_there = batch.describe_compute_environments(computeEnvironments=[enabled_ce["name"]])["computeEnvironments"]
    assert len(still_there) == 1 and still_there[0]["state"] == "ENABLED", "CE must not have been deleted"

    # Positive control: disabling first lets the identical delete call succeed.
    batch.update_compute_environment(computeEnvironment=enabled_ce["name"], state="DISABLED")
    _poll_ce_status(ctx, enabled_ce["name"], {"VALID", "INVALID"})
    batch.delete_compute_environment(computeEnvironment=enabled_ce["name"])
    deleted = _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[enabled_ce["name"]])["computeEnvironments"],
        lambda ces: len(ces) == 0,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert deleted == [], f"expected the deleted compute environment to be gone, still describing: {deleted!r}"

    # Deletes prove gone AND unusable: a mutation on the dead id must also fail.
    dead_code, dead_message = _error(
        lambda: batch.update_compute_environment(computeEnvironment=enabled_ce["name"], state="DISABLED")
    )
    assert dead_code == "ClientException", (
        f"expected ClientException updating a deleted compute environment, got {dead_code!r}"
    )
    expected_dead = f"{enabled_ce['arn']} does not exist"
    assert dead_message == expected_dead, f"expected message {expected_dead!r}, got {dead_message!r}"


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator accepting a call real AWS refuses must not be reported as an
    error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _poll_ce_status(ctx, name, target_statuses, timeout_s=90.0):
    batch = ctx.client("batch")

    def probe():
        r = batch.describe_compute_environments(computeEnvironments=[name])
        ces = r["computeEnvironments"]
        return ces[0] if ces else None

    return _poll_until(
        probe, lambda ce: ce is not None and ce["status"] in target_statuses, timeout_s=timeout_s, interval_s=2.0
    )


def _create_batch_service_role(ctx) -> str:
    """Real AWS Batch requires an explicit serviceRole for CreateComputeEnvironment (even
    for UNMANAGED environments) unless the account already has one on file; create a
    minimal one inline."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-svcrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "batch.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _detach_role_policy(ctx, role_name, policy_arn))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _detach_role_policy(ctx, role_name: str, policy_arn: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_compute_environment_with_role(ctx, name: str, service_role_arn: str, timeout_s: float = 60.0):
    """A freshly-created IAM role can take a few seconds to be assumable by batch.amazonaws.com;
    poll by retrying the create call itself rather than sleeping blindly."""
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return batch.create_compute_environment(
                computeEnvironmentName=name,
                type="UNMANAGED",
                state="ENABLED",
                serviceRole=service_role_arn,
                tags={"sim2real:managed": "true"},
            )
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    raise last_exc


#: The suite's cleanup budget; the retries of every teardown of one run share one deadline in it.
_CLEANUP_BUDGET_S = 900.0
_cleanup_deadlines: dict[int, tuple[object, float]] = {}


def _teardown_ce(ctx, batch, name):
    """Disable and delete the compute environment, then wait until DescribeComputeEnvironments no
    longer lists it: the service role torn down after it must outlive the asynchronous delete.
    ClientException refusals (a queue still detaching, the CE still updating) retry every 2 s."""
    held = _cleanup_deadlines.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _cleanup_deadlines[id(ctx)] = (ctx, time.monotonic() + _CLEANUP_BUDGET_S)
    deadline = held[1]
    steps = [
        lambda: batch.update_compute_environment(computeEnvironment=name, state="DISABLED"),
        lambda: batch.delete_compute_environment(computeEnvironment=name),
    ]
    while True:
        listed = [
            ce
            for ce in batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
            if ce.get("status") != "DELETED"
        ]
        if not listed:
            return
        if steps and listed[0].get("status") != "DELETING":
            try:
                steps[0]()
                steps.pop(0)
                continue
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                    return
                if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                    raise
        elif time.monotonic() >= deadline:
            raise TimeoutError(f"compute environment {name} still listed at the cleanup deadline")
        time.sleep(2)


def _create_unmanaged_ce_no_cleanup(ctx) -> dict[str, Any]:
    """The check itself drives this CE through disable->delete as its own assertions;
    a safety-net cleanup is still registered in case an assertion fails first."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-ce-")
    service_role_arn = _create_batch_service_role(ctx)
    resp = _create_compute_environment_with_role(ctx, name, service_role_arn)

    ctx.on_cleanup(lambda: _teardown_ce(ctx, batch, name))
    _poll_ce_status(ctx, name, {"VALID"})
    return {"name": name, "arn": resp["computeEnvironmentArn"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
