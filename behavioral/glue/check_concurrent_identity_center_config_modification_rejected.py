"""concurrent-identity-center-config-modification-rejected."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-identity-center-config-modification-rejected"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Racing CreateGlueIdentityCenterConfiguration calls for the account singleton are serialized:
    exactly one creates it and every other is rejected with ConcurrentModificationException or
    AlreadyExistsException; a sequential delete then leaves it truly gone."""
    instance_arn = _identity_center_instance_arn(ctx)

    glue = ctx.client("glue")
    # A pre-existing account-wide configuration is refused up front rather than race-modified.
    try:
        glue.get_glue_identity_center_configuration()
    except ClientError as e:
        existing_code = e.response["Error"]["Code"]
        existing_message = e.response["Error"].get("Message")
    else:
        raise AssertionError(
            "this account already has a Glue Identity Center configuration; refusing to "
            "race-modify an account-wide configuration that may be in real use"
        )
    assert existing_code == "EntityNotFoundException", existing_code
    assert existing_message == "Idc application not found. Need to create glue application first.", (
        f"unexpected GetGlueIdentityCenterConfiguration message: {existing_message!r}"
    )

    ctx.on_cleanup(lambda: _safe_call(lambda: glue.delete_glue_identity_center_configuration()))

    def make_call():
        def _call():
            return glue.create_glue_identity_center_configuration(InstanceArn=instance_arn)

        return _call

    racers = 6
    outcomes = _race([make_call() for _ in range(racers)])

    successes = [o for o in outcomes if o["error"] is None]
    failures = [o for o in outcomes if o["error"] is not None]
    assert len(successes) == 1, f"expected exactly one racer to create the configuration, got {outcomes}"
    assert len(failures) == racers - 1, f"expected every other racer to be rejected, got {outcomes}"
    application_arn = successes[0]["result"]["ApplicationArn"]
    # A racer that overlaps the winner's creation lock is refused as a concurrent modification;
    # one that arrives after the winner committed is refused as a duplicate of it.
    expected = {
        "ConcurrentModificationException": "Concurrent modification when creating glue Idc application",
        "AlreadyExistsException": f"Glue Idc Application already exists. ApplicationArn: {application_arn}",
    }
    for f in failures:
        assert f["error"] in expected, f"unexpected rejection code {f['error']!r}"
        assert f["message"] == expected[f["error"]], (
            f"unexpected CreateGlueIdentityCenterConfiguration {f['error']} message: {f['message']!r}"
        )

    # the configuration that was actually created is real, not a phantom of a lost race
    cfg = glue.get_glue_identity_center_configuration()
    assert cfg["ApplicationArn"], "winning racer's configuration has no ApplicationArn"

    glue.delete_glue_identity_center_configuration()
    code_after_delete, message_after_delete = _error(lambda: glue.get_glue_identity_center_configuration())
    assert code_after_delete == "EntityNotFoundException", code_after_delete
    assert message_after_delete == "Idc application not found. Need to create glue application first.", (
        f"unexpected GetGlueIdentityCenterConfiguration message: {message_after_delete!r}"
    )



def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises rather than
    reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _race(calls: list) -> list:
    n = len(calls)
    barrier = threading.Barrier(n)
    outcomes: list = [None] * n

    def worker(i: int, fn) -> None:
        barrier.wait()
        try:
            outcomes[i] = {"result": fn(), "error": None, "message": None}
        except ClientError as e:
            outcomes[i] = {
                "result": None,
                "error": e.response["Error"]["Code"],
                "message": e.response["Error"].get("Message"),
            }

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(worker, i, fn) for i, fn in enumerate(calls)]
        for f in futures:
            f.result()
    return outcomes


def _identity_center_instance_arn(ctx) -> str:
    """The account's IAM Identity Center instance ARN, creating one if none exists.

    `sso-admin:CreateInstance` provisions a standalone (non-Organizations) instance, so the
    prerequisite is satisfiable in-check.
    """
    import time

    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        # Exactly one instance is allowed per account, and deleting it would disrupt any other
        # check relying on it, so one created here is deliberately never torn down.
        instance_arn = sso.create_instance()["InstanceArn"]
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(
        f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
