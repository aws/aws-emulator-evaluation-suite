"""concurrent-identity-center-configuration-create-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-identity-center-configuration-create-rejected"
GROUP = "concurrency"
SERVICES = ["glue"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Two concurrent CreateGlueIdentityCenterConfiguration calls for the account singleton: exactly
    one creates it and the other is refused with ConcurrentModificationException or
    AlreadyExistsException (exact message); a later create is refused as AlreadyExistsException."""

    instance_arn = _identity_center_instance_arn(ctx)

    glue = ctx.client("glue")
    try:
        glue.get_glue_identity_center_configuration()
    except ClientError as err:
        existing = err.response["Error"]["Code"]
        existing_message = err.response["Error"].get("Message")
    else:
        raise AssertionError(
            "a Glue Identity Center configuration already exists for this account; this "
            "singleton check requires a clean account to exercise the create-vs-create race"
        )
    assert existing == "EntityNotFoundException", (
        f"expected EntityNotFoundException on a clean account, got {existing!r}"
    )
    assert existing_message == "Idc application not found. Need to create glue application first.", (
        f"unexpected GetGlueIdentityCenterConfiguration message: {existing_message!r}"
    )

    def _create():
        return glue.create_glue_identity_center_configuration(InstanceArn=instance_arn)

    results = _race([_create, _create])
    successes = [r for r, c, _ in results if c is None]
    failures = [c for _, c, _ in results if c is not None]
    failure_messages = [m for _, c, m in results if c is not None]

    application_arn = None
    try:
        assert len(successes) == 1, f"expected exactly one success, got results={results}"
        application_arn = successes[0]["ApplicationArn"]
        assert len(failures) == 1, f"expected exactly one refused create, got {results}"
        # A loser overlapping the winner's creation is refused as a concurrent modification; one
        # that runs after the winner committed is refused as a duplicate of it.
        expected = {
            "ConcurrentModificationException": "Concurrent modification when creating glue Idc application",
            "AlreadyExistsException": f"Glue Idc Application already exists. ApplicationArn: {application_arn}",
        }
        assert failures[0] in expected, f"undocumented racing create refusal: {failures[0]!r} ({failure_messages[0]!r})"
        assert failure_messages[0] == expected[failures[0]], (
            f"unexpected racing CreateGlueIdentityCenterConfiguration {failures[0]} message: {failure_messages[0]!r}"
        )

        got = glue.get_glue_identity_center_configuration()
        assert got["ApplicationArn"] == application_arn, (
            f"expected the winning ApplicationArn {application_arn!r}, got {got['ApplicationArn']!r}"
        )
        assert got["InstanceArn"] == instance_arn, (
            f"expected InstanceArn {instance_arn!r}, got {got['InstanceArn']!r}"
        )

        # Once the singleton exists, a further sequential create is refused as a duplicate.
        code, message = _error(lambda: glue.create_glue_identity_center_configuration(InstanceArn=instance_arn))
        assert code == "AlreadyExistsException", code
        assert message == f"Glue Idc Application already exists. ApplicationArn: {application_arn}", f"unexpected CreateGlueIdentityCenterConfiguration message: {message!r}"
    finally:
        _safe(lambda: glue.delete_glue_identity_center_configuration())


# ===== helpers =====
def _safe(fn):
    try:
        fn()
    except ClientError:
        pass


def _race(fns):
    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(fn) for fn in fns]
        results = []
        for fut in futures:
            try:
                results.append((fut.result(), None, None))
            except ClientError as exc:
                results.append((None, exc.response["Error"]["Code"], exc.response["Error"].get("Message")))
    return results


def _wait_s(ctx, cap_s):
    """cap_s, shortened so the wait ends before the runner's budget does."""
    left = ctx.time_left()
    if left is None:
        return cap_s
    return max(1.0, min(cap_s, left - 10.0))


def _identity_center_instance_arn(ctx) -> str:
    """The account's IAM Identity Center instance ARN, creating one if none exists.

    `sso-admin:CreateInstance` provisions a STANDALONE (non-Organizations) instance, so the
    prerequisite is satisfiable in-check and an account without an instance does not block the
    check.
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
    deadline = time.time() + _wait_s(ctx, 120)
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
