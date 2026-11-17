"""delete-secret-refuses-namespace-managed-admin-password-secret."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-secret-refuses-namespace-managed-admin-password-secret"
GROUP = "ownership"
SERVICES = ["redshift-serverless", "secretsmanager"]

_OWNING_SERVICE = "redshift"
_SECRET_OWNED_BY_SERVICE = (
    "InvalidRequestException",
    f"Operation is not allowed on secret owned by {_OWNING_SERVICE}",
)


def _teardown(undo, *not_found: str):
    """Cleanup running undo(); only the resource's own not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _namespace_or_absent(rss, name: str):
    try:
        return rss.get_namespace(namespaceName=name)["namespace"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _wait_available(rss, name: str, deadline: float, interval_s: float = 5.0) -> dict:
    last = None
    while time.monotonic() < deadline:
        last = _namespace_or_absent(rss, name)
        if last is not None and last["status"] == "AVAILABLE":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"namespace {name!r} never reached AVAILABLE; last={last!r}")


def _delete_namespace(rss, name: str, deadline: float, interval_s: float = 5.0) -> None:
    while True:
        try:
            rss.delete_namespace(namespaceName=name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        if _namespace_or_absent(rss, name) is None:
            return
        time.sleep(interval_s)
    raise AssertionError(f"namespace {name!r} still present after DeleteNamespace")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteSecret on the Secrets Manager secret backing a namespace's managed admin password is
    refused as owned by another service; an ordinary secret under the same caller deletes.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html
    """
    rss = ctx.client("redshift-serverless")
    sm = ctx.client("secretsmanager")
    deadline = time.monotonic() + 280.0

    namespace_name = ctx.unique_name("sim2real-behav-rssdelsec-")
    created = rss.create_namespace(
        namespaceName=namespace_name, adminUsername="admin1", manageAdminPassword=True
    )["namespace"]
    ctx.on_cleanup(lambda: _delete_namespace(rss, namespace_name, time.monotonic() + 50.0))

    namespace = created if created.get("status") == "AVAILABLE" else _wait_available(
        rss, namespace_name, deadline
    )
    managed_secret_arn = namespace.get("adminPasswordSecretArn")
    assert managed_secret_arn, (
        f"an AVAILABLE managed-password namespace must carry adminPasswordSecretArn, got "
        f"{namespace!r}"
    )

    described = sm.describe_secret(SecretId=managed_secret_arn)
    assert described["OwningService"] == _OWNING_SERVICE, (
        f"expected the managed secret's OwningService to be {_OWNING_SERVICE!r}, got "
        f"{described.get('OwningService')!r}"
    )

    expect_error(
        lambda: sm.delete_secret(SecretId=managed_secret_arn, ForceDeleteWithoutRecovery=True),
        *_SECRET_OWNED_BY_SERVICE,
    )

    still_described = sm.describe_secret(SecretId=managed_secret_arn)
    assert still_described.get("DeletedDate") is None, (
        f"the refused DeleteSecret must leave the managed secret undeleted, got DeletedDate="
        f"{still_described.get('DeletedDate')!r}"
    )

    # Positive control: an ordinary secret under the same caller, unrelated to any service, deletes.
    ordinary_name = ctx.unique_name("sim2real-behav-rssdelsec-ordinary-")
    ordinary_arn = sm.create_secret(Name=ordinary_name, SecretString="placeholder-value")["ARN"]
    ctx.on_cleanup(
        _teardown(
            lambda: sm.delete_secret(SecretId=ordinary_arn, ForceDeleteWithoutRecovery=True),
            "ResourceNotFoundException",
        )
    )

    ordinary_before = sm.describe_secret(SecretId=ordinary_arn)
    assert "OwningService" not in ordinary_before, (
        f"an ordinary secret must carry no OwningService, got "
        f"{ordinary_before.get('OwningService')!r}"
    )

    deleted = sm.delete_secret(SecretId=ordinary_arn)
    assert deleted["ARN"] == ordinary_arn, (
        f"DeleteSecret must echo the deleted secret's arn, got {deleted.get('ARN')!r}"
    )

    ordinary_after = sm.describe_secret(SecretId=ordinary_arn)
    assert ordinary_after.get("DeletedDate") is not None, (
        f"an ordinary secret must be scheduled for deletion after DeleteSecret, got DeletedDate="
        f"{ordinary_after.get('DeletedDate')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
