"""namespace-managed-admin-password-yields-describable-secret."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "namespace-managed-admin-password-yields-describable-secret"
GROUP = "representation"
SERVICES = ["redshift-serverless", "secretsmanager"]


def _code(exc: ClientError) -> str:
    return exc.response["Error"]["Code"]


def _namespace_or_absent(rss, name: str):
    try:
        return rss.get_namespace(namespaceName=name)["namespace"]
    except ClientError as exc:
        if _code(exc) == "ResourceNotFoundException":
            return None
        raise


def _wait_available(rss, name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _namespace_or_absent(rss, name)
        if last is not None and last["status"] == "AVAILABLE":
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"namespace {name!r} never reached AVAILABLE within {timeout_s:.0f}s; last={last!r}"
    )


def _delete_namespace(rss, name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    """Issue DeleteNamespace until it is accepted, then wait until GetNamespace reports it gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rss.delete_namespace(namespaceName=name)
            break
        except ClientError as exc:
            code = _code(exc)
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    while time.monotonic() < deadline:
        if _namespace_or_absent(rss, name) is None:
            return
        time.sleep(interval_s)
    raise AssertionError(f"namespace {name!r} still present {timeout_s:.0f}s after DeleteNamespace")


def _confirm_secret_scheduled_or_gone(
    sm, secret_arn: str, timeout_s: float = 60.0, interval_s: float = 2.0
) -> None:
    """DeleteNamespace schedules its managed secret's deletion as part of the same call; confirm
    that happened rather than leave a leaked secret unreported."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            described = sm.describe_secret(SecretId=secret_arn)
        except ClientError as exc:
            if _code(exc) == "ResourceNotFoundException":
                return
            raise
        if described.get("DeletedDate") is not None:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"secret {secret_arn!r} was not scheduled for deletion within {timeout_s:.0f}s of "
        f"DeleteNamespace"
    )


def _cleanup(rss, sm, name: str, state: dict) -> None:
    _delete_namespace(rss, name)
    secret_arn = state.get("secret_arn")
    if secret_arn:
        _confirm_secret_scheduled_or_gone(sm, secret_arn)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNamespace with manageAdminPassword and no adminUserPassword yields, once AVAILABLE, an
    adminPasswordSecretArn naming a same-account, same-region Secrets Manager secret that
    DescribeSecret resolves.

    Reference: https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_CreateNamespace.html
    """
    rss = ctx.client("redshift-serverless")
    sm = ctx.client("secretsmanager")

    name = ctx.unique_name("sim2real-behav-rssmgdsec-")
    state: dict = {"secret_arn": None}
    created = rss.create_namespace(
        namespaceName=name, adminUsername="admin1", manageAdminPassword=True
    )["namespace"]
    ctx.on_cleanup(lambda: _cleanup(rss, sm, name, state))

    assert created.get("adminUserPassword") is None, (
        f"CreateNamespace must never echo a password back, got {created.get('adminUserPassword')!r}"
    )

    namespace = created if created.get("status") == "AVAILABLE" else _wait_available(rss, name)

    secret_arn = namespace.get("adminPasswordSecretArn")
    assert secret_arn, (
        f"GetNamespace on an AVAILABLE managed-password namespace must carry "
        f"adminPasswordSecretArn, got {namespace!r}"
    )
    state["secret_arn"] = secret_arn

    parts = secret_arn.split(":")
    assert parts[:3] == ["arn", "aws", "secretsmanager"], (
        f"adminPasswordSecretArn must name a Secrets Manager secret, got {secret_arn!r}"
    )
    assert parts[3] == ctx.region, (
        f"the secret must live in the namespace's own region {ctx.region!r}, got {parts[3]!r} "
        f"from {secret_arn!r}"
    )
    assert parts[4] == ctx.account, (
        f"the secret must live in the caller's own account {ctx.account!r}, got {parts[4]!r} "
        f"from {secret_arn!r}"
    )

    refetched = rss.get_namespace(namespaceName=name)["namespace"]
    assert refetched["adminPasswordSecretArn"] == secret_arn, (
        f"a fresh GetNamespace must agree with the earlier one on the secret arn: "
        f"{refetched.get('adminPasswordSecretArn')!r} != {secret_arn!r}"
    )

    described = sm.describe_secret(SecretId=secret_arn)
    assert described["ARN"] == secret_arn, (
        f"DescribeSecret must resolve the arn GetNamespace reported: asked for {secret_arn!r}, "
        f"got {described.get('ARN')!r}"
    )
    assert described.get("DeletedDate") is None, (
        f"a live namespace's secret must not be scheduled for deletion, got "
        f"{described.get('DeletedDate')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
