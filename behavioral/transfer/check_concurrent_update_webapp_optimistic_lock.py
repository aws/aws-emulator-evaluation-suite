"""concurrent-update-webapp-optimistic-lock."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-update-webapp-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["transfer"]

_CONFLICT_MESSAGE = "Unable to update WebApp"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Two concurrent UpdateWebApp calls on one web app: a loser is refused only with
    ConflictException and its exact message, the persisted WebAppUnits is a successful writer's,
    and a later sequential update lands."""
    instance_arn = _ensure_identity_center_instance(ctx)
    role_arn = _create_transfer_role(ctx)

    transfer = ctx.client("transfer")
    web_app_id = _retry_role_propagation(
        lambda: transfer.create_web_app(
            IdentityProviderDetails={"IdentityCenterConfig": {"InstanceArn": instance_arn, "Role": role_arn}},
            Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-webapp-")}],
        )
    )["WebAppId"]
    ctx.on_cleanup(lambda: transfer.delete_web_app(WebAppId=web_app_id))

    units_a, units_b = 2, 3

    def update(units: int):
        transfer.update_web_app(WebAppId=web_app_id, WebAppUnits={"Provisioned": units})

    results = _race(lambda: update(units_a), lambda: update(units_b))

    written = [units for units, (ok, _) in zip((units_a, units_b), results) if ok]
    refused = [error for ok, error in results if not ok]
    assert written, f"expected at least one UpdateWebApp racer to succeed, got {results}"
    # An overlapping writer may be refused; serialized writers both succeed.
    assert all(error == ("ConflictException", _CONFLICT_MESSAGE) for error in refused), (
        f"a refused racer must get ConflictException with its exact message, got {refused}"
    )
    described = transfer.describe_web_app(WebAppId=web_app_id)["WebApp"]
    assert described["WebAppUnits"]["Provisioned"] in written, (
        f"expected the persisted WebAppUnits to be a successful writer's value {written!r}, "
        f"got {described['WebAppUnits']['Provisioned']!r}"
    )

    # Positive control: a plain, non-racing UpdateWebApp call still succeeds -- rules out
    # a target that just rejects every Nth/second UpdateWebApp call regardless of contention.
    # Provisioned=1 is the modelled minimum (WebAppUnitCount), not a guessed account ceiling.
    transfer.update_web_app(WebAppId=web_app_id, WebAppUnits={"Provisioned": 1})
    settled = transfer.describe_web_app(WebAppId=web_app_id)["WebApp"]
    assert settled["WebAppUnits"]["Provisioned"] == 1, (
        f"expected the uncontended follow-up UpdateWebApp to land, got "
        f"{settled['WebAppUnits']['Provisioned']!r}"
    )


def _ensure_identity_center_instance(ctx):
    """Create-or-adopt: IAM Identity Center is an account-global singleton (like the Config
    recorder), so this adopts an existing instance if one is enabled and otherwise creates
    one via sso-admin CreateInstance. Never torn down in cleanup: other concurrent
    checks in this suite adopt the same singleton and deleting it would break them."""
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        return instances[0]["InstanceArn"]
    return sso.create_instance(Name=ctx.unique_name("sim2real-identitycenter-"))["InstanceArn"]


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-transfer-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "transfer.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    return role_arn


def _safe_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retry_role_propagation(fn, attempts: int = 6, delay_s: float = 3.0):
    """Retry a call that depends on a just-created IAM role, tolerating IAM's eventual consistency."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _race(fn_a, fn_b):
    """Fire fn_a and fn_b concurrently via a barrier; return [(ok, (code, message) or None), ...]
    in submission order (fn_a first, fn_b second)."""
    barrier = threading.Barrier(2)

    def _wrapped(fn):
        barrier.wait(timeout=10)
        try:
            fn()
            return (True, None)
        except ClientError as exc:
            return (False, (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_wrapped, fn_a), pool.submit(_wrapped, fn_b)]
        return [f.result(timeout=30) for f in futures]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
