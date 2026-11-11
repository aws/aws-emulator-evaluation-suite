"""register-application-quota-limit-rejected."""
from __future__ import annotations

import secrets
import time

from behavioral_harness import tags

CHECK = "register-application-quota-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm-sap"]

# Safety cap on the discovery loop below, well above any plausible account-wide
# Applications quota (observed to be 10) — not an assumed quota value.
_MAX_ATTEMPTS = 20


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterApplication succeeds until the applications quota, then fails with ValidationException and the exact
    quota message; the rejected application does not exist, the others stay registered, and freeing one slot lets
    the same call succeed."""
    _ensure_service_linked_role(ctx)
    _purge_own_stale_apps(ctx)
    client = ctx.client("ssm-sap")
    created: list[str] = []

    def _cleanup_all():
        for app_id in created:
            _deregister_ignore_errors(ctx, app_id)

    ctx.on_cleanup(_cleanup_all)

    # Bounded retry, not a blind sleep: absorbs both a freshly-created
    # AWSServiceRoleForAWSSSMForSAP lagging briefly before RegisterApplication
    # accepts it, and transient contention from other checks sharing the account's
    # application quota.
    deadline = time.monotonic() + 30.0
    overflow_id = None
    overflow_kwargs = None
    for _ in range(_MAX_ATTEMPTS):
        app_id = ctx.unique_name("sim2real-sap-quota-").replace("_", "-")[:60]
        instance_id = "i-" + secrets.token_hex(9)[:17]
        kwargs = dict(
            ApplicationId=app_id,
            ApplicationType="HANA",
            Instances=[instance_id],
            Sid="HDB",
            SapInstanceNumber="00",
            Credentials=[
                {
                    "CredentialType": "ADMIN",
                    "DatabaseName": "HDB/HDB",
                    "SecretId": "sim2real-fake-secret-id",
                }
            ],
            Tags={"sim2real": CHECK},
        )
        err = _register(client, deadline, **kwargs)
        if err is None:
            created.append(app_id)
            continue
        assert err["Code"] == "ValidationException", f"unexpected error registering application {app_id}: {err!r}"
        # at the boundary the account's registered count equals its quota, so both
        # numbers in the message are the count the service lists right now
        n_registered = len(_list_all_applications(client))
        expected = (
            f"Resource Limit Reached. Account {ctx.account} is only allotted {n_registered} "
            f"applications. Currently has {n_registered} applications"
        )
        assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
        overflow_id, overflow_kwargs = app_id, kwargs
        break
    else:
        raise AssertionError(f"never hit the applications quota after {_MAX_ATTEMPTS} registrations")

    # effect-absent: the overflow app was never created, and the apps that got us
    # to the limit are still registered.
    absent = _error(lambda: client.get_application(ApplicationId=overflow_id))
    assert absent["Code"] == "ValidationException", f"overflow application should not exist, got {absent!r}"
    expected_absent = (
        f"No registered application found for account: {ctx.account}, and application: {overflow_id}"
    )
    assert absent.get("Message") == expected_absent, (
        f"expected message {expected_absent!r}, got {absent.get('Message')!r}"
    )
    for app_id in created:
        got = client.get_application(ApplicationId=app_id)["Application"]["Id"]
        assert got == app_id, f"application {app_id} used to reach the quota is no longer registered, got {got!r}"

    # restore: freeing exactly one slot must let the identical call succeed —
    # proving the rejection tracks the quota, not the specific request. Only
    # exercised when this check's own registrations built the quota headroom: an
    # account already at the limit from apps this check does not own has nothing
    # it is safe for this check to free.
    if created:
        freed_app = created.pop()
        _deregister_ignore_errors(ctx, freed_app)
        restore_deadline = time.monotonic() + 30.0
        restore_err = _register(client, restore_deadline, **overflow_kwargs)
        assert restore_err is None, f"expected the identical call to succeed after freeing a slot, got {restore_err!r}"
        created.append(overflow_id)
        got = client.get_application(ApplicationId=overflow_id)["Application"]["Id"]
        assert got == overflow_id, f"expected the restored application to be registered, got {got!r}"


def _ensure_service_linked_role(ctx) -> None:
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.get_role(RoleName="AWSServiceRoleForAWSSSMForSAP")
        return
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.create_service_linked_role(AWSServiceName="ssm-sap.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName="AWSServiceRoleForAWSSSMForSAP")
            return
        except ClientError:
            time.sleep(5.0)
    raise RuntimeError("AWSServiceRoleForAWSSSMForSAP did not become visible within 60s of creation")


def _purge_own_stale_apps(ctx) -> None:
    """Deregister this check's own leftovers from a previous incomplete run.
    Scoped to the sim2real-sap-quota- prefix this check itself creates below —
    never the sim2real-sap- prefix shared by the other checks in this directory."""
    from botocore.exceptions import ClientError

    client = ctx.client("ssm-sap")
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        try:
            page = client.list_applications(MaxResults=50, **kwargs)
        except ClientError:
            return
        for a in page.get("Applications", []):
            if a.get("Id", "").startswith("sim2real-sap-quota-") and a.get("Status") != "REGISTERING":
                try:
                    client.deregister_application(ApplicationId=a["Id"])
                except ClientError:
                    pass
        token = page.get("NextToken")
        if not token:
            break


def _register(client, deadline, **kwargs):
    """Attempt RegisterApplication, retrying on failure until deadline. Returns None
    on success, else the final botocore error dict — the caller decides what that
    error means (quota boundary vs. a real defect)."""
    from botocore.exceptions import ClientError

    while True:
        try:
            client.register_application(**kwargs)
            return None
        except ClientError as e:
            if time.monotonic() >= deadline:
                return e.response["Error"]
            time.sleep(5.0)


def _list_all_applications(client):
    apps = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = client.list_applications(MaxResults=50, **kwargs)
        apps.extend(page.get("Applications", []))
        token = page.get("NextToken")
        if not token:
            break
    return apps


def _error(fn):
    """Call fn(); return its botocore error dict (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _deregister_ignore_errors(ctx, app_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ctx.client("ssm-sap").deregister_application(ApplicationId=app_id)
    except ClientError:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
