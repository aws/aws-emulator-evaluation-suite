"""deregister-application-removes-resource."""
from __future__ import annotations

import secrets
import time

from behavioral_harness import tags

CHECK = "deregister-application-removes-resource"
GROUP = "lifecycle"
SERVICES = ["ssm-sap"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterApplication removes the application: GetApplication on the
    deregistered ApplicationId eventually rejects with ValidationException and
    the id disappears from ListApplications."""
    _ensure_service_linked_role(ctx)
    client = ctx.client("ssm-sap")
    app_id = ctx.unique_name("sim2real-sap-").replace("_", "-")[:60]
    instance_id = "i-" + secrets.token_hex(9)[:17]

    _register_application_awaiting_role_propagation(
        client,
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
    ctx.on_cleanup(lambda: _deregister_ignore_errors(ctx, app_id))

    # sanity: it exists before we deregister it
    got_id = client.get_application(ApplicationId=app_id)["Application"]["Id"]
    assert got_id == app_id, f"expected GetApplication to return Id {app_id!r}, got {got_id!r}"

    # DeregisterApplication rejects an application whose registration hasn't
    # finished (REGISTERING) yet -- wait for it to settle (FAILED, since the
    # backing EC2 instance is fake and discovery cannot succeed) before
    # attempting to remove it.
    deadline_settle = time.monotonic() + 180.0
    status = None
    while time.monotonic() < deadline_settle:
        status = client.get_application(ApplicationId=app_id)["Application"]["Status"]
        if status != "REGISTERING":
            break
        time.sleep(2)
    assert status != "REGISTERING", (
        f"application never left REGISTERING within 180s, still {status!r}"
    )

    client.deregister_application(ApplicationId=app_id)

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 120.0
    gone = None
    while gone is None:
        try:
            client.get_application(ApplicationId=app_id)
        except ClientError as e:
            gone = e.response["Error"]
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"GetApplication still returned {app_id!r} 120s after DeregisterApplication")
        time.sleep(5.0)

    expected_gone = f"No registered application found for account: {ctx.account}, and application: {app_id}"
    assert gone["Code"] == "ValidationException", (
        f"expected GetApplication to reject the deregistered app with "
        f"ValidationException, got {gone!r}"
    )
    assert gone.get("Message") == expected_gone, (
        f"expected message {expected_gone!r}, got {gone.get('Message')!r}"
    )

    all_ids = {a["Id"] for a in _list_all_applications(client)}
    assert app_id not in all_ids, "deregistered application still present in ListApplications"

    # a mutation on the dead id -- not just a read -- must also fail: a
    # double-deregister proves the id is gone, not merely that this one read
    # path was updated.
    redereg = _error(lambda: client.deregister_application(ApplicationId=app_id))
    assert redereg["Code"] == "ValidationException", (
        f"expected a second DeregisterApplication on the removed app to reject with "
        f"ValidationException, got {redereg!r}"
    )
    assert redereg.get("Message") == expected_gone, (
        f"expected message {expected_gone!r}, got {redereg.get('Message')!r}"
    )


def _ensure_service_linked_role(ctx) -> None:
    import time

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
    while True:
        try:
            iam.get_role(RoleName="AWSServiceRoleForAWSSSMForSAP")
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "AWSServiceRoleForAWSSSMForSAP did not become visible within 60s "
                    "of create_service_linked_role"
                )
            time.sleep(5.0)


def _register_application_awaiting_role_propagation(client, **kwargs):
    """RegisterApplication rejects with a specific ValidationException while the
    just-created AWSServiceRoleForAWSSSMForSAP is still propagating to ssm-sap's
    control plane -- the service's own error message says to retry after "a few
    minutes". Retry only that exact, named condition; anything else raises."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180.0
    while True:
        try:
            return client.register_application(**kwargs)
        except ClientError as e:
            message = e.response["Error"].get("Message", "")
            if (
                e.response["Error"]["Code"] == "ValidationException"
                and "AWSServiceRoleForAWSSSMForSAP" in message
                and "propagate" in message
                and time.monotonic() < deadline
            ):
                time.sleep(2)
                continue
            raise


def _error(fn):
    """Call fn(); return its botocore error dict (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails here rather than as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _deregister_ignore_errors(ctx, app_id: str) -> None:
    """Teardown: deregister once the application leaves REGISTERING, retrying ConflictException;
    returns once the deregister is accepted or the application is gone, and raises any other error."""
    import time

    from botocore.exceptions import ClientError

    client = ctx.client("ssm-sap")

    def _gone(exc) -> bool:
        err = exc.response["Error"]
        return err["Code"] == "ValidationException" and err.get("Message", "").startswith(
            "No registered application found"
        )

    deadline = time.monotonic() + 240.0
    while True:
        try:
            status = client.get_application(ApplicationId=app_id)["Application"].get("Status")
        except ClientError as exc:
            if _gone(exc):
                return
            raise
        if status != "REGISTERING":
            try:
                client.deregister_application(ApplicationId=app_id)
                return
            except ClientError as exc:
                if _gone(exc):
                    return
                if exc.response["Error"]["Code"] != "ConflictException":
                    raise
        if time.monotonic() > deadline:
            raise AssertionError(f"application {app_id} was not deregistered within 240s of teardown")
        time.sleep(2)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
