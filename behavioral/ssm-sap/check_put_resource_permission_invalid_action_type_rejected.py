"""put-resource-permission-invalid-action-type-rejected."""
from __future__ import annotations

import secrets

from behavioral_harness import tags

CHECK = "put-resource-permission-invalid-action-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm-sap"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePermission and GetResourcePermission reject an application ARN that is not a
    discovered HANA database with ValidationException ("not a valid database ARN"), and an
    ActionType outside {RESTORE} is rejected the same way: no policy is fabricated."""
    _ensure_service_linked_role(ctx)
    _purge_stale_apps(ctx)
    client = ctx.client("ssm-sap")
    real_id = ctx.unique_name("sim2real-sap-real-").replace("_", "-")[:60]
    never_id = ctx.unique_name("sim2real-sap-never-").replace("_", "-")[:60]

    real = _register_application_with_retry(
        client,
        ApplicationId=real_id,
        ApplicationType="HANA",
        Instances=["i-" + secrets.token_hex(9)[:17]],
        Sid="HDB",
        SapInstanceNumber="00",
        Credentials=[
            {
                "CredentialType": "ADMIN",
                "DatabaseName": "HDB/HDB",
                "SecretId": "sim2real-fake-secret-id-real",
            }
        ],
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _deregister_ignore_errors(ctx, real_id))
    real_arn = real["Application"]["Arn"]

    # partition/account differ only in the resource-id suffix, so this ARN
    # is pattern-valid but references a database that was never registered
    never_arn = real_arn.rsplit("/", 1)[0] + "/" + never_id

    # 1) even with a valid ActionType, an unregistered target resource is
    # rejected -- the service must not fabricate a policy for an ARN it has
    # never seen.
    err_missing = _error(
        lambda: client.put_resource_permission(
            ActionType="RESTORE",
            SourceResourceArn=real_arn,
            ResourceArn=never_arn,
        )
    )
    assert err_missing["Code"] == "ValidationException", err_missing
    expected_missing = f"ResourceArn: Database ARN '{never_arn}' is not valid"
    assert err_missing.get("Message") == expected_missing, (
        f"expected message {expected_missing!r}, got {err_missing.get('Message')!r}"
    )

    # 2) GetResourcePermission on that same never-registered ARN is rejected
    # the same way, and no policy was created by the rejected Put above.
    err_get = _error(lambda: client.get_resource_permission(ResourceArn=never_arn))
    assert err_get["Code"] == "ValidationException", err_get
    expected_get = f"Database ARN '{never_arn}' is not valid"
    assert err_get.get("Message") == expected_get, (
        f"expected message {expected_get!r}, got {err_get.get('Message')!r}"
    )

    # 3) an ActionType outside the {RESTORE} enum is rejected even against a
    # resource ARN that does correspond to a real, registered application --
    # this is a distinct failure family from the "resource not found" cases
    # above (ValidationException vs ResourceNotFoundException).
    err_bad_action = _error(
        lambda: client.put_resource_permission(
            ActionType="NOT_A_REAL_ACTION_TYPE",
            SourceResourceArn=real_arn,
            ResourceArn=real_arn,
        )
    )
    assert err_bad_action["Code"] == "ValidationException", err_bad_action
    expected_bad_action = (
        "1 validation error detected: Value 'NOT_A_REAL_ACTION_TYPE' at 'actionType' failed to "
        "satisfy constraint: Member must satisfy enum value set: [RESTORE]"
    )
    assert err_bad_action.get("Message") == expected_bad_action, (
        f"expected message {expected_bad_action!r}, got {err_bad_action.get('Message')!r}"
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
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName="AWSServiceRoleForAWSSSMForSAP")
            return
        except ClientError:
            time.sleep(5.0)
    raise TimeoutError(
        "AWSServiceRoleForAWSSSMForSAP did not become visible within 60s of creation"
    )


def _register_application_with_retry(client, **kwargs):
    """RegisterApplication can fail while a just-created AWSServiceRoleForAWSSSMForSAP's
    trust policy is still propagating; retry the actual dependent call on a bounded
    deadline instead of guessing a fixed propagation delay."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    while True:
        try:
            return client.register_application(**kwargs)
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _purge_stale_apps(ctx) -> None:
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
            if a.get("Id", "").startswith("sim2real-sap-") and a.get("Status") != "REGISTERING":
                try:
                    client.deregister_application(ApplicationId=a["Id"])
                except ClientError:
                    pass
        token = page.get("NextToken")
        if not token:
            break


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

    deadline = time.monotonic() + 300.0
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
            raise AssertionError(f"application {app_id} was not deregistered within 300s of teardown")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

