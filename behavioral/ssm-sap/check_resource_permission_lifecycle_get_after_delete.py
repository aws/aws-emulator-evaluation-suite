"""resource-permission-lifecycle-get-after-delete."""
from __future__ import annotations

import secrets

from behavioral_harness import tags

CHECK = "resource-permission-lifecycle-get-after-delete"
GROUP = "permissions"
SERVICES = ["ssm-sap"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourcePermission and DeleteResourcePermission reject a pattern-valid ARN that is not a
    discovered HANA database with ValidationException ("not a valid database ARN") rather than
    fabricating or silently deleting a policy."""
    _ensure_service_linked_role(ctx)
    _purge_stale_apps(ctx)
    client = ctx.client("ssm-sap")
    real_id = ctx.unique_name("sim2real-sap-real-").replace("_", "-")[:60]

    real = _register_application_with_retry(client, real_id)
    ctx.on_cleanup(lambda: _deregister_ignore_errors(ctx, real_id))
    real_arn = real["Application"]["Arn"]
    never_arn = real_arn.rsplit("/", 1)[0] + "/" + ctx.unique_name(
        "sim2real-sap-never-"
    ).replace("_", "-")[:60]

    expected_never = f"Database ARN '{never_arn}' is not valid"
    err_get = _error(lambda: client.get_resource_permission(ResourceArn=never_arn))
    assert err_get["Code"] == "ValidationException", err_get
    assert err_get.get("Message") == expected_never, (
        f"expected message {expected_never!r}, got {err_get.get('Message')!r}"
    )

    err_delete = _error(
        lambda: client.delete_resource_permission(ResourceArn=never_arn)
    )
    assert err_delete["Code"] == "ValidationException", err_delete
    assert err_delete.get("Message") == expected_never, (
        f"expected message {expected_never!r}, got {err_delete.get('Message')!r}"
    )

    # positive control: the same "not a valid database ARN" family also
    # applies to the real application ARN, because it was never the target
    # of a successful PutResourcePermission (no HANA database was ever
    # discovered for it) -- GetResourcePermission does not fabricate a
    # policy for a bare app ARN either.
    err_get_real = _error(lambda: client.get_resource_permission(ResourceArn=real_arn))
    assert err_get_real["Code"] == "ValidationException", err_get_real
    expected_real = f"Database ARN '{real_arn}' is not valid"
    assert err_get_real.get("Message") == expected_real, (
        f"expected message {expected_real!r}, got {err_get_real.get('Message')!r}"
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
                raise AssertionError(
                    "AWSServiceRoleForAWSSSMForSAP did not become visible within 60s of creation"
                )
            time.sleep(5.0)


def _register_application_with_retry(client, app_id: str):
    import time

    from botocore.exceptions import ClientError

    # IAM role propagation is eventually consistent: RegisterApplication can
    # reject the just-created AWSServiceRoleForAWSSSMForSAP as not yet usable
    # until the change propagates to ssm-sap.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return client.register_application(
                ApplicationId=app_id,
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
                Tags={"sim2real:managed": "true"},
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            role_not_ready = code in ("AccessDeniedException", "ValidationException") and (
                "AWSServiceRoleForAWSSSMForSAP" in str(e) or "service-linked role" in str(e).lower()
            )
            if role_not_ready and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


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

