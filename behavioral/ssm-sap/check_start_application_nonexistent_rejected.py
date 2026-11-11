"""start-application-nonexistent-rejected."""
from __future__ import annotations

import secrets
import time

from behavioral_harness import tags

CHECK = "start-application-nonexistent-rejected"
GROUP = "start-stop"
SERVICES = ["ssm-sap"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartApplication on a never-registered ApplicationId is rejected with
    ResourceNotFoundException, and on an application whose registration FAILED with
    ValidationException, a distinct failure family; neither starts an application."""
    _ensure_service_linked_role(ctx)
    _purge_stale_apps(ctx)
    client = ctx.client("ssm-sap")
    never_registered = ctx.unique_name("sim2real-sap-never-").replace("_", "-")[:60]

    err = _error(lambda: client.start_application(ApplicationId=never_registered))
    assert err["Code"] == "ResourceNotFoundException", err
    expected = f"Application {never_registered} doesn't exist."
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    app_id = ctx.unique_name("sim2real-sap-").replace("_", "-")[:60]
    instance_id = "i-" + secrets.token_hex(9)[:17]
    _register_application_with_propagation_retry(
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
        Tags={"sim2real": "1"},
    )
    ctx.on_cleanup(lambda: _deregister_ignore_errors(ctx, app_id))

    # wait for registration to settle (it will end up FAILED, since the
    # instance is fake and can never be discovered) before probing
    # StartApplication's precondition check.
    deadline = time.monotonic() + 180.0
    status = None
    while time.monotonic() < deadline:
        status = client.get_application(ApplicationId=app_id)["Application"]["Status"]
        if status != "REGISTERING":
            break
        time.sleep(2)
    assert status != "REGISTERING", (
        f"application never left REGISTERING within 180s, still {status!r}"
    )

    err_not_ready = _error(lambda: client.start_application(ApplicationId=app_id))
    assert err_not_ready["Code"] == "ValidationException", err_not_ready
    expected_not_ready = f"The registration of application {app_id} is failed."
    assert err_not_ready.get("Message") == expected_not_ready, (
        f"expected message {expected_not_ready!r}, got {err_not_ready.get('Message')!r}"
    )

    client.deregister_application(ApplicationId=app_id)
    # GetApplication's "gone" signal for a deregistered id is ValidationException
    # with a specific "no registered application" message -- a different error
    # family than StartApplication's ResourceNotFoundException for the same
    # condition (confirmed against real AWS; the two operations do not share
    # a not-found vocabulary on this service).
    gone_error = _error(lambda: client.get_application(ApplicationId=app_id))
    assert gone_error["Code"] == "ValidationException", gone_error
    expected_gone = f"No registered application found for account: {ctx.account}, and application: {app_id}"
    assert gone_error.get("Message") == expected_gone, (
        f"expected message {expected_gone!r}, got {gone_error.get('Message')!r}"
    )

    dead_mutation = _error(lambda: client.start_application(ApplicationId=app_id))
    assert dead_mutation["Code"] == "ResourceNotFoundException", dead_mutation
    expected_dead = f"Application {app_id} doesn't exist."
    assert dead_mutation.get("Message") == expected_dead, (
        f"expected message {expected_dead!r}, got {dead_mutation.get('Message')!r}"
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


def _register_application_with_propagation_retry(client, **kwargs):
    """RegisterApplication needs the just-created service-linked role to have
    propagated to ssm-sap's control plane; AWS's own ValidationException
    message says to retry after a few minutes, so retry on exactly that
    signal rather than sleeping blind before the first attempt."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180.0
    while True:
        try:
            return client.register_application(**kwargs)
        except ClientError as e:
            error = e.response["Error"]
            if error["Code"] != "ValidationException" or "propagate" not in error.get(
                "Message", ""
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
