"""stop-application-on-registering-app-is-accepted."""
from __future__ import annotations

import secrets

from behavioral_harness import tags

CHECK = "stop-application-on-registering-app-is-accepted"
GROUP = "state-machine"
SERVICES = ["ssm-sap"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopApplication accepts an application still REGISTERING and returns a tracked
    OperationId rather than a conflict, and the application stays usable afterwards
    (TagResource still succeeds against it)."""
    _ensure_service_linked_role(ctx)
    _purge_stale_apps(ctx)
    client = ctx.client("ssm-sap")
    app_id = ctx.unique_name("sim2real-sap-").replace("_", "-")[:60]
    instance_id = "i-" + secrets.token_hex(9)[:17]

    resp = _register_application_with_retry(
        ctx,
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
    )
    ctx.on_cleanup(lambda: _deregister_ignore_errors(ctx, app_id))
    app_arn = resp["Application"]["Arn"]
    assert resp["Application"]["Status"] == "REGISTERING", (
        f"expected a freshly-registered application to be REGISTERING, got "
        f"{resp['Application']['Status']!r}"
    )

    stop_resp = client.stop_application(ApplicationId=app_id)
    assert "OperationId" in stop_resp and stop_resp["OperationId"], (
        "StopApplication against a REGISTERING application did not return "
        "a tracked OperationId"
    )

    # positive control: the application resource is otherwise fully usable
    client.tag_resource(resourceArn=app_arn, tags={"sim2real-check": "true"})
    ctx.on_cleanup(
        lambda: client.untag_resource(resourceArn=app_arn, tagKeys=["sim2real-check"])
    )
    resource_tags = client.list_tags_for_resource(resourceArn=app_arn)["tags"]
    assert resource_tags.get("sim2real-check") == "true", (
        f"TagResource against an application stopped while REGISTERING did not "
        f"stick -- ListTagsForResource returned {resource_tags!r}"
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
                raise
            time.sleep(5.0)


def _register_application_with_retry(ctx, client, **kwargs):
    import time

    from botocore.exceptions import ClientError

    # A freshly-created AWSServiceRoleForAWSSSMForSAP is visible via iam:GetRole
    # (see _ensure_service_linked_role) before ssm-sap's own control plane has
    # propagated it; retry the first call that actually depends on it instead of
    # guessing a fixed settle time.
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

