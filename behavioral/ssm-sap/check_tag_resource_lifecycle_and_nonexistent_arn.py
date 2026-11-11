"""tag-resource-lifecycle-and-nonexistent-arn."""
from __future__ import annotations

import secrets

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle-and-nonexistent-arn"
GROUP = "tagging"
SERVICES = ["ssm-sap"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a real application ARN, and
    TagResource on a valid but nonexistent application ARN is rejected with NotFoundException
    without disturbing the real application's tags."""
    _ensure_service_linked_role(ctx)
    _purge_stale_apps(ctx)
    client = ctx.client("ssm-sap")
    app_id = ctx.unique_name("sim2real-sap-").replace("_", "-")[:60]
    instance_id = "i-" + secrets.token_hex(9)[:17]

    resp = _register_application_with_propagation_retry(
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

    client.tag_resource(resourceArn=app_arn, tags={"sim2real-owner": "behavioral-suite"})
    tags = client.list_tags_for_resource(resourceArn=app_arn)["tags"]
    assert tags.get("sim2real-owner") == "behavioral-suite", tags

    bogus_arn = app_arn.rsplit("/", 1)[0] + "/does-not-exist-" + app_id
    err = _error(
        lambda: client.tag_resource(resourceArn=bogus_arn, tags={"x": "y"})
    )
    assert err["Code"] == "NotFoundException", err
    expected = "Resource was not found"
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # effect absent / positive control: the real application's tags are
    # untouched by the rejected call against the bogus ARN
    unchanged = client.list_tags_for_resource(resourceArn=app_arn)["tags"]
    assert unchanged.get("sim2real-owner") == "behavioral-suite", unchanged

    client.untag_resource(resourceArn=app_arn, tagKeys=["sim2real-owner"])
    after_untag = client.list_tags_for_resource(resourceArn=app_arn)["tags"]
    assert "sim2real-owner" not in after_untag, after_untag


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
    import time

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
