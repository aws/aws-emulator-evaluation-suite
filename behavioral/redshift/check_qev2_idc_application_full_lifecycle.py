"""qev2-idc-application-full-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "qev2-idc-application-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateQev2IdcApplication, ModifyQev2IdcApplication and DeleteQev2IdcApplication
    drive the resource through create->update->delete, with each transition reflected
    in DescribeQev2IdcApplications."""
    idc_instance_arn = _require_idc_instance(ctx)
    redshift = ctx.client("redshift")
    app_name = ctx.unique_name("sim2real-qev2app-")

    created = redshift.create_qev2_idc_application(
        IdcInstanceArn=idc_instance_arn,
        Qev2IdcApplicationName=app_name,
        IdcDisplayName="sim2real-qev2-app",
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
    )
    app = created["Qev2IdcApplication"]
    app_arn = app["Qev2IdcApplicationArn"]
    ctx.on_cleanup(lambda: _delete_qev2_application_ignore_missing(ctx, app_arn))
    assert app["Qev2IdcApplicationName"] == app_name
    assert app["IdcDisplayName"] == "sim2real-qev2-app"

    described = redshift.describe_qev2_idc_applications(Qev2IdcApplicationArn=app_arn)
    apps = described["Qev2IdcApplications"]
    assert len(apps) == 1 and apps[0]["IdcDisplayName"] == "sim2real-qev2-app", (
        f"expected the created application visible via describe, got {apps}"
    )

    modified = redshift.modify_qev2_idc_application(
        Qev2IdcApplicationArn=app_arn, IdcDisplayName="sim2real-qev2-app-updated"
    )
    assert modified["Qev2IdcApplication"]["IdcDisplayName"] == "sim2real-qev2-app-updated"

    described_after_modify = redshift.describe_qev2_idc_applications(
        Qev2IdcApplicationArn=app_arn
    )
    assert (
        described_after_modify["Qev2IdcApplications"][0]["IdcDisplayName"]
        == "sim2real-qev2-app-updated"
    ), "modify was not reflected in a subsequent describe"

    redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=app_arn)

    final_code, final_message = _error(
        lambda: redshift.describe_qev2_idc_applications(Qev2IdcApplicationArn=app_arn)
    )
    assert final_code == "Qev2IdcApplicationNotExists", (
        f"expected Qev2IdcApplicationNotExists after delete, got {final_code}"
    )
    assert final_message == "The Qev2IdcApplication you specified doesn't exist.", (
        f"unexpected Qev2IdcApplicationNotExists message {final_message!r}"
    )


def _require_idc_instance(ctx):
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        return instances[0]["InstanceArn"]

    from botocore.exceptions import ClientError

    try:
        created = sso.create_instance(Name=ctx.unique_name("sim2real-idc-"))
        return created["InstanceArn"]
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code == "ConflictException":
            instances = sso.list_instances().get("Instances", [])
            if instances:
                return instances[0]["InstanceArn"]
        raise AssertionError(
            f"no IAM Identity Center instance available and CreateInstance "
            f"failed with {code}: {err.response['Error'].get('Message')}"
        ) from err


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_qev2_application_ignore_missing(ctx, app_arn):
    from botocore.exceptions import ClientError

    redshift = ctx.client("redshift")
    try:
        redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=app_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "Qev2IdcApplicationNotExists":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
