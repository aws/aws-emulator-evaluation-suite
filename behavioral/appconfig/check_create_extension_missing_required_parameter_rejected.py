"""create-extension-missing-required-parameter-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-extension-missing-required-parameter-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-create-extension-missing-required-parameter-rejected"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating an extension that declares a Required parameter without supplying it is rejected with
    BadRequestException and creates no association, while supplying the parameter succeeds."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    app_arn = _app_arn(ctx, app_id)

    ext_name = ctx.unique_name("sim2real-ext-")
    ext = appconfig.create_extension(
        Name=ext_name,
        Actions={"ON_DEPLOYMENT_COMPLETE": [
            {"Name": "notify", "Uri": f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:sim2real-appconfig-ext-notify"},
        ]},
        Parameters={"ApiKey": {"Required": True}},
        Tags=_TAGS,
    )
    ext_id = ext["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id)))

    code, message = _error(lambda: appconfig.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=app_arn))
    assert code == "BadRequestException", (
        f"expected rejection when the required 'ApiKey' parameter is omitted, got {code}"
    )
    expected = (
        f"Extension {ext_name} version 1 has required parameters, but no parameters have been "
        "supplied"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    orphaned = appconfig.list_extension_associations(ExtensionIdentifier=ext_id)["Items"]
    assert orphaned == [], f"no association should exist after the rejected call, found {orphaned}"

    # Positive control: supplying the declared required parameter succeeds.
    created = appconfig.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=app_arn, Parameters={"ApiKey": "secret-value"},
    )
    assoc_id = created["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)))
    assert created["Parameters"] == {"ApiKey": "secret-value"}

    listing = appconfig.list_extension_associations(ExtensionIdentifier=ext_id)["Items"]
    assert any(item["Id"] == assoc_id for item in listing)



def _error(fn):
    """Call fn(); return its botocore (Error code, Error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available and must not be
    reported as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_arn(ctx, app_id):
    return f"arn:aws:appconfig:{ctx.region}:{_account_id(ctx)}:application/{app_id}"


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
