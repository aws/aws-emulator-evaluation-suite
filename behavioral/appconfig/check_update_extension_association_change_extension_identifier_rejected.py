"""update-extension-association-change-extension-identifier-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-extension-association-change-extension-identifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-update-extassoc-identifier-rejected"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A raw signed UpdateExtensionAssociation PATCH carrying an ExtensionIdentifier leaves the
    association's ExtensionArn unchanged while its Parameters update: only Parameters are mutable.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    app_arn = _app_arn(ctx, app_id)

    ext_a = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-ext-a-"),
        Actions={"ON_DEPLOYMENT_COMPLETE": [
            {"Name": "notify", "Uri": f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:sim2real-appconfig-ext-a"},
        ]},
        Parameters={"note": {"Required": False}},
        Tags=_TAGS,
    )
    ext_a_id, ext_a_arn = ext_a["Id"], ext_a["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_a_id)))

    ext_b = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-ext-b-"),
        Actions={"ON_DEPLOYMENT_COMPLETE": [
            {"Name": "notify", "Uri": f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:sim2real-appconfig-ext-b"},
        ]},
        Tags=_TAGS,
    )
    ext_b_id = ext_b["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_b_id)))

    created = appconfig.create_extension_association(
        ExtensionIdentifier=ext_a_id, ResourceIdentifier=app_arn, Tags=_TAGS
    )
    assoc_id = created["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)))
    assert created["ExtensionArn"] == ext_a_arn

    # Hand-sign the PATCH so ExtensionIdentifier genuinely reaches AppConfig -- boto3's own
    # serializer cannot carry it (see docstring), so this is the only way to ask the SERVICE,
    # rather than the SDK, whether it can rebind the association's extension this way.
    status, smuggled = _raw_update_extension_association(
        ctx, appconfig, assoc_id, {"note": "x"}, extension_identifier=ext_b_id,
    )
    assert status == 200, f"raw PATCH with a smuggled ExtensionIdentifier gave HTTP {status}: {smuggled}"
    assert smuggled.get("ExtensionArn") == ext_a_arn, (
        f"AppConfig's own response to the smuggled PATCH shows ExtensionArn {smuggled.get('ExtensionArn')!r}, "
        f"expected the unchanged {ext_a_arn!r} -- ExtensionIdentifier has no effect even when it reaches the wire"
    )
    assert smuggled.get("Parameters") == {"note": "x"}, (
        f"the smuggled PATCH's own Parameters echo was {smuggled.get('Parameters')!r}, expected {{'note': 'x'}}"
    )

    unchanged = appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    assert unchanged["ExtensionArn"] == ext_a_arn, "binding to ext_a must remain unchanged after the smuggled call"

    # Positive control: the only mutable field really does update in place.
    updated = appconfig.update_extension_association(ExtensionAssociationId=assoc_id, Parameters={"note": "updated"})
    assert updated["Parameters"] == {"note": "updated"}
    assert updated["ExtensionArn"] == ext_a_arn, "Parameters update must not disturb the extension binding"


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


def _raw_update_extension_association(ctx, appconfig, assoc_id, parameters, *, extension_identifier):
    """PATCH .../extensionassociations/{id} with a hand-built, hand-signed body that carries a
    top-level ExtensionIdentifier -- a member no botocore client can ever put on the wire for
    this operation (see the check's docstring). Bypasses the SDK entirely: the same frozen
    credentials the harness already issued, signed with SigV4 for this request only."""
    import json

    import urllib3
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    raw_creds = appconfig._request_signer._credentials
    frozen = raw_creds.get_frozen_credentials() if hasattr(raw_creds, "get_frozen_credentials") else raw_creds
    signing_name = appconfig._request_signer._signing_name
    url = f"{appconfig.meta.endpoint_url}/extensionassociations/{assoc_id}"
    body = json.dumps({"Parameters": parameters, "ExtensionIdentifier": extension_identifier}).encode()

    req = AWSRequest(method="PATCH", url=url, data=body, headers={"content-type": "application/json"})
    SigV4Auth(frozen, signing_name, ctx.region).add_auth(req)

    resp = urllib3.PoolManager().request(
        "PATCH", url, body=body, headers=dict(req.headers.items()), retries=False
    )
    payload = json.loads(resp.data) if resp.data else {}
    return resp.status, payload


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
