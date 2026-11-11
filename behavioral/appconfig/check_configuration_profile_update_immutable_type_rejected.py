"""configuration-profile-update-immutable-type-rejected."""
from __future__ import annotations

import json

import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-profile-update-immutable-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "configuration-profile-update-immutable-type-rejected"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A hand-signed UpdateConfigurationProfile that carries the unmodeled Type member is refused whole with a
    Type-specific 400: neither Type nor the co-submitted Description changes, and the same request without Type
    still succeeds afterwards."""
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))

    created = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name="cp-immutable",
        LocationUri="hosted",
        Type="AWS.Freeform",
        Tags=_TAGS,
    )
    cp_id = created["Id"]
    assert created["Type"] == "AWS.Freeform", f"expected AWS.Freeform at creation, got {created.get('Type')}"
    ctx.on_cleanup(lambda: _safe_delete_profile(appconfig, app_id, cp_id))

    # Positive control: a legitimate field really does update, through the modeled SDK path.
    updated = appconfig.update_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, Description="pre-smuggle"
    )
    assert updated["Description"] == "pre-smuggle", f"positive control did not take: {updated}"
    assert updated["Type"] == "AWS.Freeform", f"Type moved on a Description-only update: {updated}"

    # Negative: sign the PATCH request by hand so the unmodeled "Type" member reaches the real
    # service instead of being rejected client-side by the SDK's own request-shape validation.
    status, body = _raw_update_configuration_profile(
        ctx, appconfig, app_id, cp_id,
        {"Description": "post-smuggle", "Type": "AWS.AppConfig.FeatureFlags"},
    )
    assert status == 400, f"expected the server to refuse a smuggled Type change, got {status}: {body}"
    message = body.get("Message", "")
    assert "type" in message.lower(), f"expected a Type-specific refusal, got {message!r}"

    # Effect absent, via an independent read: the refusal is whole-request, not per-field --
    # neither the smuggled Type nor the co-submitted Description took effect.
    unaffected = appconfig.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    assert unaffected["Type"] == "AWS.Freeform", f"Type changed after the refused update: {unaffected}"
    assert unaffected["Description"] == "pre-smuggle", f"Description leaked from the refused call: {unaffected}"

    # Restore: the same legitimate shape, without the smuggled field, still succeeds.
    restored = appconfig.update_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, Description="post-restore"
    )
    assert restored["Description"] == "post-restore", f"legitimate update after refusal did not take: {restored}"
    assert restored["Type"] == "AWS.Freeform", f"Type moved on restore: {restored}"

    # Terminal assertion: an independent read at the destination, through a third operation
    # distinct from either update call, confirms what the mutating calls reported.
    final = appconfig.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    assert final["Description"] == "post-restore", f"restore did not persist: {final}"
    assert final["Type"] == "AWS.Freeform", f"Type not AWS.Freeform on independent read: {final}"



def _raw_update_configuration_profile(ctx, appconfig, app_id, cp_id, body: dict):
    endpoint = appconfig.meta.endpoint_url
    url = f"{endpoint}/applications/{app_id}/configurationprofiles/{cp_id}"
    creds = appconfig._request_signer._credentials
    frozen = creds.get_frozen_credentials() if hasattr(creds, "get_frozen_credentials") else creds
    data = json.dumps(body).encode("utf-8")
    request = AWSRequest(method="PATCH", url=url, data=data, headers={"Content-Type": "application/json"})
    SigV4Auth(frozen, "appconfig", ctx.region).add_auth(request)
    prepared = request.prepare()
    http = urllib3.PoolManager()
    resp = http.request(prepared.method, prepared.url, body=prepared.body, headers=dict(prepared.headers))
    payload = json.loads(resp.data.decode("utf-8")) if resp.data else {}
    return resp.status, payload


def _safe_delete_application(appconfig, app_id):
    try:
        appconfig.delete_application(ApplicationId=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_profile(appconfig, app_id, cp_id):
    try:
        appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
