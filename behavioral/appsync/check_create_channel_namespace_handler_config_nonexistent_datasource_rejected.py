"""create-channel-namespace-handler-config-nonexistent-datasource-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-namespace-handler-config-nonexistent-datasource-rejected"
GROUP = "channel-namespace"
SERVICES = ["appsync", "iam"]

_EVENT_CONFIG = {
    "authProviders": [{"authType": "API_KEY"}],
    "connectionAuthModes": [{"authType": "API_KEY"}],
    "defaultPublishAuthModes": [{"authType": "API_KEY"}],
    "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
}


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ns_name(ctx, suffix: str) -> str:
    raw = ctx.unique_name(f"sim2real-ns-{suffix}-")
    cleaned = "".join(c if c.isalnum() or c == "-" else "-" for c in raw)
    return cleaned.strip("-")[:50] or "ns0"


def _create_data_source_with_retry(appsync, retry_seconds: float = 30.0, **kwargs):
    # A just-created IAM role is not always immediately assumable by AppSync (documented IAM
    # eventual-consistency window); poll the actual create call rather than sleeping a fixed time.
    deadline = time.monotonic() + retry_seconds
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return appsync.create_data_source(**kwargs)["dataSource"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    assert last_exc is not None
    raise last_exc


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannelNamespace with a DIRECT handlerConfigs integration naming a data source that
    does not exist on the Event API fails BadRequestException and creates nothing; the identical
    shape naming a real Lambda data source succeeds."""
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    api = appsync.create_api(name=ctx.unique_name("sim2real-eventapi-"), eventConfig=_EVENT_CONFIG)["api"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))

    role_name = ctx.unique_name("sim2real-eventapi-ds-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "appsync.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    ds_name = ctx.unique_name("sim2real_ds_").replace("-", "_")
    lambda_config = {
        "lambdaFunctionArn": f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{ds_name}"
    }
    _create_data_source_with_retry(
        appsync, apiId=api_id, name=ds_name, type="AWS_LAMBDA",
        lambdaConfig=lambda_config, serviceRoleArn=role_arn,
    )
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))

    missing_ds_name = ctx.unique_name("sim2real_missing_ds_").replace("-", "_")
    bad_ns_name = _ns_name(ctx, "bad")
    bad_handler_configs = {
        "onPublish": {"behavior": "DIRECT", "integration": {"dataSourceName": missing_ds_name}}
    }
    code, message = _error(
        lambda: appsync.create_channel_namespace(
            apiId=api_id, name=bad_ns_name, handlerConfigs=bad_handler_configs
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "DataSource not found.", f"expected the exact refusal message, got {message!r}"

    listed = appsync.list_channel_namespaces(apiId=api_id)["channelNamespaces"]
    assert all(ns["name"] != bad_ns_name for ns in listed), (
        f"rejected CreateChannelNamespace must not create a namespace: found {bad_ns_name!r} "
        f"in ListChannelNamespaces: {listed!r}"
    )
    not_found_code, _ = _error(lambda: appsync.get_channel_namespace(apiId=api_id, name=bad_ns_name))
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException for the never-created namespace {bad_ns_name!r}, got {not_found_code!r}"
    )

    good_ns_name = _ns_name(ctx, "good")
    good_handler_configs = {
        "onPublish": {"behavior": "DIRECT", "integration": {"dataSourceName": ds_name}}
    }
    good = appsync.create_channel_namespace(
        apiId=api_id, name=good_ns_name, handlerConfigs=good_handler_configs
    )["channelNamespace"]
    ctx.on_cleanup(lambda: appsync.delete_channel_namespace(apiId=api_id, name=good_ns_name))
    assert good["name"] == good_ns_name, f"expected name {good_ns_name!r}, got {good.get('name')!r}"

    fetched = appsync.get_channel_namespace(apiId=api_id, name=good_ns_name)["channelNamespace"]
    assert fetched["handlerConfigs"]["onPublish"]["integration"]["dataSourceName"] == ds_name, (
        f"expected GetChannelNamespace to reflect the real data source {ds_name!r} on onPublish, "
        f"got {fetched.get('handlerConfigs')!r}"
    )
    assert fetched["handlerConfigs"]["onPublish"]["behavior"] == "DIRECT", (
        f"expected onPublish behavior 'DIRECT', got {fetched.get('handlerConfigs')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
