"""access-denied-channel-namespace."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_PROPAGATION = frozenset({"InvalidClientTokenId", "UnrecognizedClientException"})

def _error(fn, *, retry_propagation=False, timeout_s=60, interval_s=3):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises. When retry_propagation
    is set, a freshly minted access key's transient InvalidClientTokenId/UnrecognizedClientException
    is retried on a bounded deadline (real-AWS credential propagation lag) rather than trusted as
    the verdict."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            if retry_propagation and code in _PROPAGATION and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return code, err.get("Message")
        raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _ns_name(raw):
    """Channel-namespace name: ([A-Za-z0-9](?:[A-Za-z0-9-]{0,48}[A-Za-z0-9])?), <=50 chars."""
    cleaned = re.sub(r"[^0-9A-Za-z-]", "-", raw)
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    if len(cleaned) > 50:
        cleaned = cleaned[:50]
    cleaned = cleaned.strip("-")
    if not cleaned or not cleaned[0].isalnum():
        cleaned = "n" + cleaned
    return cleaned

def _implicit_deny(principal_arn, action, resource):
    """AWS's AccessDeniedException message for a principal with no policy granting ``action``."""
    return (
        f"User: {principal_arn} is not authorized to perform: appsync:{action} on resource: "
        f"{resource} because no identity-based policy allows the appsync:{action} action"
    )

def _denied_client(ctx):
    """Provision a throwaway IAM user with ZERO attached policies (implicit deny on every action)
    and return its ARN plus a fresh appsync client credentialed as that user. Credential propagation lag on
    real AWS is absorbed per-call by ``_error(..., retry_propagation=True)`` -- propagation
    is not a single monotonic flip, so a later call can still transiently see it -- not by an
    unconditional sleep here."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-denied-")
    user_arn = iam.create_user(UserName=user)["User"]["Arn"]
    def _cleanup_user(_u=user, _iam=iam):
        for k in _iam.list_access_keys(UserName=_u).get("AccessKeyMetadata", []):
            _iam.delete_access_key(UserName=_u, AccessKeyId=k["AccessKeyId"])
        _iam.delete_user(UserName=_u)
    ctx.on_cleanup(_cleanup_user)
    key = iam.create_access_key(UserName=user)["AccessKey"]
    return user_arn, ctx.client("appsync", creds={
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    })

CHECK = "access-denied-channel-namespace"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetChannelNamespace/UpdateChannelNamespace/DeleteChannelNamespace from an unauthorized
    principal all reject with AccessDeniedException."""
    svc = ctx.client("appsync")
    api = svc.create_api(name=ctx.unique_name("sim2real-behav-appsync-eventapi-"), eventConfig={"authProviders": [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}], "connectionAuthModes": [{"authType": "API_KEY"}], "defaultPublishAuthModes": [{"authType": "API_KEY"}], "defaultSubscribeAuthModes": [{"authType": "API_KEY"}]})["api"]
    ctx.on_cleanup(lambda _a=api: svc.delete_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    ns_name = _ns_name(ctx.unique_name("sim2real-behav-ns-"))
    svc.create_channel_namespace(
        apiId=api_id,
        name=ns_name,
        subscribeAuthModes=[{"authType": "API_KEY"}],
        publishAuthModes=[{"authType": "API_KEY"}],
    )
    def _cleanup_ns(_a=api_id, _n=ns_name):
        try:
            svc.delete_channel_namespace(apiId=_a, name=_n)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
    ctx.on_cleanup(_cleanup_ns)

    # Positive control: the authorized principal's own UpdateChannelNamespace actually takes
    # effect here, so a denial below is scoped to the missing permission and not a namespace
    # (or an emulator) where the operation is universally broken.
    svc.update_channel_namespace(
        apiId=api_id,
        name=ns_name,
        subscribeAuthModes=[{"authType": "API_KEY"}, {"authType": "AWS_IAM"}],
        publishAuthModes=[{"authType": "API_KEY"}],
    )
    authorized_state = svc.get_channel_namespace(apiId=api_id, name=ns_name)["channelNamespace"]
    assert authorized_state["subscribeAuthModes"] == [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}], (
        "positive control: the authorized principal's UpdateChannelNamespace must take effect"
    )

    user_arn, denied = _denied_client(ctx)
    ns_arn = f"{api['apiArn']}/channelNamespace/{ns_name}"
    checks = [
        ("GetChannelNamespace", lambda: denied.get_channel_namespace(apiId=api_id, name=ns_name)),
        ("UpdateChannelNamespace", lambda: denied.update_channel_namespace(
            apiId=api_id,
            name=ns_name,
            subscribeAuthModes=[{"authType": "AWS_IAM"}],
            publishAuthModes=[{"authType": "API_KEY"}],
        )),
        ("DeleteChannelNamespace", lambda: denied.delete_channel_namespace(apiId=api_id, name=ns_name)),
    ]
    for label, fn in checks:
        code, message = _error(fn, retry_propagation=True)
        assert code == "AccessDeniedException", (
            f"{label}: expected AccessDeniedException for an unauthorized principal, got {code}"
        )
        expected = _implicit_deny(user_arn, label, ns_arn)
        assert message == expected, f"{label}: expected message {expected!r}, got {message!r}"

    # Untouched: still there, and the denied Update must not have taken effect.
    still_there = svc.get_channel_namespace(apiId=api_id, name=ns_name)["channelNamespace"]
    assert still_there["subscribeAuthModes"] == [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}], (
        "the denied UpdateChannelNamespace call must not have taken effect"
    )

    # Positive control + delete proves gone: the authorized principal's Delete actually removes
    # it, an independent read 404s, and a further mutation on the dead id also fails.
    svc.delete_channel_namespace(apiId=api_id, name=ns_name)
    gone_code, gone_message = _error(lambda: svc.get_channel_namespace(apiId=api_id, name=ns_name))
    assert gone_code == "NotFoundException", (
        f"expected NotFoundException reading a deleted channel namespace, got {gone_code!r}"
    )
    assert gone_message == "Channel namespace not found.", gone_message
    mutate_code, mutate_message = _error(lambda: svc.update_channel_namespace(
        apiId=api_id,
        name=ns_name,
        subscribeAuthModes=[{"authType": "API_KEY"}],
        publishAuthModes=[{"authType": "API_KEY"}],
    ))
    assert mutate_code == "NotFoundException", (
        f"expected NotFoundException mutating a deleted channel namespace, got {mutate_code!r}"
    )
    # AWS answers this 404 with an empty message.
    assert mutate_message == "", mutate_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
