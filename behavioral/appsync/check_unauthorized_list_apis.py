"""unauthorized-list-apis."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_KEY_NOT_YET_ACTIVE = frozenset({"InvalidClientTokenId", "UnrecognizedClientException"})

def _stable_error(fn, timeout_s, transient_codes):
    """Return the (code, message) fn() is rejected with; raise if it succeeds.
    Retries transient codes until the deadline: a freshly assumed role may not have propagated."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            if code in transient_codes and time.monotonic() < deadline:
                time.sleep(2)
                continue
            return code, err.get("Message")
        raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

def _list_all(call, items_key, **params):
    """Paginate any AppSync ``List*`` call (all use ``nextToken``) and return the concatenated items."""
    results = []
    next_token = None
    while True:
        kwargs = dict(params)
        if next_token:
            kwargs["nextToken"] = next_token
        resp = call(**kwargs)
        results.extend(resp.get(items_key, []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return results

def _denied_client(ctx):
    """Create a same-account IAM role with no permissions and return an appsync client for it.
    An assumed-role session is used because plain IAM user keys are rejected outright here."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role = ctx.unique_name("sim2real-behav-denied-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    role_arn = f"arn:aws:iam::{account_id}:role/{role}"

    deadline = time.monotonic() + 60.0
    creds = None
    last_exc = None
    session = ctx.unique_name("sess-")
    while creds is None and time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session)["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    if creds is None:
        raise AssertionError(f"could not assume the denied role in time: {last_exc!r}")

    client = ctx.client("appsync", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })
    return client, f"arn:aws:sts::{account_id}:assumed-role/{role}/{session}", account_id

CHECK = "unauthorized-list-apis"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListApis and ListGraphqlApis reject a zero-permission principal with AccessDeniedException
    (not the modeled UnauthorizedException) rather than leaking the list; the authorized caller
    sees both APIs."""
    svc = ctx.client("appsync")
    event_api = svc.create_api(
        name=ctx.unique_name("sim2real-behav-appsync-eventapi-"),
        eventConfig={"authProviders": [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}], "connectionAuthModes": [{"authType": "API_KEY"}], "defaultPublishAuthModes": [{"authType": "API_KEY"}], "defaultSubscribeAuthModes": [{"authType": "API_KEY"}]},
        tags={"sim2real": CHECK},
    )["api"]
    ctx.on_cleanup(lambda _a=event_api: svc.delete_api(apiId=_a["apiId"]))
    graphql_api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=graphql_api: svc.delete_graphql_api(apiId=_a["apiId"]))

    apis = {a["apiId"] for a in _list_all(svc.list_apis, "apis")}
    assert event_api["apiId"] in apis, (
        f"positive control: {event_api['apiId']} not visible via authorized ListApis"
    )
    gapis = {a["apiId"] for a in _list_all(svc.list_graphql_apis, "graphqlApis")}
    assert graphql_api["apiId"] in gapis, (
        f"positive control: {graphql_api['apiId']} not visible via authorized ListGraphqlApis"
    )

    denied, denied_arn, account_id = _denied_client(ctx)

    code_apis, msg_apis = _stable_error(lambda: denied.list_apis(), 30.0, _KEY_NOT_YET_ACTIVE)
    assert code_apis == "AccessDeniedException", (
        f"ListApis: expected AccessDeniedException for an unauthorized principal, got {code_apis}"
    )
    assert msg_apis == (
        f"User: {denied_arn} is not authorized to perform: appsync:ListApis on resource: "
        f"arn:aws:appsync:{ctx.region}:{account_id}:* because no identity-based policy allows "
        "the appsync:ListApis action"
    ), f"ListApis: unexpected message: {msg_apis!r}"

    code_gapis, msg_gapis = _stable_error(lambda: denied.list_graphql_apis(), 30.0, _KEY_NOT_YET_ACTIVE)
    assert code_gapis == "AccessDeniedException", (
        f"ListGraphqlApis: expected AccessDeniedException for an unauthorized principal, got {code_gapis}"
    )
    assert msg_gapis == (
        f"User: {denied_arn} is not authorized to perform: appsync:ListGraphqlApis on resource: "
        f"arn:aws:appsync:{ctx.region}:{account_id}:* because no identity-based policy allows "
        "the appsync:ListGraphqlApis action"
    ), f"ListGraphqlApis: unexpected message: {msg_gapis!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
