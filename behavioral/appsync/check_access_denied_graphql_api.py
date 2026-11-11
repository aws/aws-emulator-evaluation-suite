"""access-denied-graphql-api."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_PROPAGATION = frozenset({"InvalidClientTokenId", "UnrecognizedClientException"})

def _error(fn, *, retry_propagation=False, timeout_s=90, interval_s=3):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises.
    When retry_propagation is set, a freshly minted access key's transient
    InvalidClientTokenId/UnrecognizedClientException is retried on a bounded deadline rather than
    trusted as the verdict."""
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
        raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

def _implicit_deny(principal_arn, action, resource):
    """AWS's AccessDeniedException message for a principal with no policy granting ``action``."""
    return (
        f"User: {principal_arn} is not authorized to perform: appsync:{action} on resource: "
        f"{resource} because no identity-based policy allows the appsync:{action} action"
    )

def _denied_client(ctx):
    """Provision a throwaway IAM user with ZERO attached policies (implicit deny on every action)
    and return its ARN plus a fresh appsync client credentialed as that user. Credential
    propagation lag is absorbed per-call by ``_error(..., retry_propagation=True)``."""
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

CHECK = "access-denied-graphql-api"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GraphQL API get/update/delete and env-var get/put fail AccessDeniedException for a
    zero-policy principal and leave state untouched; they succeed for the permissioned caller.
    """
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY")["graphqlApi"]
    api_id = api["apiId"]

    def _cleanup_api(_a=api_id, _svc=svc):
        try:
            _svc.delete_graphql_api(apiId=_a)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
    ctx.on_cleanup(_cleanup_api)

    # Positive control: the authorized caller succeeds at every operation under test.
    svc.get_graphql_api(apiId=api_id)
    svc.update_graphql_api(apiId=api_id, name=api["name"], authenticationType="API_KEY")
    svc.put_graphql_api_environment_variables(apiId=api_id, environmentVariables={"PROBE": "1"})
    probe_env = svc.get_graphql_api_environment_variables(apiId=api_id).get("environmentVariables", {})
    assert probe_env.get("PROBE") == "1", (
        f"authorized PutGraphqlApiEnvironmentVariables must take effect; got {probe_env!r}"
    )

    user_arn, denied = _denied_client(ctx)
    account_id = user_arn.split(":")[4]
    api_arn = api["arn"]
    env_resource = f"arn:aws:appsync:{ctx.region}:{account_id}:/v1/apis/{api_id}/environmentVariables"

    checks = [
        ("GetGraphqlApi", api_arn, lambda: denied.get_graphql_api(apiId=api_id)),
        ("UpdateGraphqlApi", api_arn, lambda: denied.update_graphql_api(apiId=api_id, name=api["name"], authenticationType="API_KEY")),
        ("DeleteGraphqlApi", api_arn, lambda: denied.delete_graphql_api(apiId=api_id)),
        ("GetGraphqlApiEnvironmentVariables", env_resource, lambda: denied.get_graphql_api_environment_variables(apiId=api_id)),
        ("PutGraphqlApiEnvironmentVariables", env_resource, lambda: denied.put_graphql_api_environment_variables(apiId=api_id, environmentVariables={"FOO": "bar"})),
    ]
    for label, resource, fn in checks:
        code, message = _error(fn, retry_propagation=True)
        assert code == "AccessDeniedException", (
            f"{label}: expected AccessDeniedException for an unauthorized principal, got {code}"
        )
        expected = _implicit_deny(user_arn, label, resource)
        assert message == expected, f"{label}: expected message {expected!r}, got {message!r}"

    # The api and its env vars must be completely untouched by the denied calls.
    still_there = svc.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert still_there["apiId"] == api_id, (
        f"expected the api to still be {api_id!r} after the denied calls, got {still_there!r}"
    )
    env = svc.get_graphql_api_environment_variables(apiId=api_id).get("environmentVariables", {})
    assert "FOO" not in env, "the denied PutGraphqlApiEnvironmentVariables call must not have taken effect"
    assert env.get("PROBE") == "1", (
        f"the denied calls must not disturb state the authorized caller set earlier; got {env!r}"
    )

    # An authorized Delete succeeds, after which reads and mutations on the id are NotFound.
    svc.delete_graphql_api(apiId=api_id)
    gone_code, gone_message = _error(lambda: svc.get_graphql_api(apiId=api_id))
    assert gone_code == "NotFoundException", f"expected NotFoundException after delete, got {gone_code}"
    assert gone_message == "API not found.", gone_message
    dead_code, dead_message = _error(
        lambda: svc.update_graphql_api(apiId=api_id, name=api["name"], authenticationType="API_KEY")
    )
    assert dead_code == "NotFoundException", (
        f"expected NotFoundException for a mutation on the deleted api, got {dead_code}"
    )
    assert dead_message == "API not found.", dead_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
