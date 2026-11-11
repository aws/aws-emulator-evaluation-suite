"""access-denied-tagging."""
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
    user_arn = iam.create_user(UserName=user, Tags=[{"Key": "sim2real-behav", "Value": "true"}])["User"]["Arn"]
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

CHECK = "access-denied-tagging"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Tag/Untag/ListTagsForResource from a zero-policy principal fail with AccessDeniedException.

    The API owner's identical calls succeed before and after, so the block is IAM-driven.
    """
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real-behav": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    arn = api["arn"]
    key = "sim2real-behav-k"

    # Positive control: the unrestricted principal can tag/list/untag its own API.
    svc.tag_resource(resourceArn=arn, tags={key: "control"})
    assert svc.list_tags_for_resource(resourceArn=arn)["tags"].get(key) == "control", (
        "positive control: TagResource from the unrestricted principal did not take effect"
    )
    svc.untag_resource(resourceArn=arn, tagKeys=[key])
    assert key not in svc.list_tags_for_resource(resourceArn=arn)["tags"], (
        "positive control: UntagResource from the unrestricted principal did not take effect"
    )

    user_arn, denied = _denied_client(ctx)
    checks = [
        ("TagResource", lambda: denied.tag_resource(resourceArn=arn, tags={key: "v"})),
        ("UntagResource", lambda: denied.untag_resource(resourceArn=arn, tagKeys=[key])),
        ("ListTagsForResource", lambda: denied.list_tags_for_resource(resourceArn=arn)),
    ]
    for label, fn in checks:
        code, message = _error(fn, retry_propagation=True)
        assert code == "AccessDeniedException", (
            f"{label}: expected AccessDeniedException for an unauthorized principal, got {code}"
        )
        expected = _implicit_deny(user_arn, label, arn)
        assert message == expected, f"{label}: expected message {expected!r}, got {message!r}"

    assert key not in svc.list_tags_for_resource(resourceArn=arn)["tags"], (
        "the denied TagResource call must not have taken effect"
    )

    svc.tag_resource(resourceArn=arn, tags={key: "restored"})
    assert svc.list_tags_for_resource(resourceArn=arn)["tags"].get(key) == "restored", (
        "restore: TagResource from the unrestricted principal must succeed after the denial"
    )
    svc.untag_resource(resourceArn=arn, tagKeys=[key])
    assert key not in svc.list_tags_for_resource(resourceArn=arn)["tags"], (
        "restore: UntagResource from the unrestricted principal must succeed after the denial"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
