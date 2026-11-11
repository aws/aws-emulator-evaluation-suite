"""put-resource-policy-stale-revision-conflict."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-stale-revision-conflict"
GROUP = "concurrency"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with a stale PolicyRevisionId is refused with
    InvalidPolicyRevisionIdException and the stored policy is unchanged, while a retry with the
    current revision succeeds.
    """
    rum = ctx.client("rum")
    app = _create_app_monitor(ctx)

    policy_v1 = _policy_document(ctx, app["arn"], sid="V1")
    resp_v1 = rum.put_resource_policy(Name=app["name"], PolicyDocument=json.dumps(policy_v1))
    revision_1 = resp_v1["PolicyRevisionId"]

    policy_v2 = _policy_document(ctx, app["arn"], sid="V2")
    resp_v2 = rum.put_resource_policy(
        Name=app["name"], PolicyDocument=json.dumps(policy_v2), PolicyRevisionId=revision_1
    )
    revision_2 = resp_v2["PolicyRevisionId"]
    assert revision_2 != revision_1, (
        f"expected PutResourcePolicy to mint a new revision id, got the same {revision_1!r} twice"
    )

    # Break exactly one thing: reuse the now-stale revision_1 for a new write.
    policy_v3 = _policy_document(ctx, app["arn"], sid="V3")
    code, message = _client_error(
        lambda: rum.put_resource_policy(
            Name=app["name"], PolicyDocument=json.dumps(policy_v3), PolicyRevisionId=revision_1
        )
    )
    assert code == "InvalidPolicyRevisionIdException", (
        f"expected InvalidPolicyRevisionIdException for a stale revision, got {code!r}"
    )
    assert message == "If policyRevisionID is provided, then it must match the existing revision.", message

    # Effect absent: the stored policy is still v2 at revision_2, untouched by the
    # rejected stale write.
    get_resp = rum.get_resource_policy(Name=app["name"])
    assert get_resp["PolicyRevisionId"] == revision_2, (
        f"expected the stored revision to remain {revision_2!r} after the rejected write, "
        f"got {get_resp['PolicyRevisionId']!r}"
    )
    assert json.loads(get_resp["PolicyDocument"]) == policy_v2, (
        f"expected the stored policy to remain policy_v2 after the rejected write, "
        f"got {get_resp['PolicyDocument']!r}"
    )

    # Positive control (same file): the correct current revision is accepted.
    resp_v3 = rum.put_resource_policy(
        Name=app["name"], PolicyDocument=json.dumps(policy_v3), PolicyRevisionId=revision_2
    )
    revision_3 = resp_v3["PolicyRevisionId"]
    assert revision_3 != revision_2, (
        f"expected PutResourcePolicy to mint a new revision id, got the same {revision_2!r} twice"
    )
    get_resp_final = rum.get_resource_policy(Name=app["name"])
    assert json.loads(get_resp_final["PolicyDocument"]) == policy_v3, (
        f"expected the stored policy to be policy_v3 after the correctly-revisioned write, "
        f"got {get_resp_final['PolicyDocument']!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name):
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _create_app_monitor(ctx, name=None, **kwargs):
    rum = ctx.client("rum")
    name = name or ctx.unique_name("sim2real-rum-am-")
    kwargs.setdefault("Domain", "example.com")
    tags_kwarg = kwargs.pop("Tags", {"sim2real:managed": "true", "sim2real:check": CHECK})
    resp = rum.create_app_monitor(Name=name, Tags=tags_kwarg, **kwargs)

    def _cleanup():
        try:
            rum.delete_app_monitor(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"name": name, "id": resp["Id"], "arn": _app_monitor_arn(ctx, name)}


def _policy_document(ctx, resource_arn, sid="AllowPutRumEvents"):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"AWS": _account_id(ctx)},
                "Action": "rum:PutRumEvents",
                "Resource": resource_arn,
            }
        ],
    }


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
