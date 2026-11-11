"""resource-policy-put-get-delete-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-put-get-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["rum"]
_POLICY_NOT_FOUND = "Resource policy does not exist"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy attaches a policy that Get reflects; Delete removes it and a
    subsequent Get then fails with PolicyNotFoundException (the app monitor's
    resource-policy attachment is a real state transition, not decoration)."""
    rum = ctx.client("rum")
    app = _create_app_monitor(ctx)
    policy = _policy_document(ctx, app["arn"])

    put_resp = rum.put_resource_policy(Name=app["name"], PolicyDocument=json.dumps(policy))
    revision_1 = put_resp["PolicyRevisionId"]
    assert json.loads(put_resp["PolicyDocument"]) == policy, (
        f"expected PutResourcePolicy to echo {policy!r}, got {put_resp['PolicyDocument']!r}"
    )
    assert revision_1, f"expected a non-empty PolicyRevisionId, got {put_resp!r}"

    get_resp = rum.get_resource_policy(Name=app["name"])
    assert get_resp["PolicyRevisionId"] == revision_1, (
        f"expected GetResourcePolicy to report the put's revision {revision_1!r}, "
        f"got {get_resp['PolicyRevisionId']!r}"
    )
    assert json.loads(get_resp["PolicyDocument"]) == policy, (
        f"expected GetResourcePolicy to reflect {policy!r}, got {get_resp['PolicyDocument']!r}"
    )

    rum.delete_resource_policy(Name=app["name"], PolicyRevisionId=revision_1)

    err = _client_error(lambda: rum.get_resource_policy(Name=app["name"]))
    assert err["Code"] == "PolicyNotFoundException", (
        f"expected GetResourcePolicy after delete to fail with PolicyNotFoundException, got {err!r}"
    )
    assert err.get("Message") == _POLICY_NOT_FOUND, (
        f"expected message {_POLICY_NOT_FOUND!r}, got {err.get('Message')!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name):
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _create_app_monitor(ctx, name=None, **kwargs):
    rum = ctx.client("rum")
    name = name or ctx.unique_name("sim2real-rum-am-")
    kwargs.setdefault("Domain", "example.com")
    kwargs.setdefault("Tags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})
    resp = rum.create_app_monitor(Name=name, **kwargs)

    def _cleanup():
        try:
            rum.delete_app_monitor(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"name": name, "id": resp["Id"], "arn": _app_monitor_arn(ctx, name)}


def _policy_document(ctx, resource_arn):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPutRumEvents",
                "Effect": "Allow",
                "Principal": {"AWS": _account_id(ctx)},
                "Action": "rum:PutRumEvents",
                "Resource": resource_arn,
            }
        ],
    }


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
