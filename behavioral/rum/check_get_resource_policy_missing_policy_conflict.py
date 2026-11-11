"""get-resource-policy-missing-policy-conflict."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resource-policy-missing-policy-conflict"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on an app monitor that never had a resource-based policy
    attached fails with PolicyNotFoundException per the documented precondition,
    rather than returning an empty/None PolicyDocument."""
    rum = ctx.client("rum")
    app = _create_app_monitor(ctx)

    code, message = _client_error(lambda: rum.get_resource_policy(Name=app["name"]))
    assert code == "PolicyNotFoundException", f"expected PolicyNotFoundException, got {code}"
    assert message == "Resource policy does not exist", message

    # Positive control (same file): once a policy actually exists, Get succeeds and
    # reflects it exactly.
    policy = _policy_document(ctx, app["arn"])
    put_resp = rum.put_resource_policy(Name=app["name"], PolicyDocument=json.dumps(policy))
    get_resp = rum.get_resource_policy(Name=app["name"])
    assert get_resp["PolicyRevisionId"] == put_resp["PolicyRevisionId"], (
        f"expected revision {put_resp['PolicyRevisionId']!r}, got {get_resp['PolicyRevisionId']!r}"
    )
    assert json.loads(get_resp["PolicyDocument"]) == policy, (
        f"expected {policy}, got {json.loads(get_resp['PolicyDocument'])}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name):
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _create_app_monitor(ctx, name=None, **kwargs):
    rum = ctx.client("rum")
    name = name or ctx.unique_name("sim2real-rum-am-")
    kwargs.setdefault("Domain", "example.com")
    kwargs.setdefault("Tags", {"sim2real": CHECK})
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
