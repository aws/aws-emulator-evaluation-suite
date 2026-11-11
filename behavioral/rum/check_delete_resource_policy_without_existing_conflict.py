"""delete-resource-policy-without-existing-conflict."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-without-existing-conflict"
GROUP = "error-semantics"
SERVICES = ["rum"]

_NO_POLICY = "Resource policy does not exist"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy on an app monitor that never had a resource policy is refused with
    PolicyNotFoundException rather than succeeding as a no-op.
    """
    rum = ctx.client("rum")
    app = _create_app_monitor(ctx)

    # Break exactly one thing: try to delete a resource policy that was never attached.
    code, message = _client_error(lambda: rum.delete_resource_policy(Name=app["name"]))
    assert code == "PolicyNotFoundException", f"expected PolicyNotFoundException, got {code!r}"
    assert message == _NO_POLICY, f"expected message {_NO_POLICY!r}, got {message!r}"

    # Effect absent: there is still no policy to retrieve.
    code_after, message_after = _client_error(lambda: rum.get_resource_policy(Name=app["name"]))
    assert code_after == "PolicyNotFoundException", (
        f"expected PolicyNotFoundException on the follow-up get, got {code_after!r}"
    )
    assert message_after == _NO_POLICY, f"expected message {_NO_POLICY!r}, got {message_after!r}"

    # Positive control (same file): attach a real policy, delete it for real, and
    # confirm that a *genuine* delete of an existing policy succeeds cleanly.
    policy = _policy_document(ctx, app["arn"])
    put_resp = rum.put_resource_policy(Name=app["name"], PolicyDocument=json.dumps(policy))
    rum.delete_resource_policy(Name=app["name"], PolicyRevisionId=put_resp["PolicyRevisionId"])
    code_final, message_final = _client_error(lambda: rum.get_resource_policy(Name=app["name"]))
    assert code_final == "PolicyNotFoundException", (
        f"expected the real policy to be gone after a genuine delete, got {code_final!r}"
    )
    assert message_final == _NO_POLICY, f"expected message {_NO_POLICY!r}, got {message_final!r}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name):
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _create_app_monitor(ctx, name=None, **kwargs):
    rum = ctx.client("rum")
    name = name or ctx.unique_name("sim2real-rum-am-")
    kwargs.setdefault("Domain", "example.com")
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
    """Call fn and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
