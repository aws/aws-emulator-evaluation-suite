"""get-resource-policy-unknown-app-monitor-denied."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-resource-policy-unknown-app-monitor-denied"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy for a well-formed but nonexistent app monitor name is refused with
    ResourceNotFoundException, a malformed name with ValidationException, while a real monitor's
    policy reads back.
    """
    rum = ctx.client("rum")

    # --- positive control: a real app monitor with a real policy reads fine ---
    name = _create_app_monitor(ctx)
    account_id = _account_id(ctx)
    arn = f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{name}"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "rum:PutRumEvents",
                    "Resource": arn,
                    "Principal": "*",
                }
            ],
        },
        separators=(",", ":"),
    )
    rum.put_resource_policy(Name=name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: rum.delete_resource_policy(Name=name))
    control = rum.get_resource_policy(Name=name)
    assert control["PolicyDocument"] == policy_doc, (
        f"positive control: expected the put policy document {policy_doc!r} back, "
        f"got {control['PolicyDocument']!r}"
    )

    # --- negative 1: well-formed name, but no such app monitor exists ---
    missing_name = ctx.unique_name("sim2real-behav-rum-missing-")
    not_found_code, not_found_message = _client_error(lambda: rum.get_resource_policy(Name=missing_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {not_found_code}"
    )
    assert not_found_message == f"Resource not found {missing_name}", not_found_message

    # --- negative 2: malformed name (leading dot violates the naming pattern) ---
    malformed_name = "." + missing_name
    validation_code, validation_message = _client_error(lambda: rum.get_resource_policy(Name=malformed_name))
    assert validation_code == "ValidationException", (
        f"expected ValidationException, got {validation_code}"
    )
    assert validation_message == (
        f"1 validation error detected: Value '{malformed_name}' at 'name' failed to satisfy "
        r"constraint: Member must satisfy regular expression pattern: (?!\.)[\.\-_#A-Za-z0-9]+"
    ), validation_message

    assert not_found_code != validation_code, (
        f"a nonexistent-but-well-formed name and a malformed name must be distinguished, "
        f"but both produced {not_found_code!r}"
    )


def _create_app_monitor(ctx) -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-rum-")
    rum.create_app_monitor(Name=name, Domain="www.example.com", Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    return name


def _account_id(ctx) -> str:
    sts = ctx.client("sts")
    return sts.get_caller_identity()["Account"]


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
