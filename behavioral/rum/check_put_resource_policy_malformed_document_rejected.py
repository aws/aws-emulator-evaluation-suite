"""put-resource-policy-malformed-document-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-malformed-document-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A syntactically invalid PolicyDocument is rejected and never persisted
    (confirmed via a subsequent GetResourcePolicy showing no stored policy),
    while a well-formed policy on the same app monitor is accepted and readable."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-badpolicy-")
    rum.create_app_monitor(Name=name, Domain="localhost", Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))

    malformed = '{"Version": "2012-10-17", "Statement": [ this is not valid json'
    code, message = _client_error(lambda: rum.put_resource_policy(Name=name, PolicyDocument=malformed))
    assert code == "MalformedPolicyDocumentException", (
        f"a syntactically invalid PolicyDocument should be refused with "
        f"MalformedPolicyDocumentException, got {code!r}"
    )
    # AWS refuses a malformed document with no message at all.
    assert message is None, message

    # Effect absence: nothing was ever persisted for this app monitor.
    not_found_code, not_found_message = _client_error(lambda: rum.get_resource_policy(Name=name))
    assert not_found_code == "PolicyNotFoundException", (
        f"the rejected policy must never be stored, but GetResourcePolicy returned "
        f"{not_found_code!r} instead of failing with PolicyNotFoundException"
    )
    assert not_found_message == "Resource policy does not exist", not_found_message

    # Positive control: a well-formed policy on the same app monitor works.
    arn = _app_monitor_arn(ctx, name)
    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRUMPutEvents",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "rum:PutRumEvents",
                "Resource": arn,
            }
        ],
    }
    put_resp = rum.put_resource_policy(Name=name, PolicyDocument=json.dumps(valid_policy))
    ctx.on_cleanup(lambda: rum.delete_resource_policy(Name=name))
    get_resp = rum.get_resource_policy(Name=name)
    assert json.loads(get_resp["PolicyDocument"]) == valid_policy, (
        f"a well-formed policy on the same app monitor must round-trip byte-for-byte, "
        f"got {get_resp['PolicyDocument']!r}"
    )
    assert get_resp["PolicyRevisionId"] == put_resp["PolicyRevisionId"], (
        f"GetResourcePolicy revision {get_resp['PolicyRevisionId']!r} does not match the "
        f"PutResourcePolicy revision {put_resp['PolicyRevisionId']!r} for the same policy"
    )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

def _app_monitor_arn(ctx, name: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
