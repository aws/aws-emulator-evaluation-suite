"""representation-resource-policy-json-round-trip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "representation-resource-policy-json-round-trip"
GROUP = "representation"
SERVICES = ["rum"]
_POLICY_NOT_FOUND = "Resource policy does not exist"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A nested resource policy round-trips structurally through PutResourcePolicy -> GetResourcePolicy
    with the same PolicyRevisionId, and after DeleteResourcePolicy a GetResourcePolicy fails with
    PolicyNotFoundException and its exact message."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-respol-")
    rum.create_app_monitor(
        Name=name,
        Domain="localhost",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-rum-respol"},
    )
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))

    arn = _app_monitor_arn(ctx, name)
    # CloudWatch RUM resource-based policies support ONLY the rum:PutRumEvents
    # action (a Deny statement on other actions like GetAppMonitorData is
    # rejected as malformed), so the nested structure under test lives in the
    # Condition block instead.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRUMPutEvents",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "rum:PutRumEvents",
                "Resource": arn,
                "Condition": {
                    "StringEquals": {"rum:alias": ["alias1", "alias2"]},
                    "Bool": {"aws:SecureTransport": "true"},
                },
            },
            {
                "Sid": "DenyFromBlockedIp",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "rum:PutRumEvents",
                "Resource": arn,
                "Condition": {"NotIpAddress": {"aws:SourceIp": ["198.51.100.252", "203.0.113.9"]}},
            },
        ],
    }

    put_resp = rum.put_resource_policy(Name=name, PolicyDocument=json.dumps(policy))
    revision_1 = put_resp["PolicyRevisionId"]
    ctx.on_cleanup(lambda: _cleanup_delete_policy(rum, name))
    assert revision_1, f"expected a non-empty PolicyRevisionId from PutResourcePolicy, got {revision_1!r}"

    get_resp = rum.get_resource_policy(Name=name)
    round_tripped = json.loads(get_resp["PolicyDocument"])
    assert round_tripped == policy, (
        f"nested policy did not round-trip structurally: expected {policy!r}, got {round_tripped!r}"
    )
    assert get_resp["PolicyRevisionId"] == revision_1, (
        f"expected GetResourcePolicy to reflect the Put revision {revision_1!r}, "
        f"got {get_resp['PolicyRevisionId']!r}"
    )

    rum.delete_resource_policy(Name=name, PolicyRevisionId=revision_1)
    err = _client_error(lambda: rum.get_resource_policy(Name=name))
    assert err["Code"] == "PolicyNotFoundException", (
        f"expected an independent GetResourcePolicy to 404 with PolicyNotFoundException "
        f"after DeleteResourcePolicy, got {err!r}"
    )
    assert err.get("Message") == _POLICY_NOT_FOUND, (
        f"expected message {_POLICY_NOT_FOUND!r}, got {err.get('Message')!r}"
    )


def _app_monitor_arn(ctx, name: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{name}"


def _cleanup_delete_policy(rum, name: str) -> None:
    try:
        rum.delete_resource_policy(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "PolicyNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _client_error(fn) -> dict:
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
