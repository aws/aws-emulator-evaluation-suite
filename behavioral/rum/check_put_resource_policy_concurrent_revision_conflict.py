"""put-resource-policy-concurrent-revision-conflict."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-concurrent-revision-conflict"
GROUP = "concurrency"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with a PolicyRevisionId another writer has advanced is refused with
    InvalidPolicyRevisionIdException rather than overwriting the newer policy, while the current
    revision succeeds.
    """
    rum = ctx.client("rum")
    sts = ctx.client("sts")

    app_name = ctx.unique_name("sim2real-rum-policyrev-")
    account_id = sts.get_caller_identity()["Account"]
    rum.create_app_monitor(Name=app_name, Domain="sim2real-behav.example.com", Tags={"Team": "rum-fidelity"})
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=app_name))
    app_arn = f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{app_name}"
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: rum.delete_resource_policy(Name=app_name)))

    r1 = rum.put_resource_policy(Name=app_name, PolicyDocument=_policy_doc(app_arn, "v1"))
    revision_1 = r1["PolicyRevisionId"]

    # A second writer advances the policy using the correct (then-current) revision.
    r2 = rum.put_resource_policy(
        Name=app_name, PolicyDocument=_policy_doc(app_arn, "v2"), PolicyRevisionId=revision_1
    )
    revision_2 = r2["PolicyRevisionId"]
    assert revision_2 != revision_1, f"expected a new revision id after the v2 write, got {revision_2!r} again"

    # Break exactly one thing: try to write again using the now-stale revision_1.
    code, message = _client_error(
        lambda: rum.put_resource_policy(
            Name=app_name, PolicyDocument=_policy_doc(app_arn, "v3-stale"), PolicyRevisionId=revision_1
        )
    )
    assert code == "InvalidPolicyRevisionIdException", f"expected InvalidPolicyRevisionIdException, got {code!r}"
    assert message == "If policyRevisionID is provided, then it must match the existing revision.", message

    # Effect absent: the stored policy is still v2 at revision_2, untouched by the stale write.
    current = rum.get_resource_policy(Name=app_name)
    assert current["PolicyRevisionId"] == revision_2, (
        f"expected revision {revision_2!r} to survive the rejected stale write, got {current['PolicyRevisionId']!r}"
    )
    current_sid = json.loads(current["PolicyDocument"])["Statement"][0]["Sid"]
    assert current_sid == "v2", f"expected the stale write to leave Sid 'v2' in place, got {current_sid!r}"

    # Positive control: supplying the correct current revision succeeds.
    r3 = rum.put_resource_policy(
        Name=app_name, PolicyDocument=_policy_doc(app_arn, "v3"), PolicyRevisionId=revision_2
    )
    assert r3["PolicyRevisionId"] != revision_2, (
        f"expected a new revision id after the v3 write, got {revision_2!r} again"
    )
    final = rum.get_resource_policy(Name=app_name)
    final_sid = json.loads(final["PolicyDocument"])["Statement"][0]["Sid"]
    assert final_sid == "v3", f"expected the restored write to land Sid 'v3', got {final_sid!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("PolicyNotFoundException", "ResourceNotFoundException"):
            raise


def _policy_doc(app_arn: str, sid: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Action": "rum:PutRumEvents",
                    "Resource": app_arn,
                    "Principal": "*",
                }
            ],
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
