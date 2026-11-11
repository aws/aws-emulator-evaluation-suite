"""resource-policy-revision-mismatch-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-revision-mismatch-rejected"
GROUP = "representation"
SERVICES = ["rum"]
_POLICY_NOT_FOUND = "Resource policy does not exist"
_STALE_REVISION = "PolicyRevisionID must match the existing revision"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy with a stale PolicyRevisionId is rejected, leaves the current
    policy untouched, and deleting with the correct revision id succeeds."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-")
    rum.create_app_monitor(Name=name, Domain="localhost", Tags={"Team": "rum-fidelity"})
    ctx.on_cleanup(lambda: _safe(lambda: rum.delete_app_monitor(Name=name)))

    arn = _app_monitor_arn(ctx, name)
    doc1 = (
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
        '"Principal": {"AWS": "arn:aws:iam::111111111111:root"}, '
        '"Action": "rum:PutRumEvents", "Resource": "' + arn + '"}]}'
    )
    doc2 = (
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
        '"Principal": {"AWS": "arn:aws:iam::123456789012:root"}, '
        '"Action": "rum:PutRumEvents", "Resource": "' + arn + '"}]}'
    )

    put1 = rum.put_resource_policy(Name=name, PolicyDocument=doc1)
    rev1 = put1["PolicyRevisionId"]

    # Correct-revision update succeeds and mints a new revision id.
    put2 = rum.put_resource_policy(
        Name=name, PolicyDocument=doc2, PolicyRevisionId=rev1
    )
    rev2 = put2["PolicyRevisionId"]
    assert rev2 != rev1, f"PutResourcePolicy should mint a new revision id, got {rev2!r} == {rev1!r}"
    ctx.on_cleanup(
        lambda rev=rev2: _safe(
            lambda: rum.delete_resource_policy(Name=name, PolicyRevisionId=rev)
        )
    )

    # Deleting with the now-stale rev1 must be rejected.
    err = _client_error(
        lambda: rum.delete_resource_policy(Name=name, PolicyRevisionId=rev1)
    )
    assert err["Code"] == "InvalidPolicyRevisionIdException", (
        f"expected InvalidPolicyRevisionIdException for a stale revision, got {err!r}"
    )
    assert err.get("Message") == _STALE_REVISION, (
        f"expected message {_STALE_REVISION!r}, got {err.get('Message')!r}"
    )

    # Effect absent: the stored policy is unchanged (still doc2 / rev2).
    get_resp = rum.get_resource_policy(Name=name)
    assert json.loads(get_resp["PolicyDocument"]) == json.loads(doc2), (
        f"expected the stale delete to leave doc2 in place, got {get_resp['PolicyDocument']}"
    )
    assert get_resp["PolicyRevisionId"] == rev2, (
        f"expected revision to remain {rev2!r}, got {get_resp['PolicyRevisionId']!r}"
    )

    # Positive control: deleting with the correct current revision succeeds.
    rum.delete_resource_policy(Name=name, PolicyRevisionId=rev2)
    absent = _client_error(lambda: rum.get_resource_policy(Name=name))
    assert absent["Code"] == "PolicyNotFoundException", (
        f"expected the policy to be gone after a correctly-revisioned delete, got {absent!r}"
    )
    assert absent.get("Message") == _POLICY_NOT_FOUND, (
        f"expected message {_POLICY_NOT_FOUND!r}, got {absent.get('Message')!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "PolicyNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _client_error(fn) -> dict:
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name: str) -> str:
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
