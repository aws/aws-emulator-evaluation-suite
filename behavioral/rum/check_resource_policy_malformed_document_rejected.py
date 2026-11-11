"""resource-policy-malformed-document-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-malformed-document-rejected"
GROUP = "representation"
SERVICES = ["rum"]
_POLICY_NOT_FOUND = "Resource policy does not exist"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with syntactically invalid JSON is rejected, leaves no policy
    stored, and a subsequent valid PutResourcePolicy on the same app monitor succeeds."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-")
    rum.create_app_monitor(Name=name, Domain="localhost")
    ctx.on_cleanup(lambda: _safe(lambda: rum.delete_app_monitor(Name=name)))

    arn = _app_monitor_arn(ctx, name)

    # Trailing comma makes this invalid JSON -> MalformedPolicyDocumentException.
    malformed_document = (
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
        '"Principal": {"AWS": "arn:aws:iam::123456789012:root"}, '
        '"Action": "rum:PutRumEvents", "Resource": "' + arn + '",}]}'
    )
    err = _client_error(lambda: rum.put_resource_policy(Name=name, PolicyDocument=malformed_document))
    assert err["Code"] == "MalformedPolicyDocumentException", err
    # AWS answers this refusal with a JSON body of {"message": null}: the exact message is null.
    assert err.get("Message") is None, f"expected a null message, got {err.get('Message')!r}"

    # Effect must be absent: no policy was ever stored for this app monitor.
    absent = _client_error(lambda: rum.get_resource_policy(Name=name))
    assert absent["Code"] == "PolicyNotFoundException", absent
    assert absent.get("Message") == _POLICY_NOT_FOUND, (
        f"expected message {_POLICY_NOT_FOUND!r}, got {absent.get('Message')!r}"
    )

    # Positive control: a syntactically valid document on the same app monitor succeeds.
    valid_document = (
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
        '"Principal": {"AWS": "arn:aws:iam::' + ctx.account + ':root"}, '
        '"Action": "rum:PutRumEvents", "Resource": "' + arn + '"}]}'
    )
    put_resp = rum.put_resource_policy(Name=name, PolicyDocument=valid_document)
    ctx.on_cleanup(
        lambda rev=put_resp["PolicyRevisionId"]: _safe(
            lambda: rum.delete_resource_policy(Name=name, PolicyRevisionId=rev)
        )
    )
    get_resp = rum.get_resource_policy(Name=name)
    stored = json.loads(get_resp["PolicyDocument"])
    expected = json.loads(valid_document)
    assert stored == expected, f"expected stored policy {expected!r}, got {stored!r}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "PolicyNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name: str) -> str:
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
