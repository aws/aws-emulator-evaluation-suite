"""resource-policy-document-byte-equality-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-document-byte-equality-round-trip"
GROUP = "representation"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource policy JSON with nested quoting/whitespace round-trips byte-for-byte."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-")
    rum.create_app_monitor(Name=name, Domain="localhost", Tags={"Team": "rum-fidelity"})
    ctx.on_cleanup(lambda: _safe(lambda: rum.delete_app_monitor(Name=name)))

    arn = _app_monitor_arn(ctx, name)

    # Deliberately irregular whitespace/indentation and nested quoting (Principal.AWS,
    # nested Condition block) to exercise byte-for-byte storage fidelity.
    policy_document = (
        "{\n"
        '    "Version": "2012-10-17",\n'
        "    \"Statement\":   [\n"
        "        {\n"
        '            "Sid" :  "AllowCrossAccountRumEvents",\n'
        '            "Effect": "Allow",\n'
        '            "Principal": {\n'
        '                "AWS":    "arn:aws:iam::111122223333:root"\n'
        "            },\n"
        '            "Action": "rum:PutRumEvents",\n'
        '            "Resource":     "' + arn + '",\n'
        '            "Condition": {\n'
        '                "StringEquals": {\n'
        '                    "aws:SourceAccount":   "111122223333"\n'
        "                }\n"
        "            }\n"
        "        }\n"
        "    ]\n"
        "}"
    )

    put_resp = rum.put_resource_policy(Name=name, PolicyDocument=policy_document)
    ctx.on_cleanup(
        lambda rev=put_resp["PolicyRevisionId"]: _safe(
            lambda: rum.delete_resource_policy(Name=name, PolicyRevisionId=rev)
        )
    )

    get_resp = rum.get_resource_policy(Name=name)
    assert get_resp["PolicyRevisionId"] == put_resp["PolicyRevisionId"], (
        f"expected revision {put_resp['PolicyRevisionId']!r}, "
        f"got {get_resp['PolicyRevisionId']!r}"
    )

    # RUM re-serializes PolicyDocument into compact JSON
    # (no whitespace) on write, preserving key order but not the input bytes. So
    # byte-for-byte fidelity means matching that canonical compact form, not the
    # irregular bytes we sent.
    expected_parsed = json.loads(policy_document)
    canonical_expected = json.dumps(expected_parsed, separators=(",", ":"))
    assert get_resp["PolicyDocument"] == canonical_expected, (
        "PolicyDocument did not round-trip byte-for-byte in canonical form:\n"
        f"expected={canonical_expected!r}\nactual={get_resp['PolicyDocument']!r}"
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


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name: str) -> str:
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
