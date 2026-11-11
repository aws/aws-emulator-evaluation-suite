"""set-type-configuration-invalid-json-rejected."""
from __future__ import annotations

import json
import re

from behavioral_harness import tags

CHECK = "set-type-configuration-invalid-json-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetTypeConfiguration on an unregistered TypeArn fails with TypeNotFoundException "The type '<name>'
    cannot be found." for malformed and well-formed JSON alike and stores nothing (404 "TypeConfiguration
    not found"); a TypeArn not shaped like an ARN fails with the ValidationError pattern message."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    type_name = _type_name(ctx, "GhostWidget")
    fake_arn = f"arn:aws:cloudformation:{ctx.region}:{account_id}:type/resource/{type_name.replace('::', '-')}"

    malformed_config = '{"ApiKey": "broken-value"'  # missing closing brace: not valid JSON
    valid_config = json.dumps({"ApiKey": "some-value"})

    # Differential control: a TypeArn that is not shaped like a CloudFormation type ARN is
    # rejected for its shape, not with the not-found code an unregistered ARN gets below.
    garbage_arn = f"not-a-cloudformation-type-arn-{type_name.replace('::', '-')}"
    code_garbage, message_garbage = _error(lambda: cfn.set_type_configuration(TypeArn=garbage_arn, Configuration=valid_config))
    assert code_garbage != "TypeNotFoundException", (
        f"a structurally-malformed TypeArn must not resolve to TypeNotFoundException -- that "
        f"would mean SetTypeConfiguration can't tell 'malformed ARN' from 'well-formed but "
        f"unregistered ARN'; got {code_garbage}"
    )
    assert code_garbage == "ValidationError", (
        f"expected a validation error for a structurally-malformed TypeArn, got {code_garbage}"
    )
    expected = (
        f"1 validation error detected: Value '{garbage_arn}' at 'typeArn' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        "arn:aws[A-Za-z0-9-]{0,64}:cloudformation:[A-Za-z0-9-]{1,64}:([0-9]{12})?:type/.+"
    )
    assert message_garbage == expected, f"expected message {expected!r}, got {message_garbage!r}"

    code_malformed, message_malformed = _error(lambda: cfn.set_type_configuration(TypeArn=fake_arn, Configuration=malformed_config))
    assert code_malformed == "TypeNotFoundException", f"expected TypeNotFoundException, got {code_malformed}"
    expected = f"The type '{type_name}' cannot be found."
    assert message_malformed == expected, f"expected message {expected!r}, got {message_malformed!r}"

    code_valid, message_valid = _error(lambda: cfn.set_type_configuration(TypeArn=fake_arn, Configuration=valid_config))
    assert code_valid == "TypeNotFoundException", f"expected TypeNotFoundException, got {code_valid}"
    assert message_valid == expected, f"expected message {expected!r}, got {message_valid!r}"

    # effect absent either way: BatchDescribeTypeConfigurations reports no stored configuration
    # for an extension that was never actually registered.
    resp = cfn.batch_describe_type_configurations(TypeConfigurationIdentifiers=[{"TypeArn": fake_arn}])
    assert resp["TypeConfigurations"] == [], f"expected no stored configuration, got {resp['TypeConfigurations']}"
    errors = resp.get("Errors", [])
    assert len(errors) == 1 and errors[0]["ErrorCode"] == "404", (
        f"expected a single not-found error entry, got {errors}"
    )
    expected = "TypeConfiguration not found"
    assert errors[0]["ErrorMessage"] == expected, (
        f"expected ErrorMessage {expected!r}, got {errors[0]['ErrorMessage']!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises; raise on success."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _type_name(ctx, resource_word: str) -> str:
    raw = ctx.unique_name("x")
    suffix = re.sub(r"[^A-Za-z0-9]", "", raw)
    suffix = suffix[-16:] if len(suffix) > 16 else suffix
    return f"Sim2Real{suffix}::Behav::{resource_word}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


