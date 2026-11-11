"""create-app-instance-token-reuse-conflict-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-app-instance-token-reuse-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientRequestToken with DIFFERENT CreateAppInstance parameters is rejected with
    ConflictException, the second (differing) AppInstance is never created, and a positive
    control using a fresh token still succeeds."""
    # chime-sdk-identity is only served from us-east-1 and eu-central-1 (botocore
    # endpoints.json); pin us-east-1 rather than the suite's default region.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    token = uuid.uuid4().hex
    original_name = ctx.unique_name("sim2real-chime-ai-orig-")

    arn = client.create_app_instance(
        Name=original_name, Metadata="original", ClientRequestToken=token
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=arn))

    conflicting_name = ctx.unique_name("sim2real-chime-ai-conflict-")
    code, message = _error(
        lambda: client.create_app_instance(
            Name=conflicting_name, Metadata="different-metadata", ClientRequestToken=token
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = "The provided ClientRequestToken is already associated with an existing resource."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the original AppInstance is unchanged, and no AppInstance with the
    # conflicting name was ever materialized under that identity.
    desc = client.describe_app_instance(AppInstanceArn=arn)["AppInstance"]
    assert desc["Name"] == original_name, (
        f"expected original name {original_name!r} unchanged, got {desc['Name']!r}"
    )
    assert desc["Metadata"] == "original", (
        f"expected original metadata unchanged, got {desc['Metadata']!r}"
    )

    # Positive control: a fresh token with the same original parameters still works.
    control_name = ctx.unique_name("sim2real-chime-ai-control-")
    control_arn = client.create_app_instance(
        Name=control_name,
        Metadata="control",
        ClientRequestToken=uuid.uuid4().hex,
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=control_arn))
    control_desc = client.describe_app_instance(AppInstanceArn=control_arn)["AppInstance"]
    assert control_desc["Name"] == control_name, (
        f"expected control AppInstance name {control_name!r}, got {control_desc['Name']!r}"
    )
    assert control_desc["Metadata"] == "control", (
        f"expected control AppInstance metadata 'control', got {control_desc['Metadata']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected ConflictException, but the conflicting create_app_instance call SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
