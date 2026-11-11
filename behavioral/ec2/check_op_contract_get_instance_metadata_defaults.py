"""op-contract-get-instance-metadata-defaults."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-instance-metadata-defaults"
GROUP = "error-semantics"
SERVICES = ["ec2"]

# The exact message EC2 returns for every DryRun call the caller is authorised for.
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-instance-metadata-defaults")
def run(ctx) -> None:
    """GetInstanceMetadataDefaults reflects account-level IMDS defaults set via
    ModifyInstanceMetadataDefaults, and DryRun short-circuits correctly."""
    ec2 = ctx.client("ec2")

    baseline = ec2.get_instance_metadata_defaults().get("AccountLevel", {}) or {}
    original = {
        "HttpTokens": baseline.get("HttpTokens", "no-preference"),
        "HttpPutResponseHopLimit": baseline.get("HttpPutResponseHopLimit", -1),
        "HttpEndpoint": baseline.get("HttpEndpoint", "no-preference"),
        "InstanceMetadataTags": baseline.get("InstanceMetadataTags", "no-preference"),
    }
    ctx.on_cleanup(lambda: ec2.modify_instance_metadata_defaults(**original))

    ec2.modify_instance_metadata_defaults(
        HttpTokens="required",
        HttpPutResponseHopLimit=2,
        HttpEndpoint="enabled",
        InstanceMetadataTags="enabled",
    )

    updated = ec2.get_instance_metadata_defaults()["AccountLevel"]
    assert updated["HttpTokens"] == "required", updated
    assert updated["HttpPutResponseHopLimit"] == 2, updated
    assert updated["HttpEndpoint"] == "enabled", updated
    assert updated["InstanceMetadataTags"] == "enabled", updated

    code, message = _error(lambda: ec2.get_instance_metadata_defaults(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, message


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
