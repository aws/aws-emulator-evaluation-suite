"""delete-volume-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-volume-not-found"
GROUP = "error-semantics"
SERVICES = ["workspaces-instances"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVolume on a well-formed but never-created VolumeId returns ResourceNotFoundException."""
    wsi = ctx.client("workspaces-instances")
    bogus_volume_id = "vol-00000000notreal"

    code, message = _error(lambda: wsi.delete_volume(VolumeId=bogus_volume_id))
    assert code == "ResourceNotFoundException", (code, message)
    assert message == "Workspace managed EBS volume is not found", message


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
