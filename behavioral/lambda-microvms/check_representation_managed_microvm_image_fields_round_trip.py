"""representation-managed-microvm-image-fields-round-trip."""
from __future__ import annotations

import re
from datetime import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "representation-managed-microvm-image-fields-round-trip"
GROUP = "representation"
SERVICES = ["lambda-microvms"]

_NAME_RE = re.compile(r"^[a-zA-Z0-9\-_]+$")
_MANAGED_ARN_RE = re.compile(r"arn:[a-z0-9-]+:lambda:[a-z0-9-]*:aws:microvm-image:.+")
_VALID_STATES = {
    "CREATING", "CREATED", "CREATE_FAILED", "UPDATING", "UPDATED", "UPDATE_FAILED",
    "DELETING", "DELETE_FAILED", "DELETED",
}


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListManagedMicrovmImages items carry an aws-owned microvm-image ARN and real timestamp
    createdAt/updatedAt values; GetMicrovmImage on that ARN is denied with AccessDeniedException."""
    client = ctx.client("lambda-microvms")
    items = client.list_managed_microvm_images().get("items", [])
    assert items, "expected at least one Lambda-managed base MicroVM image in this account/region"

    for item in items:
        arn = item["imageArn"]
        # MicrovmImageArn's model pattern, with the aws-owned account segment of a managed image.
        assert _MANAGED_ARN_RE.fullmatch(arn), (
            f"managed imageArn does not match arn:<partition>:lambda:<region>:aws:microvm-image:<name>: {arn!r}"
        )
        assert isinstance(item.get("createdAt"), datetime), (
            f"required createdAt is missing or not a timestamp: {item.get('createdAt')!r}"
        )
        for ts_field in ("createdAt", "updatedAt"):
            if ts_field in item and item[ts_field] is not None:
                ts = item[ts_field]
                assert isinstance(ts, (int, float, datetime)), (
                    f"{ts_field} did not survive as a timestamp type: {type(ts)!r}"
                )
                if isinstance(ts, (int, float)):
                    assert ts > 0, f"{ts_field} lost its epoch value: {ts!r}"

    sample = items[0]
    # AWS names the calling principal's own ARN in the message.
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    try:
        client.get_microvm_image(imageIdentifier=sample["imageArn"])
        raise AssertionError("expected GetMicrovmImage to be denied for this principal")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "AccessDeniedException", exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert message == f"User: {caller} is not authorized to perform this operation", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


