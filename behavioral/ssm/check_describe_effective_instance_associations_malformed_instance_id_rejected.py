"""describe-effective-instance-associations-malformed-instance-id-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-effective-instance-associations-malformed-instance-id-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_MALFORMED_ID = (
    "ValidationException",
    "1 validation error detected: Value 'not-an-instance' at 'instanceId' failed to satisfy "
    "constraint: Member must satisfy regular expression pattern: "
    "(^i-(\\w{8}|\\w{17})$)|(^mi-\\w{17}$)",
)


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) raised by ``fn``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeEffectiveInstanceAssociations rejects an InstanceId that does not match the
    managed-node id pattern, and accepts a syntactically valid but unregistered id."""
    ssm = ctx.client("ssm")

    got = _error(lambda: ssm.describe_effective_instance_associations(InstanceId="not-an-instance"))
    assert got == _MALFORMED_ID, f"expected {_MALFORMED_ID!r}, got {got!r}"

    well_formed_unregistered = "i-" + uuid.uuid4().hex[:17]
    resp = ssm.describe_effective_instance_associations(InstanceId=well_formed_unregistered)
    assert resp["Associations"] == [], (
        f"a well-formed but unregistered instance id returned {resp['Associations']!r}, expected []"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
