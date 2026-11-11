"""op-contract-describe-principal-id-format."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-principal-id-format"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePrincipalIdFormat: returns the root principal's ID format
    status set; DryRun=True rejects with DryRunOperation; an unrecognized
    resource type in Resources rejects with InvalidResourceType.Unknown."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_principal_id_format()
    principals = resp["Principals"]
    assert isinstance(principals, list), f"expected Principals to be a list, got {type(principals)}"
    assert len(principals) >= 1, "expected at least the root principal entry"
    root = next((p for p in principals if p["Arn"].endswith(":root")), None)
    assert root is not None, f"expected a root principal entry, got {principals}"
    assert isinstance(root["Statuses"], list), f"expected Statuses to be a list, got {root['Statuses']!r}"
    for status in root["Statuses"]:
        assert "Resource" in status, f"expected a Resource key on each status entry, got {status}"
        assert isinstance(status["UseLongIds"], bool), (
            f"expected UseLongIds to be a bool, got {status['UseLongIds']!r}"
        )

    code, msg = _client_error(lambda: ec2.describe_principal_id_format(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # error boundary specific to this operation: an unrecognized resource
    # type in Resources is rejected, not silently ignored or treated as an
    # empty result set.
    code, msg = _client_error(
        lambda: ec2.describe_principal_id_format(Resources=["sim2real-not-a-real-resource-type"])
    )
    assert code == "InvalidResourceType.Unknown", f"expected InvalidResourceType.Unknown, got {code}"
    expected_msg = "Invalid resource type"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
