"""op-contract-describeTrunkInterfaceAssociations."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeTrunkInterfaceAssociations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTrunkInterfaceAssociations with DryRun answers DryRunOperation, while the real call,
    with or without a filter, fails with OperationNotPermitted for a caller that is not a trunking
    service principal (exact messages)."""
    ec2 = ctx.client("ec2")
    op_name = "describe_trunk_interface_associations"
    if not hasattr(ec2, op_name):
        raise AssertionError(f"{op_name} not available in installed botocore/EC2 model")

    # positive control: this principal has ordinary EC2 read access, so a denial below is
    # specific to trunk-interface-association's principal gate and not a blanket lockout
    ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}], MaxResults=5)

    dry_code, dry_message = _error_code_and_message(
        lambda: ec2.describe_trunk_interface_associations(DryRun=True)
    )
    assert dry_code == "DryRunOperation", f"expected DryRunOperation for DryRun=True, got {dry_code!r}"
    expected_dry = "Request would have succeeded, but DryRun flag is set."
    assert dry_message == expected_dry, f"expected message {expected_dry!r}, got {dry_message!r}"

    # the real (non-DryRun) call hits the deeper service-linked-principal gate that DryRun
    # never reaches, and is rejected deterministically before any filter/shape behavior runs
    code, message = _error_code_and_message(lambda: ec2.describe_trunk_interface_associations())
    assert code == "OperationNotPermitted", (
        f"expected OperationNotPermitted (this operation is reserved for AWS-internal "
        f"service-linked trunking principals), got {code!r} / {message!r}"
    )
    expected_denied = f"User {ctx.account} is not permitted to perform this operation"
    assert message == expected_denied, f"expected message {expected_denied!r}, got {message!r}"

    # the same gate applies regardless of the request shape: a Filters-qualified call is
    # rejected identically rather than reaching filter evaluation
    filtered_code, filtered_message = _error_code_and_message(
        lambda: ec2.describe_trunk_interface_associations(
            Filters=[{"Name": "interface-protocol", "Values": ["GRE"]}]
        )
    )
    assert filtered_code == "OperationNotPermitted", (
        f"expected the Filters-qualified call to hit the same principal gate, got {filtered_code!r}"
    )
    assert filtered_message == expected_denied, (
        f"expected message {expected_denied!r}, got {filtered_message!r}"
    )


def _error_code_and_message(fn):
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call succeeded with: {resp}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
