"""describe-parameters-label-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-parameters-label-filter-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ssm']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeParameters refuses a Label filter key with InvalidFilterKey, though the same label
    resolves via GetParametersByPath on the identical ParameterStringFilter shape.
    """
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-behav-labelreject-")
    name = f"{base}/p"
    label = "sim2real-reject-label"

    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    ssm.put_parameter(Name=name, Value="v", Type="String", Tags=[{"Key": "sim2real", "Value": CHECK}])
    labelled = ssm.label_parameter_version(Name=name, ParameterVersion=1, Labels=[label])
    assert labelled.get("InvalidLabels", []) == [], labelled

    # Prove the label is real: GetParametersByPath, which DOES accept Label, resolves it.
    via_path = ssm.get_parameters_by_path(
        Path=base, Recursive=True,
        ParameterFilters=[{"Key": "Label", "Option": "Equals", "Values": [label]}],
    )["Parameters"]
    assert [p["Name"] for p in via_path] == [name], (
        f"the label must be real and resolvable via GetParametersByPath before this "
        f"check can mean anything; got {[p['Name'] for p in via_path]}"
    )

    code, message = _error(
        lambda: ssm.describe_parameters(
            ParameterFilters=[{"Key": "Label", "Option": "Equals", "Values": [label]}]
        )
    )
    assert code == "InvalidFilterKey", (
        f"DescribeParameters with filter key Label must be refused as InvalidFilterKey, "
        f"got {code!r} ({message!r})"
    )
    expected_message = (
        "The following filter key is not valid: Label. "
        "Valid filter keys include: [Path, Name, Type, KeyId, Tier, DataType]."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: a filter key DescribeParameters does accept still works on the
    # same parameter.
    ok = ssm.describe_parameters(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    )["Parameters"]
    assert [p["Name"] for p in ok] == [name], (
        f"the allowlisted Name filter must still resolve the parameter, got "
        f"{[p['Name'] for p in ok]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
