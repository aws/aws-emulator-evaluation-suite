"""get-parameters-by-path-unsupported-filter-keys-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-parameters-by-path-unsupported-filter-keys-rejected"
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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetParametersByPath rejects the Name, Tier, Path and DataType filter keys with
    InvalidFilterKey while DescribeParameters accepts the same keys; Type still works."""
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-behav-badfilter-")
    name = f"{base}/p"
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    ssm.put_parameter(Name=name, Value="v", Type="String",
                       Tags=[{"Key": "env", "Value": "sim2real"}])

    rejected_keys = {
        "Name": {"Key": "Name", "Option": "BeginsWith", "Values": [base]},
        "Tier": {"Key": "Tier", "Option": "Equals", "Values": ["Standard"]},
        "DataType": {"Key": "DataType", "Option": "Equals", "Values": ["text"]},
        "Path": {"Key": "Path", "Option": "Recursive", "Values": [base]},
    }
    for key, filt in rejected_keys.items():
        code, message = _error(
            lambda f=filt: ssm.get_parameters_by_path(Path=base, Recursive=True, ParameterFilters=[f])
        )
        assert code == "InvalidFilterKey", (
            f"GetParametersByPath with filter key {key!r} must be refused as InvalidFilterKey, "
            f"got {code!r} ({message!r})"
        )
        expected_message = (
            f"The following filter key is not valid: {key}. "
            "Valid filter keys include: [Type, KeyId, Label]."
        )
        assert message == expected_message, (
            f"for filter key {key!r} expected message {expected_message!r}, got {message!r}"
        )
        # The SAME key, sent to DescribeParameters's identical filter shape, is accepted.
        accepted = ssm.describe_parameters(ParameterFilters=[filt])
        assert "Parameters" in accepted, (
            f"DescribeParameters must accept filter key {key!r} (it is documented valid there), "
            f"got {accepted!r}"
        )

    # Positive control: the allowlisted Type key still works on the same path.
    ok = ssm.get_parameters_by_path(
        Path=base, Recursive=True,
        ParameterFilters=[{"Key": "Type", "Option": "Equals", "Values": ["String"]}],
    )["Parameters"]
    assert [p["Name"] for p in ok] == [name], (
        f"the allowlisted Type filter must still resolve the subtree, got "
        f"{[p['Name'] for p in ok]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
