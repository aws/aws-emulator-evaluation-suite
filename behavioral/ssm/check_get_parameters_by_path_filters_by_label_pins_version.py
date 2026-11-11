"""get-parameters-by-path-filters-by-label-pins-version."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-parameters-by-path-filters-by-label-pins-version"
GROUP = 'parameter-store'
SERVICES = ['ssm']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetParametersByPath's Label filter serves the labelled older version, not the latest.

    An unattached label filters to nothing, and Label refuses any option but Equals."""
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-behav-bylabel-")
    name = f"{base}/p"
    label = "sim2real-pin"

    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    put1 = ssm.put_parameter(Name=name, Value="version-one", Type="String", Tags=[{"Key": "sim2real", "Value": CHECK}])
    assert put1["Version"] == 1, f"first PutParameter must mint version 1, got {put1!r}"

    put2 = ssm.put_parameter(Name=name, Value="version-two", Type="String", Overwrite=True)
    assert put2["Version"] == 2, f"the overwrite must mint version 2, got {put2!r}"

    labelled = ssm.label_parameter_version(Name=name, ParameterVersion=1, Labels=[label])
    assert labelled.get("InvalidLabels", []) == [], (
        f"a conforming label on a real version must not come back under InvalidLabels, "
        f"got {labelled!r}"
    )

    latest = ssm.get_parameters_by_path(Path=base, Recursive=True)["Parameters"]
    assert [p["Name"] for p in latest] == [name], latest
    assert latest[0]["Value"] == "version-two", (
        f"an unfiltered read must serve the latest version, got {latest[0]['Value']!r}"
    )

    pinned = ssm.get_parameters_by_path(
        Path=base, Recursive=True,
        ParameterFilters=[{"Key": "Label", "Option": "Equals", "Values": [label]}],
    )["Parameters"]
    assert [p["Name"] for p in pinned] == [name], (
        f"the Label filter must still return the parameter under its base name, got "
        f"{[p['Name'] for p in pinned]}"
    )
    assert pinned[0]["Value"] == "version-one", (
        f"the Label filter must serve the LABELLED version's bytes ('version-one'), not "
        f"the latest ('version-two'); got {pinned[0]['Value']!r}"
    )
    assert pinned[0]["Version"] == 1, (
        f"the Label filter result must report Version 1, got {pinned[0]['Version']}"
    )

    absent = ssm.get_parameters_by_path(
        Path=base, Recursive=True,
        ParameterFilters=[{"Key": "Label", "Option": "Equals", "Values": ["sim2real-never-attached"]}],
    )["Parameters"]
    assert absent == [], (
        f"an unattached label must filter the subtree to empty, got "
        f"{[p['Name'] for p in absent]}"
    )

    code, message = _error(
        lambda: ssm.get_parameters_by_path(
            Path=base, Recursive=True,
            ParameterFilters=[{"Key": "Label", "Option": "BeginsWith", "Values": [label]}],
        )
    )
    assert code == "InvalidFilterOption", (
        f"Label with Option=BeginsWith must be refused as InvalidFilterOption, got {code!r}"
    )
    expected_message = (
        "The following filter option is not valid: BeginsWith. Valid options include: [Equals]."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
