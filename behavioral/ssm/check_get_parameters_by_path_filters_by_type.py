"""get-parameters-by-path-filters-by-type."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-parameters-by-path-filters-by-type"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetParametersByPath Type filters partition a subtree by parameter type, and Type values
    are checked against the String/StringList/SecureString enum even under BeginsWith."""
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-behav-bytype-")
    str_name = f"{base}/str"
    list_name = f"{base}/list"
    secure_name = f"{base}/secure"

    for name in (str_name, list_name, secure_name):
        ctx.on_cleanup(lambda n=name: ssm.delete_parameter(Name=n))

    ssm.put_parameter(Name=str_name, Value="plain-value", Type="String", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ssm.put_parameter(Name=list_name, Value="a,b,c", Type="StringList", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ssm.put_parameter(Name=secure_name, Value="secret-value", Type="SecureString", Tags=[{"Key": "sim2real", "Value": CHECK}])

    unfiltered = ssm.get_parameters_by_path(Path=base, Recursive=True)["Parameters"]
    assert {p["Name"] for p in unfiltered} == {str_name, list_name, secure_name}, (
        f"an unfiltered read of {base} must return all three members, got "
        f"{sorted(p['Name'] for p in unfiltered)}"
    )

    by_string = ssm.get_parameters_by_path(
        Path=base, Recursive=True,
        ParameterFilters=[{"Key": "Type", "Option": "Equals", "Values": ["String"]}],
    )["Parameters"]
    assert [p["Name"] for p in by_string] == [str_name], (
        f"Type=Equals[String] must return exactly {str_name!r}, got "
        f"{[p['Name'] for p in by_string]}"
    )
    assert by_string[0]["Value"] == "plain-value", by_string[0]

    by_secure = ssm.get_parameters_by_path(
        Path=base, Recursive=True, WithDecryption=True,
        ParameterFilters=[{"Key": "Type", "Option": "Equals", "Values": ["SecureString"]}],
    )["Parameters"]
    assert [p["Name"] for p in by_secure] == [secure_name], (
        f"Type=Equals[SecureString] must return exactly {secure_name!r}, got "
        f"{[p['Name'] for p in by_secure]}"
    )
    assert by_secure[0]["Value"] == "secret-value", (
        f"the SecureString member must decrypt to its plaintext under the Type filter, "
        f"got {by_secure[0]['Value']!r}"
    )

    by_two = ssm.get_parameters_by_path(
        Path=base, Recursive=True,
        ParameterFilters=[{"Key": "Type", "Option": "Equals", "Values": ["String", "StringList"]}],
    )["Parameters"]
    assert {p["Name"] for p in by_two} == {str_name, list_name}, (
        f"Type=Equals[String, StringList] must union to exactly those two members, got "
        f"{sorted(p['Name'] for p in by_two)}"
    )

    # Option=BeginsWith does not turn Type into a prefix matcher: the value is still
    # checked against the closed enum, so a genuine prefix of a valid value is refused
    # with InvalidFilterValue rather than silently matching nothing or everything.
    code, message = _error(
        lambda: ssm.get_parameters_by_path(
            Path=base, Recursive=True,
            ParameterFilters=[{"Key": "Type", "Option": "BeginsWith", "Values": ["Str"]}],
        )
    )
    assert code == "InvalidFilterValue", (
        f"Type=BeginsWith[Str] (a real prefix of String/StringList) must be refused as "
        f"InvalidFilterValue, not treated as a prefix match or as InvalidFilterOption; got {code!r}"
    )
    expected_message = (
        "The following filter value is not valid: Str. Valid values include: "
        "[String, StringList, SecureString]."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
