"""secure-string-reads-plaintext-only-with-decryption-and-is-gone-after-delete."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secure-string-reads-plaintext-only-with-decryption-and-is-gone-after-delete"
GROUP = "state-machine"
SERVICES = ["ssm"]


def _error(fn):
    """(Error.Code, HTTP status, Error.Message) of the ClientError fn raises; FAILS on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"), err.get(
            "Message"
        ) or ""
    raise AssertionError("the call succeeded; expected a refusal")


def _refusal(got, what):
    """(code, message) of an ``_error`` result, after grading its HTTP 4xx status."""
    code, status, message = got
    assert isinstance(status, int) and 400 <= status < 500, f"{what}: answered HTTP {status!r}, expected 4xx"
    return code, message


def _delete_if_present(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SecureString returns its plaintext only WithDecryption=True. After DeleteParameter, reads
    and LabelParameterVersion are refused ParameterNotFound and DescribeParameters lists nothing."""
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-behav-secure-")
    plaintext = "s3cr3t-" + ctx.unique_name("v")
    ssm.put_parameter(Name=name, Value=plaintext, Type="SecureString")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, name))

    decrypted = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]
    assert decrypted["Value"] == plaintext, f"WithDecryption=True returned {decrypted['Value']!r}, not the plaintext"
    assert decrypted["Type"] == "SecureString", f"Type {decrypted['Type']!r}, expected SecureString"
    assert decrypted["Version"] == 1, f"Version {decrypted['Version']!r}, expected 1"
    raw = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]
    assert isinstance(raw["Value"], str) and raw["Value"], f"the undecrypted read returned {raw['Value']!r}"
    assert plaintext not in raw["Value"], "WithDecryption=False returned the plaintext"

    ssm.delete_parameter(Name=name)
    got = _refusal(_error(lambda: ssm.get_parameter(Name=name, WithDecryption=True)), "GetParameter after delete")
    # AWS answers this ParameterNotFound with an empty message.
    assert got == ("ParameterNotFound", ""), f"GetParameter after delete: got {got!r}"
    described = ssm.describe_parameters(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    )["Parameters"]
    assert described == [], f"DescribeParameters still lists the deleted parameter: {described!r}"
    got = _refusal(
        _error(lambda: ssm.label_parameter_version(Name=name, ParameterVersion=1, Labels=["dead"])),
        "LabelParameterVersion on the deleted parameter",
    )
    assert got == ("ParameterNotFound", f"Parameter {name} not found."), (
        f"LabelParameterVersion on the deleted parameter: got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
