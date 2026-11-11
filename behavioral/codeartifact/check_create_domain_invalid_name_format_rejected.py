"""create-domain-invalid-name-format-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-domain-invalid-name-format-rejected"
GROUP = "error-semantics"
SERVICES = ["codeartifact"]


def _error(fn):
    """The (code, message) of a call that MUST be rejected; raises if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain with a name violating the naming pattern fails with the exact
    ValidationException, while a valid name creates an Active domain that DescribeDomain reads back
    with the same ARN."""
    ca = ctx.client("codeartifact")

    # Uppercase letters and an underscore both violate ^[a-z][a-z0-9\\-]{0,48}[a-z0-9]$.
    invalid_name = "Invalid_Domain_Name"

    refusal = _error(lambda: ca.create_domain(domain=invalid_name))
    expected = (
        "ValidationException",
        f"1 validation error detected: Value '{invalid_name}' at 'domain' failed to satisfy "
        r"constraint: Member must satisfy regular expression pattern: [a-z][a-z0-9\-]{0,48}[a-z0-9]",
    )
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # Positive control: a name that satisfies the pattern is created successfully.
    valid_name = (ctx.unique_name("sim2real-ca-") + "0").lower()
    created = ca.create_domain(domain=valid_name, tags=[{"key": "sim2real", "value": CHECK}])["domain"]
    ctx.on_cleanup(lambda: ca.delete_domain(domain=valid_name))
    assert created["name"] == valid_name, f"expected domain name {valid_name}, got {created['name']}"
    assert created["status"] == "Active", f"expected status Active, got {created['status']}"

    # Independent read at the destination: DescribeDomain confirms the domain exists and is
    # active, rather than trusting CreateDomain's own echo of what it just did.
    described = ca.describe_domain(domain=valid_name)["domain"]
    assert described["name"] == valid_name, f"expected describe_domain name {valid_name}, got {described['name']}"
    assert described["status"] == "Active", f"expected describe_domain status Active, got {described['status']}"
    assert described["arn"] == created["arn"], (
        f"expected describe_domain arn {created['arn']}, got {described['arn']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
