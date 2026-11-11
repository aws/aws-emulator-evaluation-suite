"""invoke-endpoint-async-missing-input-failure-location-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "invoke-endpoint-async-missing-input-failure-location-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker-runtime"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeEndpointAsync refuses an InputLocation that is not an s3:// or https:// URI and a
    RequestTTLSeconds below 60 with ValidationError and their exact constraint messages, distinct from
    the exact endpoint-not-found message a well-formed request gets, so field checks run first."""
    from botocore.config import Config
    from botocore.exceptions import ClientError

    smr = ctx.client("sagemaker-runtime")
    # botocore enforces RequestTTLSeconds' [60, 21600] range locally, so parameter validation is
    # disabled and the out-of-range request reaches the service, whose enforcement is graded.
    smr_unvalidated = ctx.client(
        "sagemaker-runtime", config=Config(parameter_validation=False)
    )
    bogus_endpoint = ctx.unique_name("sim2real-smrt-async-never-created-")

    def _invoke(client, input_location, **extra):
        """The rejection's (code, message). Raises if the call SUCCEEDED."""
        try:
            resp = client.invoke_endpoint_async(
                EndpointName=bogus_endpoint, InputLocation=input_location, **extra
            )
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err.get("Message", "")
        raise AssertionError(f"expected a ValidationError but the call SUCCEEDED: {resp!r}")

    # Baseline: a well-formed InputLocation against a nonexistent endpoint
    # reaches the account-scoped endpoint lookup and is rejected there,
    # establishing what "reached the lookup" looks like.
    baseline_code, baseline_msg = _invoke(
        smr, f"s3://{bogus_endpoint}-bucket/does-not-matter.bin"
    )
    assert baseline_code == "ValidationError", f"expected ValidationError, got {baseline_code}: {baseline_msg}"
    expected_baseline = f"Endpoint {bogus_endpoint} of account {ctx.account} not found."
    assert baseline_msg == expected_baseline, (
        f"a well-formed InputLocation against an absent endpoint must reach the account-scoped "
        f"endpoint lookup and report it by name; expected {expected_baseline!r}, got {baseline_msg!r}"
    )

    # Malformed InputLocation scheme (neither s3:// nor https://) is a distinct
    # field-shape violation, rejected by the constraint layer before any
    # endpoint dispatch is possible.
    bad_location = "ftp://not-a-supported-scheme/input.bin"
    bad_scheme_code, bad_scheme_msg = _invoke(smr, bad_location)
    assert bad_scheme_code == "ValidationError", (
        f"expected ValidationError for malformed InputLocation scheme, got {bad_scheme_code}: {bad_scheme_msg}"
    )
    expected_scheme = (
        f"1 validation error detected: Value '{bad_location}' at 'inputLocation' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: ^(https|s3)://([^/]+)/?(.*)$"
    )
    assert bad_scheme_msg == expected_scheme, (
        f"a malformed InputLocation scheme must be refused by the constraint layer, pre-empting "
        f"the endpoint lookup; expected {expected_scheme!r}, got {bad_scheme_msg!r}"
    )

    # RequestTTLSeconds outside the modeled [60, 21600] range is rejected by the
    # SERVICE too (parameter validation disabled above), and must likewise
    # pre-empt the endpoint lookup rather than disclosing non-existence.
    ttl_code, ttl_msg = _invoke(
        smr_unvalidated,
        f"s3://{bogus_endpoint}-bucket/does-not-matter.bin",
        RequestTTLSeconds=30,
    )
    assert ttl_code == "ValidationError", (
        f"expected ValidationError for RequestTTLSeconds below the [60,21600] floor, got {ttl_code}: {ttl_msg}"
    )
    expected_ttl = (
        "1 validation error detected: Value '30' at 'requestTTLSeconds' failed to satisfy "
        "constraint: Member must have value greater than or equal to 60"
    )
    assert ttl_msg == expected_ttl, (
        f"an out-of-range RequestTTLSeconds must be refused by the constraint layer, pre-empting "
        f"the endpoint lookup; expected {expected_ttl!r}, got {ttl_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

