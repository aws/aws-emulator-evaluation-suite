"""invoke-endpoint-oversized-custom-attributes-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "invoke-endpoint-oversized-custom-attributes-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker-runtime"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeEndpoint refuses a CustomAttributes header over 1024 characters with ValidationError and the
    exact message naming the field and the limit without echoing the sensitive value, while the
    baseline call gets the exact endpoint-not-found message."""
    from botocore.exceptions import ClientError

    smr = ctx.client("sagemaker-runtime")
    bogus_endpoint = ctx.unique_name("sim2real-smrt-never-created-")

    def _invoke_error(custom_attributes):
        """The rejection's (code, message). Raises if the call SUCCEEDED."""
        try:
            resp = smr.invoke_endpoint(
                EndpointName=bogus_endpoint, Body=b"x", CustomAttributes=custom_attributes
            )
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err.get("Message", "")
        raise AssertionError(f"expected a ValidationError but the call SUCCEEDED: {resp!r}")

    # Baseline: a short (well within limit) CustomAttributes value passes the
    # constraint layer and reaches the account-scoped endpoint lookup, which
    # fails purely on endpoint-existence grounds.
    baseline_code, baseline_msg = _invoke_error("short-value")
    assert baseline_code == "ValidationError", f"expected ValidationError, got {baseline_code}: {baseline_msg}"
    expected_baseline = f"Endpoint {bogus_endpoint} of account {ctx.account} not found."
    assert baseline_msg == expected_baseline, (
        f"the baseline call must reach the endpoint lookup and report the name and account "
        f"searched, or it proves nothing about the oversized call below; "
        f"expected {expected_baseline!r}, got {baseline_msg!r}"
    )

    # CustomAttributes over 1024 characters is refused by the constraint layer before the endpoint
    # lookup, with a message naming the field and the limit and without echoing the sensitive value.
    oversized = "a" * 1025
    oversized_code, oversized_msg = _invoke_error(oversized)
    assert oversized_code == "ValidationError", (
        f"expected ValidationError for oversized CustomAttributes, got {oversized_code}: {oversized_msg}"
    )
    expected_oversized = (
        "1 validation error detected: Value at 'customAttributes' failed to satisfy constraint: "
        "Member must have length less than or equal to 1024"
    )
    assert oversized_msg == expected_oversized, (
        "an oversized CustomAttributes header must be refused by the constraint layer, naming the "
        "field and the modelled ceiling without echoing the sensitive value; "
        f"expected {expected_oversized!r}, got {oversized_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

