"""put-retention-policy-invalid-value-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


CHECK = "put-retention-policy-invalid-value-fails"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: retentionInDays outside the allowed enum must be rejected,
    with a positive control proving the same wiring accepts a valid value and an
    independent read proving the rejected call left retention untouched."""
    svc = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-retention-bad-")
    svc.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=name: svc.delete_log_group(logGroupName=_n))

    # Positive control: a valid retentionInDays value must succeed and be reflected,
    # so the later rejection cannot be explained by "everything is rejected".
    svc.put_retention_policy(logGroupName=name, retentionInDays=7)
    described = svc.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    matches = [g for g in described if g["logGroupName"] == name]
    assert matches, f"log group {name} missing after a valid PutRetentionPolicy call"
    assert matches[0].get("retentionInDays") == 7, (
        f"expected retentionInDays=7 after the positive control, got {matches[0]}"
    )

    refused = _expect_error(lambda: svc.put_retention_policy(logGroupName=name, retentionInDays=2),
                            ("InvalidParameterException",))
    expected_message = "Invalid retention value. Valid values are: [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653]"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    # Effect absent: the rejected call must not have moved retention off the
    # positive control's value.
    described2 = svc.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    match2 = [g for g in described2 if g["logGroupName"] == name][0]
    assert match2.get("retentionInDays") == 7, (
        f"a rejected PutRetentionPolicy(retentionInDays=2) changed retention: {match2}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
