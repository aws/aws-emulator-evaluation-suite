"""get-csv-header-malformed-pool-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-csv-header-malformed-pool-id-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-idp"]

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-csvhdr"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCSVHeader rejects a syntactically malformed UserPoolId with
    InvalidParameterException, distinct from the ResourceNotFoundException returned for
    a well-formed but nonexistent pool id."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-csvhdr-"), UserPoolTags=_POOL_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    # A syntactically malformed UserPoolId (no "<region>_<id>" shape) can't be resolved
    # to an authorizable resource, so Cognito rejects it before it ever reaches
    # CSV-header business logic -- distinctly from the ResourceNotFoundException below
    # for a well-formed but nonexistent pool id. boto3 does not validate the UserPoolId
    # pattern client-side, so the malformed id reaches AWS on the normal client.
    malformed_id = "totally-invalid-pool-id-no-underscore"
    code, message = _error(lambda: cognito.get_csv_header(UserPoolId=malformed_id))
    assert code == "InvalidParameterException", f"malformed pool id got {code}"
    expected = (
        f"1 validation error detected: Value '{malformed_id}' at 'userPoolId' failed to satisfy "
        r"constraint: Member must satisfy regular expression pattern: [\w-]+_[0-9a-zA-Z]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # well-formed (matches the UserPoolId pattern) but the pool doesn't exist
    well_formed_missing_id = f"{ctx.region}_ABCDEFGHI"
    code2, message2 = _error(lambda: cognito.get_csv_header(UserPoolId=well_formed_missing_id))
    assert code2 == "ResourceNotFoundException", (
        f"well-formed but nonexistent pool id got {code2}"
    )
    expected2 = f"User pool {well_formed_missing_id} does not exist."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"

    # positive control: a real, existing pool succeeds and returns an actual header
    resp = cognito.get_csv_header(UserPoolId=pool_id)
    assert resp["CSVHeader"], f"expected a non-empty CSVHeader for a live pool, got {resp!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
