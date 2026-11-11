"""list-tags-nonexistent-arn-not-found."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "list-tags-nonexistent-arn-not-found"
GROUP = 'domain'
SERVICES = ['opensearch']

def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected a rejection, but the call SUCCEEDED and returned {result!r}')

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTags/AddTags/RemoveTags on a well-formed ARN for a never-existing domain raise
    ValidationException "Invalid ARN. Domain not found.", not ResourceNotFoundException.
    """
    os = ctx.client('opensearch')
    bogus_arn = f"arn:aws:es:{ctx.region}:{ctx.client('sts').get_caller_identity()['Account']}:domain/{_missing_domain_name(ctx)}"
    expected = ('ValidationException', 'Invalid ARN. Domain not found.')
    got = _error(lambda: os.list_tags(ARN=bogus_arn))
    assert got == expected, f'ListTags: expected {expected}, got {got}'
    got = _error(lambda: os.add_tags(ARN=bogus_arn, TagList=[{'Key': 'k', 'Value': 'v'}]))
    assert got == expected, f'AddTags: expected {expected}, got {got}'
    got = _error(lambda: os.remove_tags(ARN=bogus_arn, TagKeys=['k']))
    assert got == expected, f'RemoveTags: expected {expected}, got {got}'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
