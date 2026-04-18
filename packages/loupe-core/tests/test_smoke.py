import re

from loupe_core import __version__

# Permissive PEP-440-ish: N.N.N with optional .N or pre/post/local suffix.
_VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:\.\d+|[a-z0-9.+-]*)?")


def test_version_is_valid_semver():
    """Reject junk: empty strings, 'unknown', or anything not vaguely versiony.

    Catches the failure mode where importlib.metadata returns a fallback
    placeholder because the package wasn't installed correctly.
    """
    assert isinstance(__version__, str)
    assert __version__ != ""
    assert _VERSION_RE.fullmatch(__version__), (
        f"__version__ {__version__!r} is not a recognisable version string"
    )
