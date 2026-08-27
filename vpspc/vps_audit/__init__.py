"""Evidence-first VPS user behavior audit."""

__version__ = "0.6.0"


def current_controller_version() -> str:
    """Return the controller package version from its single source of truth."""
    return __version__
