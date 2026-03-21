"""
Display layer: tries rich first, falls back to plain ANSI renderer.

Both renderers accept the same AnalysisResult / generation result objects,
so main.py has one import path regardless of what is installed.
"""

try:
    from .rich_display import (
        render_analysis,
        render_password,
        render_passphrase,
        render_pin,
    )
    RICH_AVAILABLE = True
except ImportError:
    from .plain import (  # type: ignore[assignment]
        render_analysis,
        render_password,
        render_passphrase,
        render_pin,
    )
    RICH_AVAILABLE = False

__all__ = [
    "render_analysis",
    "render_password",
    "render_passphrase",
    "render_pin",
    "RICH_AVAILABLE",
]
