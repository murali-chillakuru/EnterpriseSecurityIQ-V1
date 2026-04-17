"""Cloud Explorer — first-class query module (v54).

Fully self-contained: ARG templates, keyword maps, NL dispatcher,
composite queries, and orchestrator all live here.  No assessment
engine depends on any code in this package.
"""

from .orchestrator import run_composite_query, COMPOSITE_NAMES  # noqa: F401
from .arg_templates import ARG_TEMPLATES  # noqa: F401
from .keyword_map import NL_ARG_MAP, NL_ENTRA_MAP  # noqa: F401
from .dispatcher import dispatch_natural_language  # noqa: F401
