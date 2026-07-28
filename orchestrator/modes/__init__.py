from . import autonomous

try:
    from . import debate
except ImportError:
    pass
try:
    from . import community
except ImportError:
    pass
try:
    from . import rsi
except ImportError:
    pass
try:
    from . import scan
except ImportError:
    pass
try:
    from . import deep_research
except ImportError:
    pass
try:
    from . import postmortem
except ImportError:
    pass
try:
    from . import student
except ImportError:
    pass
