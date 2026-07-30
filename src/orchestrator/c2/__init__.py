# Raphael 2.0 C2 Package
from .manager import C2Manager, get_c2
from .models import C2Session, ImplantConfig, TaskResult, SessionStatus
from .beacon import BeaconProtocol, BeaconSession, BeaconTask, BeaconHTTPServer
from .dga import DGAResolver
from .implant_builder import ImplantBuilder
from .native_backend import NativeC2Backend
from .sliver_backend import SliverBackend
from .noop_backend import NoopBackend

__all__ = [
    "C2Manager", "get_c2",
    "C2Session", "ImplantConfig", "TaskResult", "SessionStatus",
    "BeaconProtocol", "BeaconSession", "BeaconTask", "BeaconHTTPServer",
    "DGAResolver", "ImplantBuilder", "NativeC2Backend", "SliverBackend", "NoopBackend",
]