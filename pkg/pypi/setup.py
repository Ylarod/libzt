"""
Build the libzt Python extension module (libzt._libzt)

The source list and compile flags mirror CMakeLists.txt. Build a wheel from
this directory with:

    pip wheel . -w dist

SWIG is installed automatically from PyPI as a build dependency (see
pyproject.toml).
"""
import os
import shutil
import subprocess
import sys
from glob import glob

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext
from setuptools.command.build_py import build_py

DIR = os.path.dirname(os.path.realpath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(DIR, "..", ".."))
ZTO_DIR = os.path.join(ROOT_DIR, "ext", "ZeroTierOne")
LWIP_DIR = os.path.join(ROOT_DIR, "ext", "lwip", "src")
LWIP_PORT_DIR = os.path.join(ROOT_DIR, "ext", "lwip-contrib", "ports", "unix", "port")
BINDING_DIR = os.path.join(ROOT_DIR, "src", "bindings", "python")


def sources(*patterns, exclude=()):
    files = []
    for pattern in patterns:
        files.extend(sorted(glob(os.path.join(ROOT_DIR, pattern))))
    excluded = {os.path.join(ROOT_DIR, e) for e in exclude}
    # Absolute paths: relative ones ("../../ext/...") would place object
    # files outside of the build directory
    return [f for f in files if f not in excluded]


INCLUDE_DIRS = [
    os.path.join(ROOT_DIR, "include"),
    os.path.join(ROOT_DIR, "src"),
    BINDING_DIR,
    os.path.join(ROOT_DIR, "ext", "concurrentqueue"),
    os.path.join(LWIP_DIR, "include"),
    os.path.join(LWIP_PORT_DIR, "include"),
    ZTO_DIR,
    os.path.join(ZTO_DIR, "include"),
    os.path.join(ZTO_DIR, "node"),
    os.path.join(ZTO_DIR, "osdep"),
    os.path.join(ZTO_DIR, "ext", "libnatpmp"),
    os.path.join(ZTO_DIR, "ext", "prometheus-cpp-lite-1.0", "core", "include"),
    os.path.join(ZTO_DIR, "ext", "prometheus-cpp-lite-1.0", "simpleapi", "include"),
]

ZT_MACROS = [
    ("ZT_SDK", "1"),
    ("ZT_USE_MINIUPNPC", "1"),
    ("_USING_LWIP_DEFINITIONS_", "0"),
    ("OMIT_JSON_SUPPORT", "1"),
    ("ZTS_DISABLE_CENTRAL_API", "1"),
    ("ZTS_ENABLE_PYTHON", "1"),
]

LWIP_SOURCES = sources(
    "ext/lwip/src/netif/*.c",
    "ext/lwip/src/api/*.c",
    "ext/lwip/src/core/*.c",
    "ext/lwip/src/core/ipv4/*.c",
    "ext/lwip/src/core/ipv6/*.c",
    "ext/lwip-contrib/ports/unix/port/sys_arch.c",
    exclude=["ext/lwip/src/netif/slipif.c"],
)

NATPMP_SOURCES = sources(
    "ext/ZeroTierOne/ext/libnatpmp/natpmp.c",
    "ext/ZeroTierOne/ext/libnatpmp/getgateway.c",
)

MINIUPNPC_SOURCES = sources(
    *[
        "ext/ZeroTierOne/ext/miniupnpc/" + f
        for f in [
            "connecthostport.c",
            "igd_desc_parse.c",
            "minisoap.c",
            "minissdpc.c",
            "miniupnpc.c",
            "miniwget.c",
            "minixml.c",
            "portlistingparse.c",
            "receivedata.c",
            "upnpcommands.c",
            "upnpdev.c",
            "upnperrors.c",
            "upnpreplyparse.c",
        ]
    ]
)

MINIUPNPC_MACROS = [
    ("ZT_USE_MINIUPNPC", None),
    ("MINIUPNP_STATICLIB", None),
    ("_DARWIN_C_SOURCE", None),
    ("MINIUPNPC_SET_SOCKET_TIMEOUT", None),
    ("MINIUPNPC_GET_SRC_ADDR", None),
    ("_BSD_SOURCE", None),
    ("_DEFAULT_SOURCE", None),
    ("MINIUPNPC_VERSION_STRING", '"2.0"'),
    ("UPNP_VERSION_STRING", '"UPnP/1.1"'),
    ("ENABLE_STRNATPMPERR", None),
    ("OS_STRING", '"Darwin/15.0.0"'),
]

C_LIBRARIES = [
    (
        "zt_lwip",
        {
            "sources": LWIP_SOURCES,
            "include_dirs": INCLUDE_DIRS,
            "macros": ZT_MACROS + [("LWIP_DBG_TYPES_ON", "0")],
        },
    ),
    (
        "zt_natpmp",
        {
            "sources": NATPMP_SOURCES,
            "include_dirs": INCLUDE_DIRS,
            "macros": [("NATPMP_EXPORTS", None)],
        },
    ),
    (
        "zt_miniupnpc",
        {
            "sources": MINIUPNPC_SOURCES,
            "include_dirs": INCLUDE_DIRS,
            "macros": MINIUPNPC_MACROS,
        },
    ),
]

EXTENSION = Extension(
    "libzt._libzt",
    language="c++",
    sources=[os.path.join(BINDING_DIR, "zt.i")]
    + sources("src/bindings/python/*.cxx", "src/*.cpp")
    + sources(
        "ext/ZeroTierOne/node/*.cpp",
        "ext/ZeroTierOne/osdep/OSUtils.cpp",
        "ext/ZeroTierOne/osdep/PortMapper.cpp",
    ),
    include_dirs=INCLUDE_DIRS,
    define_macros=ZT_MACROS,
    extra_compile_args=[
        "-std=c++11",
        "-Wno-unused-parameter",
        "-Wno-macro-redefined",
        "-Wno-parentheses-equality",
        "-Wno-tautological-overlap-compare",
        "-Wno-tautological-constant-out-of-range-compare",
        "-Wno-unknown-warning-option",
    ]
    if sys.platform == "darwin"
    else ["-std=c++11", "-Wno-unused-parameter"],
    swig_opts=["-c++", "-I" + os.path.join(ROOT_DIR, "include")],
)


def copy_python_files(src_dir, dst_dir):
    """Copy the pure Python modules (incl. the SWIG proxy) into the package"""
    for path in glob(os.path.join(src_dir, "*.py")):
        shutil.copy(path, os.path.join(dst_dir, os.path.basename(path)))


class BuildPy(build_py):
    def run(self):
        # The SWIG proxy module (libzt.py) is generated by build_ext
        self.run_command("build_ext")
        copy_python_files(BINDING_DIR, os.path.join(DIR, "libzt"))
        super().run()


class BuildExt(build_ext):
    def finalize_options(self):
        super().finalize_options()
        if self.parallel is None:
            self.parallel = os.cpu_count() or 1

    def run(self):
        if not os.path.exists(os.path.join(ZTO_DIR, "node", "Node.cpp")):
            subprocess.run(["git", "submodule", "update", "--init"], cwd=ROOT_DIR, check=True)
        # build_ext only links the C libraries, it does not build them
        self.run_command("build_clib")
        super().run()
        # The proxy is written next to zt.i, keep the packaged copy current
        # (also for editable/in-place builds that skip build_py)
        copy_python_files(BINDING_DIR, os.path.join(DIR, "libzt"))


shutil.copy(os.path.join(ROOT_DIR, "LICENSE.txt"), os.path.join(DIR, "LICENSE"))

setup(
    libraries=C_LIBRARIES,
    ext_modules=[EXTENSION],
    cmdclass={"build_py": BuildPy, "build_ext": BuildExt},
)
