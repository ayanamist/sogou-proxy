from distutils.core import setup
import py2exe

setup(
    console=['bootstrap.py'],
    options={
        "py2exe": {
            "optimize": 2,
            "compressed": True,
            "bundle_files": 2,
            "includes": [
                "__future__",
                "contextlib",
                "htmlentitydefs",
                "inspect",
                "json",
                "logging",
                "multiprocessing",
                "numbers",
                "os",
                "pkg_resources",
                "select",
                "socket",
                "struct",
                "sys",
                "time",
                "urlparse",
                "ConfigParser",
                ],
            "excludes": [
                "pyuv",
                "tornado",
                "tornado-pyuv",
            ]
        }
    }
)