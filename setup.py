from distutils.core import setup
import py2exe

setup(
    console=['bootstrap.py'],
    zipfile=None,
    options={
        "py2exe": {
            "optimize": 2,
            "compressed": True,
            "bundle_files": 1,
            "ascii": True,
            "includes": [
                "functools",
                "logging",
                "os",
                "select",
                "signal",
                "socket",
                "struct",
                "time",
                "ConfigParser",
                ],
            "excludes": [
                "_ssl",
                "bdb",
                "calendar",
                "difflib",
                "doctest",
                "gettext",
                "hashlib",
                "heapq",
                "httplib",
                "inspect",
                "locale",
                "optparse",
                "pdb",
                "pickle",
                "rfc822",
                "ssl",
                "subprocess",
                "tempfile",
                "threading",
                "tokenize",
                "unittest",
            ]
        }
    }
)