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
                "asyncore",
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
                "unittest",
                "ssl",
                "_ssl",
                "hashlib",
                "pdb",
                "pickle",
                "optparse",
                "locale",
                "inspect",
                "doctest",
                "bdb",
                "calendar",
                "collections",
                "difflib",
                "gettext",
                "heapq",
                "rfc822",
                "subprocess",
                "tempfile",
                "threading",
                "tokenize",
                "httplib",
            ]
        }
    }
)