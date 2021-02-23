"""Setup script for radius-pkix-cd."""
import os
import re
from setuptools import setup


PROJECT_NAME = "radius_pkix_cd"


def get_file_contents(file_name):
    """Return the contents of a file."""
    with open(os.path.join(os.path.dirname(__file__), file_name), 'r') as f:
        return f.read()


def get_version():
    """Return the package version."""
    init_file = get_file_contents(os.path.join(PROJECT_NAME, "__init__.py"))
    rx_compiled = re.compile(r"\s*__version__\s*=\s*\"(\S+)\"")
    ver = rx_compiled.search(init_file).group(1)
    return ver


def build_long_desc():
    """Return the long description of the package."""
    return "\n".join([get_file_contents(f) for f in ["README.rst",
                                                     "CHANGELOG.rst"]])


setup(name=PROJECT_NAME,
      version=get_version(),
      author="Ash Wilson",
      author_email="ash.wilson@valimail.com",
      description="A utility for using DANE PKIX-CD with RADIUS.",
      license="BSD",
      keywords="radius pkix-cd dane tls tlsa dns certificate discovery",
      url="https://github.com/valimail/{}".format(PROJECT_NAME),
      packages=[PROJECT_NAME],
      long_description=build_long_desc(),
      install_requires=["dane-discovery==0.7"],
      entry_points={
          "console_scripts": [
              "pkix_cd_manage_trust = radius_pkix_cd.scripts.pkix_cd_manage_trust:main",
              "pkix_cd_verify = radius_pkix_cd.scripts.pkix_cd_verify:main"
          ]
      },
      classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.7",
        "Topic :: Security",
        "License :: OSI Approved :: BSD License"
        ],)
