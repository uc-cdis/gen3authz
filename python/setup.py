from setuptools import setup, find_packages

setup(
    name="rbac",
    version="0.1.0",
    install_requires=[
        "backoff>=1.6.0,<2.0.0",
        "cdiserrors",
        "requests>=2.18.0,<3.0.0"
    ],
    scripts=[],
    dependency_links=[
        "git+https://git@github.com/uc-cdis/cdiserrors.git@master#egg=cdiserrors",
    ],
    packages=find_packages(),
)
