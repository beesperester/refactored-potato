from setuptools import setup, find_packages

setup(
    name="potato",
    version="0.1.2",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    install_requires=[],
)
