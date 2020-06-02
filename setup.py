import pathlib
from setuptools import setup


HERE = pathlib.Path(__file__).parent


README = (HERE / "README.md").read_text()


setup(
    name="python-srp",
    version="1.0.0",
    description="SRP6a Python3 implementation according to RFC 5054 and 2945",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/quaxsze/python-srp",
    author="quaxsze",
    author_email="office@realpython.com",
    license="GNU GPLv3",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU GPLv3 License",
        "Operating System :: OS Independent",
    ],
    packages=setuptools.find_packages()
)

