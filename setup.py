from setuptools import setup, find_packages

setup(
    name="persisthunt",
    version="0.1.0",
    description="Linux Persistence Detection Framework",
    author="PersistHunt Contributors",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "persisthunt=persisthunt.cli:main",
        ],
    },
)
