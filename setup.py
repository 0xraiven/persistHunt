from pathlib import Path
from setuptools import setup, find_packages

readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="persisthunt",
    version="0.1.0",
    description="A Linux persistence detection and security auditing framework.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="PersistHunt Contributors",
    license="MIT",
    url="https://github.com/0xraiven/persistHunt",
    project_urls={
        "Homepage": "https://github.com/0xraiven/persistHunt",
        "Documentation": "https://github.com/0xraiven/persistHunt#readme",
        "Repository": "https://github.com/0xraiven/persistHunt.git",
        "Issues": "https://github.com/0xraiven/persistHunt/issues",
        "Changelog": "https://github.com/0xraiven/persistHunt/blob/main/CHANGELOG.md",
    },
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": ["pytest>=7.0.0"],
    },
    entry_points={
        "console_scripts": [
            "persisthunt=persisthunt.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Topic :: Security",
        "Topic :: System :: Operating System",
        "Topic :: System :: Systems Administration",
    ],
)
