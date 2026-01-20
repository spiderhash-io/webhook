"""
Setup configuration for Core Webhook Module.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read version from __version__.py
version = {}
with open("src/__version__.py") as f:
    exec(f.read(), version)

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8")

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
with open(requirements_file) as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

# Development requirements
dev_requirements_file = Path(__file__).parent / "requirements-dev.txt"
dev_requirements = []
with open(dev_requirements_file) as f:
    dev_requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="core-webhook-module",
    version=version["__version__"],
    author="spiderhash-io",
    author_email="",
    description="Flexible, Secure, and Fast Webhook Handler",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/spiderhash-io/webhook",
    project_urls={
        "Bug Tracker": "https://github.com/spiderhash-io/webhook/issues",
        "Documentation": "https://github.com/spiderhash-io/webhook/blob/main/README.md",
        "Source Code": "https://github.com/spiderhash-io/webhook",
        "Changelog": "https://github.com/spiderhash-io/webhook/blob/main/CHANGELOG.md",
        "Docker Hub": "https://hub.docker.com/r/spiderhash/webhook",
    },
    packages=find_packages(exclude=["tests", "tests.*", "docs", "docker", "scripts"]),
    package_data={
        "src": ["py.typed"],
    },
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": dev_requirements,
        "all": requirements + dev_requirements,
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Framework :: FastAPI",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Topic :: System :: Networking",
        "Topic :: Communications",
        "Typing :: Typed",
    ],
    keywords=[
        "webhook",
        "fastapi",
        "api",
        "http",
        "rabbitmq",
        "redis",
        "kafka",
        "mqtt",
        "postgresql",
        "mysql",
        "s3",
        "clickhouse",
        "websocket",
        "authentication",
        "jwt",
        "hmac",
        "oauth",
        "microservices",
        "async",
        "asyncio",
    ],
    entry_points={
        "console_scripts": [
            "webhook-server=src.main:main",
        ],
    },
    license="MIT",
    zip_safe=False,
)
