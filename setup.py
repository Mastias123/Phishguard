"""Setup configuration for PhishGuard."""

from setuptools import setup, find_packages

setup(
    name="phishguard",
    version="0.1.0",
    description="Provider-independent phishing detection system for emails",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="PhishGuard Contributors",
    license="MIT",
    packages=find_packages("backend"),
    package_dir={"": "backend"},
    python_requires=">=3.9",
    install_requires=[
        "email-validator>=2.0.0",
        "pydantic>=2.0.0",
        "python-dotenv>=1.0.0",
        "dnspython>=2.4.0",
    ],
    extras_require={
        "imap": ["imapclient>=3.0.0"],
        "microsoft": [
            "azure-identity>=1.13.0",
            "msgraph-core>=0.2.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pylint>=2.17.0",
        ],
        "api": [
            "fastapi>=0.100.0",
            "uvicorn>=0.23.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "phishguard=phishguard.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Communications :: Email",
        "Topic :: Security",
    ],
)
