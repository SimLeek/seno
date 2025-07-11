from setuptools import setup, find_packages

setup(
    name="distributed_scheduler",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "ortools>=9.14.6206",
    ],
    author="xAI",
    description="Distributed program scheduler for robot systems",
    python_requires=">=3.9",
)