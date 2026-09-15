from setuptools import setup

setup(
    name="portscanner",
    version="1.0.0",
    py_modules=["portscanner"],
    entry_points={
        "console_scripts": [
            "portscan=portscanner:main",
        ],
    },
    python_requires=">=3.8",
)