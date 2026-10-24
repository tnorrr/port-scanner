from setuptools import setup

setup(
    name="portscanner",
    version="1.1.0",
    description="Multithreaded TCP port scanner with banner grabbing",
    license="MIT",
    py_modules=["portscanner"],
    install_requires=["tqdm"],
    entry_points={
        "console_scripts": [
            "portscan=portscanner:main",
        ],
    },
    python_requires=">=3.8",
)