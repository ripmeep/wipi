#!/usr/bin/env python3

from distutils.core import setup, Extension

setup(name="wipi", version="1.0.0",
	ext_modules=[
		Extension(
			"wipi", ["pywipi.c", "../src/wipi.c"],
			extra_link_args=["-liw"],
			include_dirs=["../src"],
            extra_compile_args=["-Wno-unused-function", "-Wno-unused-variable"]
		)
	]
)
