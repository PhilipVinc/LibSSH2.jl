LibSSH2.jl
==========

*Julia wrapper for LibSSH2*

[![Build Status](https://travis-ci.com/JuliaWeb/LibCURL.jl.svg?branch=master)](https://travis-ci.com/JuliaWeb/LibCURL.jl)
[![Appveyor](https://ci.appveyor.com/api/projects/status/github/JuliaWeb/LibCurl.jl?svg=true)](https://ci.appveyor.com/project/shashi/libcurl-jl)
[![codecov.io](http://codecov.io/github/JuliaWeb/LibCURL.jl/coverage.svg?branch=master)](http://codecov.io/github/JuliaWeb/LibCURL.jl?branch=master)

---
This is a simple Julia wrapper around https://www.libssh2.org/ generated using [Clang.jl](https://github.com/ihnorton/Clang.jl). Please see the [libssh2 API documentation](https://www.libssh2.org/docs.html/) for help on how to use this package. Some functionalities are wrapped for easier use.

### Example (fetch a URL)

```julia
using LibSSH2

host = LibSSH2.SSHHost("xxxx")
LibSSH2.set_current_session(LibSSH2.SSHSession(host))
LibSSH2.authenticate!("xxxx", "xxxx")
path = LibSSH2.SFTPPath(host, "/home/xxxx")
files = readdir(path)
```
