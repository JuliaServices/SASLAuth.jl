# SASLAuth.jl

[![](https://img.shields.io/badge/docs-stable-blue.svg)](https://JuliaServices.github.io/SASLAuth.jl/stable)
[![](https://img.shields.io/badge/docs-dev-blue.svg)](https://JuliaServices.github.io/SASLAuth.jl/dev)
[![Build Status](https://github.com/JuliaServices/SASLAuth.jl/workflows/CI/badge.svg)](https://github.com/JuliaServices/SASLAuth.jl/actions?query=workflow%3ACI+branch%3Amaster)
[![codecov.io](http://codecov.io/github/JuliaServices/SASLAuth.jl/coverage.svg?branch=master)](http://codecov.io/github/JuliaServices/SASLAuth.jl?branch=master)

---

## 🔐 Overview

**SASLAuth.jl** is a pure Julia implementation of the [Simple Authentication and Security Layer (SASL)](https://tools.ietf.org/html/rfc4422) framework. It provides both client and server support for multiple authentication mechanisms, suitable for implementing protocol layers such as IMAP, LDAP, SMTP, XMPP, or custom client-server auth.

Supported mechanisms:

- ✅ `SCRAM-SHA-256` — secure, salted password-based challenge-response
- ✅ `PLAIN` — simple username/password (must be used over TLS)
- ✅ `EXTERNAL` — identity established by external means (e.g. TLS client cert)

---

## 📦 Installation

Install from the Julia registry:

```julia
using Pkg
Pkg.add("SASLAuth")
```

For the development version:

```julia
Pkg.add(url="https://github.com/JuliaServices/SASLAuth.jl")
```

---

## 📘 Usage

### Common API

Each mechanism provides:

- `Client <: SASLClient`
- `Server <: SASLServer`

With the shared interface:

- `step!(client::SASLClient, input) → (message, done::Bool)`
- `step!(server::SASLServer, input) → (reply, done::Bool, success::Bool)`

---

## 🔐 SCRAM-SHA-256

### Client

```julia
client = SCRAMSHA256Client("alice", "correcthorsebatterystaple")

msg1, _ = step!(client, nothing)
msg2, _ = step!(client, "r=nonceXYZ,s=\$(Base64.base64encode("salt")),i=4096")
msg3, _ = step!(client, "v=\$(Base64.base64encode("serversignature"))"; verify_server_signature=false)
```

### Server

```julia
salt = rand(UInt8, 16)
iterations = 4096
salted_password = pbkdf2(Vector{UInt8}("correcthorsebatterystaple"), salt, iterations)

server = SCRAMSHA256Server("alice", salted_password, salt, iterations)

challenge, _, _ = step!(server, msg1)
response, done, success = step!(server, msg2)
```

---

## 🧾 PLAIN

```julia
client = PLAINClient("alice", "hunter2")
msg, _ = step!(client, nothing)

server = PLAINServer(username -> username == "alice" ? "hunter2" : nothing)
_, _, ok = step!(server, msg)
```

---

## 🌐 EXTERNAL

```julia
client = EXTERNALClient("alice")
msg, _ = step!(client, nothing)

server = EXTERNALServer(authzid -> authzid == "alice")
_, _, ok = step!(server, msg)
```

---

## 🧪 Running Tests

```julia
using Pkg
Pkg.test("SASLAuth")
```

---

## 📄 License

MIT © 2024 JuliaServices