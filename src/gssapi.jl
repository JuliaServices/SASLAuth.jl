"""
    SASLAuth.GSSAPI

Bindings to the operating system's GSSAPI library (RFC 2744), loaded lazily
through `Libdl`, with no bundled Kerberos: MIT `libgssapi_krb5` on Linux,
the Heimdal `GSS.framework` on macOS, and MIT Kerberos for Windows
(`gssapi64.dll`) on Windows. The system `krb5.conf`, credential caches, and
keytabs are used as-is, exactly as libpq, curl, and ssh do.

    ctx = GSSAPI.Context("postgres@db.example.com")
    token, done = GSSAPI.step!(ctx, nothing)      # first client token
    token, done = GSSAPI.step!(ctx, server_token) # until `done`
    GSSAPI.wrap(ctx, bytes); GSSAPI.unwrap(ctx, token)
    close(ctx)

Nothing is exported; call through `SASLAuth.GSSAPI`.
"""
module GSSAPI

using Libdl

const OM_uint32 = UInt32

# gss_buffer_desc
struct Buffer
    length::Csize_t
    value::Ptr{UInt8}
end
# gss_OID_desc is {OM_uint32 length; void *elements}. Apple's GSS framework
# headers wrap it in `#pragma pack(2)` on Intel, so there the pointer sits at
# offset 4 instead of 8; the descriptor is built as raw bytes to match.
const OID_ELEMENTS_OFFSET = Sys.isapple() && Sys.ARCH === :x86_64 ? 4 : sizeof(Ptr{Cvoid})
function oid_desc(elements::Vector{UInt8})
    desc = zeros(UInt8, OID_ELEMENTS_OFFSET + sizeof(Ptr{Cvoid}))
    desc[1:4] = reinterpret(UInt8, [OM_uint32(length(elements))])
    desc[OID_ELEMENTS_OFFSET+1:end] = reinterpret(UInt8, [UInt(pointer(elements))])
    return desc
end

# GSS_C_NT_HOSTBASED_SERVICE, 1.2.840.113554.1.2.1.4, as DER bytes: MIT and
# Heimdal export the OID under different variable names, the bytes are fixed
const NT_HOSTBASED_SERVICE = UInt8[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04]

const DELEG_FLAG = OM_uint32(1)
const MUTUAL_FLAG = OM_uint32(2)
const REPLAY_FLAG = OM_uint32(4)
const SEQUENCE_FLAG = OM_uint32(8)
const CONF_FLAG = OM_uint32(16)
const INTEG_FLAG = OM_uint32(32)
const S_COMPLETE = OM_uint32(0)
const S_CONTINUE_NEEDED = OM_uint32(1)
const C_GSS_CODE = Cint(1)
const C_MECH_CODE = Cint(2)
const C_INITIATE = Cint(1)

const LIBRARY_CANDIDATES = Sys.isapple() ? ("/System/Library/Frameworks/GSS.framework/GSS", "libgssapi_krb5.dylib") :
                           Sys.iswindows() ? ("gssapi64.dll", "gssapi32.dll") :
                           ("libgssapi_krb5.so.2", "libgssapi.so.3", "libgssapi_krb5.so")

"""
    GSSAPI.GSSError <: Exception

A GSSAPI failure. `major` and `minor` are the library status codes (both zero
when the library itself could not be loaded); `msg` carries both decoded
status strings, in libpq's `prefix: major: minor` form.
"""
struct GSSError <: Exception
    major::OM_uint32
    minor::OM_uint32
    msg::String
end
GSSError(msg::String) = GSSError(OM_uint32(0), OM_uint32(0), msg)
Base.showerror(io::IO, e::GSSError) = print(io, e.msg)

const _lib = Ref{Ptr{Cvoid}}(C_NULL)
const _lib_lock = ReentrantLock()

function library()
    @lock _lib_lock begin
        _lib[] != C_NULL && return _lib[]
        for name in LIBRARY_CANDIDATES
            handle = dlopen(name, RTLD_LAZY; throw_error=false)
            handle === nothing && continue
            _lib[] = handle
            return handle
        end
    end
    throw(GSSError("GSSAPI library not found (tried $(join(LIBRARY_CANDIDATES, ", "))); install the system Kerberos client library (krb5)"))
end

"""
    GSSAPI.available() -> Bool

Whether a GSSAPI library could be loaded on this machine.
"""
available() = (try; library(); true; catch; false; end)

sym(name::Symbol) = dlsym(library(), name)

# MIT Kerberos uses __stdcall on Windows; it differs from C on 32-bit x86.
macro gsscall(args...)
    convention = Sys.iswindows() && Sys.WORD_SIZE == 32 ? :stdcall : :cdecl
    return esc(Expr(:call, :ccall, args[1], convention, args[2:end]...))
end

# Native buffers are contiguous; views and other abstract vectors need a copy.
_bytes(data::Vector{UInt8}) = data
_bytes(data::AbstractVector{UInt8}) = collect(data)

function _release!(buf::Ref{Buffer})
    minor = Ref{OM_uint32}(0)
    @gsscall(sym(:gss_release_buffer), OM_uint32, (Ref{OM_uint32}, Ref{Buffer}), minor, buf)
    return
end

# copy a library-owned buffer out and release it
function _take!(buf::Ref{Buffer})
    b = buf[]
    out = b.length == 0 ? UInt8[] : unsafe_wrap(Array, b.value, Int(b.length))[:]
    _release!(buf)
    return out
end

function _status(code::OM_uint32, kind::Cint)
    msgs = String[]
    msgctx = Ref{OM_uint32}(0)
    minor = Ref{OM_uint32}(0)
    while true
        buf = Ref(Buffer(0, C_NULL))
        @gsscall(sym(:gss_display_status), OM_uint32,
              (Ref{OM_uint32}, OM_uint32, Cint, Ptr{Cvoid}, Ref{OM_uint32}, Ref{Buffer}),
              minor, code, kind, C_NULL, msgctx, buf) == S_COMPLETE || break
        push!(msgs, strip(String(_take!(buf))))
        msgctx[] == 0 && break
    end
    return join(msgs, " ")
end

# both halves, like libpq's pg_GSS_error
gsserror(prefix::String, major::OM_uint32, minor::OM_uint32) =
    GSSError(major, minor, string(prefix, ": ", _status(major, C_GSS_CODE), ": ", _status(minor, C_MECH_CODE)))

"""
    GSSAPI.has_credentials() -> Bool

Whether default initiator credentials (a Kerberos ticket) can be acquired.
libpq's `pg_GSS_have_cred_cache`, used to decide whether `gssencmode=prefer`
should try at all.
"""
function has_credentials()
    available() || return false
    minor = Ref{OM_uint32}(0)
    cred = Ref{Ptr{Cvoid}}(C_NULL)
    major = @gsscall(sym(:gss_acquire_cred), OM_uint32,
                  (Ref{OM_uint32}, Ptr{Cvoid}, OM_uint32, Ptr{Cvoid}, Cint, Ref{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}),
                  minor, C_NULL, 0, C_NULL, C_INITIATE, cred, C_NULL, C_NULL)
    major == S_COMPLETE || return false
    @gsscall(sym(:gss_release_cred), OM_uint32, (Ref{OM_uint32}, Ref{Ptr{Cvoid}}), minor, cred)
    return true
end

# The seam a protocol client codes against: `step!`, `wrap`, `unwrap`,
# `wrap_size_limit`, `close`. `Context` is the system-library implementation;
# a scripted context (tests) or an SSPI context (Windows) plugs in here.
abstract type AbstractContext end

"""
    GSSAPI.Context(target; delegate=false, encrypt=false) <: AbstractContext

An initiator security context for `target`, a host-based service name such
as `"postgres@db.example.com"` (`GSS_C_NT_HOSTBASED_SERVICE`). Mutual
authentication is always requested; `delegate` adds credential delegation
and `encrypt` adds the replay, sequence, confidentiality, and integrity flags
a wrapped transport needs. Drive it with `step!`, then `wrap`/`unwrap`.
"""
mutable struct Context <: AbstractContext
    handle::Ptr{Cvoid}
    target::Ptr{Cvoid}
    flags::OM_uint32
    established::Bool
end

function Context(target::AbstractString; delegate::Bool=false, encrypt::Bool=false)
    flags = MUTUAL_FLAG
    delegate && (flags |= DELEG_FLAG)
    encrypt && (flags |= REPLAY_FLAG | SEQUENCE_FLAG | CONF_FLAG | INTEG_FLAG)
    name = Ref{Ptr{Cvoid}}(C_NULL)
    minor = Ref{OM_uint32}(0)
    tgt = String(target)
    nametype = oid_desc(NT_HOSTBASED_SERVICE)
    major = GC.@preserve tgt nametype @gsscall(sym(:gss_import_name), OM_uint32,
                                            (Ref{OM_uint32}, Ref{Buffer}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                                            minor, Ref(Buffer(sizeof(tgt), pointer(tgt))), pointer(nametype), name)
    major == S_COMPLETE || throw(gsserror("GSSAPI name import error", major, minor[]))
    ctx = Context(C_NULL, name[], flags, false)
    return finalizer(close, ctx)
end

"""
    GSSAPI.step!(ctx, token::Union{Nothing, Vector{UInt8}}) -> (output::Vector{UInt8}, done::Bool)

Run one `gss_init_sec_context` round: `nothing` for the first call, then each
token the peer sends back. Send `output` to the peer when it is non-empty;
stop when `done`.
"""
function step!(ctx::Context, token::Union{Nothing, AbstractVector{UInt8}})
    ctx.established && throw(GSSError("GSSAPI security context is already established"))
    ctx.target == C_NULL && throw(GSSError("GSSAPI security context is closed"))
    input = token === nothing ? UInt8[] : _bytes(token)
    minor = Ref{OM_uint32}(0)
    out = Ref(Buffer(0, C_NULL))
    handle = Ref(ctx.handle)
    # an empty input buffer on the first call, as libpq's pqsecure_open_gss does
    major = GC.@preserve ctx input @gsscall(sym(:gss_init_sec_context), OM_uint32,
                  (Ref{OM_uint32}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}, OM_uint32, OM_uint32,
                   Ptr{Cvoid}, Ref{Buffer}, Ptr{Cvoid}, Ref{Buffer}, Ptr{OM_uint32}, Ptr{OM_uint32}),
                  minor, C_NULL, handle, ctx.target, C_NULL, ctx.flags, 0,
                  C_NULL, Ref(Buffer(length(input), isempty(input) ? C_NULL : pointer(input))), C_NULL, out, C_NULL, C_NULL)
    ctx.handle = handle[]
    output = _take!(out)
    (major == S_COMPLETE || major == S_CONTINUE_NEEDED) ||
        throw(gsserror("could not initiate GSSAPI security context", major, minor[]))
    ctx.established = major == S_COMPLETE
    return output, ctx.established
end

"""
    GSSAPI.wrap(ctx, data) -> Vector{UInt8}

Seal `data` with confidentiality (`gss_wrap`). Throws when the mechanism
would send it without confidentiality.
"""
function wrap(ctx::Context, data::AbstractVector{UInt8})
    data = _bytes(data)
    minor = Ref{OM_uint32}(0)
    conf = Ref{Cint}(0)
    out = Ref(Buffer(0, C_NULL))
    major = GC.@preserve ctx data @gsscall(sym(:gss_wrap), OM_uint32,
                  (Ref{OM_uint32}, Ptr{Cvoid}, Cint, OM_uint32, Ref{Buffer}, Ref{Cint}, Ref{Buffer}),
                  minor, ctx.handle, 1, 0, Ref(Buffer(length(data), pointer(data))), conf, out)
    output = _take!(out)
    major == S_COMPLETE || throw(gsserror("GSSAPI wrap error", major, minor[]))
    conf[] == 0 && throw(GSSError("outgoing GSSAPI message would not use confidentiality"))
    return output
end

"""
    GSSAPI.unwrap(ctx, token) -> Vector{UInt8}

Unseal a `wrap` token (`gss_unwrap`). Throws when it was not sent with
confidentiality.
"""
function unwrap(ctx::Context, token::AbstractVector{UInt8})
    token = _bytes(token)
    minor = Ref{OM_uint32}(0)
    conf = Ref{Cint}(0)
    out = Ref(Buffer(0, C_NULL))
    major = GC.@preserve ctx token @gsscall(sym(:gss_unwrap), OM_uint32,
                  (Ref{OM_uint32}, Ptr{Cvoid}, Ref{Buffer}, Ref{Buffer}, Ref{Cint}, Ptr{OM_uint32}),
                  minor, ctx.handle, Ref(Buffer(length(token), pointer(token))), out, conf, C_NULL)
    output = _take!(out)
    major == S_COMPLETE || throw(gsserror("GSSAPI unwrap error", major, minor[]))
    conf[] == 0 && throw(GSSError("incoming GSSAPI message did not use confidentiality"))
    return output
end

"""
    GSSAPI.wrap_size_limit(ctx, max_output) -> Int

The largest plaintext whose `wrap` output fits in `max_output` bytes.
"""
function wrap_size_limit(ctx::Context, max_output::Integer)
    minor = Ref{OM_uint32}(0)
    max_input = Ref{OM_uint32}(0)
    major = GC.@preserve ctx @gsscall(sym(:gss_wrap_size_limit), OM_uint32,
                  (Ref{OM_uint32}, Ptr{Cvoid}, Cint, OM_uint32, OM_uint32, Ref{OM_uint32}),
                  minor, ctx.handle, 1, 0, OM_uint32(max_output), max_input)
    major == S_COMPLETE || throw(gsserror("GSSAPI size check error", major, minor[]))
    return Int(max_input[])
end

function Base.close(ctx::Context)
    minor = Ref{OM_uint32}(0)
    if ctx.handle != C_NULL
        handle = Ref(ctx.handle)
        @gsscall(sym(:gss_delete_sec_context), OM_uint32, (Ref{OM_uint32}, Ref{Ptr{Cvoid}}, Ptr{Cvoid}), minor, handle, C_NULL)
        ctx.handle = C_NULL
    end
    if ctx.target != C_NULL
        name = Ref(ctx.target)
        @gsscall(sym(:gss_release_name), OM_uint32, (Ref{OM_uint32}, Ref{Ptr{Cvoid}}), minor, name)
        ctx.target = C_NULL
    end
    return nothing
end

end # module GSSAPI
