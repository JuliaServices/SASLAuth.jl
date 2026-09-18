# Exercise the actual FFI calls without a Kerberos server or C compiler.
# Keep mock symbols in a separate module so the system-library tests stay real.
module GSSAPIBufferTests
using Test
include("../src/gssapi.jl")
const G = GSSAPI
const captured = Ref(UInt8[])
const output = UInt8[7, 8, 9]
const released = Ref(0)
const status = Ref(UInt32(0))
const confidential = Ref(Cint(1))
const collected = Ref(false)

function copy_buffer(input, out, conf)
    GC.gc() # The context's finalizer must not run while native code uses it.
    buf = unsafe_load(input)
    captured[] = copy(unsafe_wrap(Array, buf.value, Int(buf.length)))
    unsafe_store!(out, G.Buffer(length(output), pointer(output)))
    unsafe_store!(conf, confidential[])
    return status[]
end
mock_wrap(minor, ctx, request, qop, input, conf, out) = copy_buffer(input, out, conf)
mock_unwrap(minor, ctx, input, out, conf, qop) = copy_buffer(input, out, conf)
function mock_release(minor, buf)
    released[] += 1
    unsafe_store!(buf, G.Buffer(0, C_NULL))
    return UInt32(0)
end
mock_status(minor, code, kind, mech, msgctx, buf) = UInt32(1)
const symbols = Dict(
    :gss_wrap => @cfunction(mock_wrap, UInt32, (Ptr{UInt32}, Ptr{Cvoid}, Cint, UInt32, Ptr{G.Buffer}, Ptr{Cint}, Ptr{G.Buffer})),
    :gss_unwrap => @cfunction(mock_unwrap, UInt32, (Ptr{UInt32}, Ptr{Cvoid}, Ptr{G.Buffer}, Ptr{G.Buffer}, Ptr{Cint}, Ptr{UInt32})),
    :gss_release_buffer => @cfunction(mock_release, UInt32, (Ptr{UInt32}, Ptr{G.Buffer})),
    :gss_display_status => @cfunction(mock_status, UInt32, (Ptr{UInt32}, UInt32, Cint, Ptr{Cvoid}, Ptr{UInt32}, Ptr{G.Buffer})),
)
@eval G sym(name::Symbol) = $(symbols)[name]

function context()
    collected[] = false
    ctx = G.Context(C_NULL, C_NULL, UInt32(0), false)
    return finalizer(_ -> (collected[] = true), ctx)
end

@testset "GSSAPI native buffers" begin
    bytes = UInt8[1, 2, 3, 4, 5]
    for operation in (G.wrap, G.unwrap), input in (bytes, @view(bytes[1:2:5]), @view(bytes[5:-1:1]), UInt8[])
        before = released[]
        @test operation(context(), input) == output
        @test captured[] == input
        @test !collected[]
        @test released[] == before + 1
        GC.gc() # Finish each context before testing the next one's lifetime.
    end
    for operation in (G.wrap, G.unwrap)
        status[] = UInt32(0x000d0000)
        before = released[]
        @test_throws G.GSSError operation(context(), bytes)
        @test released[] == before + 1
        GC.gc()
        status[] = UInt32(0)
        confidential[] = Cint(0)
        before = released[]
        @test_throws G.GSSError operation(context(), bytes)
        @test released[] == before + 1
        GC.gc()
        confidential[] = Cint(1)
    end
end
end
