module SASLAuth

using SHA, Base64, Random

# RFC 5802 mandated SCRAM constants
const SCRAM_CLIENT_KEY_STR = "Client Key"
const SCRAM_SERVER_KEY_STR = "Server Key"

secure_nonce(n=18) = replace(Base64.base64encode(rand(Random.RandomDevice(), UInt8, n)), "+" => "-", "/" => "_")

"""
    SASLAuth.pbkdf2(password::Vector{UInt8}, salt::Vector{UInt8}, iters::Int)

Derive a 32-byte key with PBKDF2-HMAC-SHA-256. The iteration count must be positive.
The inputs are not modified, and working hash state is local to each call.
"""
function pbkdf2(password::Vector{UInt8}, salt::Vector{UInt8}, iters::Int)
    iters > 0 || throw(ArgumentError("PBKDF2 iteration count must be positive"))
    ctx = HMAC_CTX(SHA2_256_CTX(), password)
    inner_state = copy(ctx.context.state)
    update!(ctx, salt)
    update!(ctx, b"\x00\x00\x00\x01")
    u = digest!(ctx)
    iters == 1 && return u
    result = copy(u)

    # RFC 2104 section 4: reuse the keyed states within this derivation only.
    outer = SHA2_256_CTX()
    update!(outer, ctx.outer)
    for _ = 2:iters
        _pbkdf2_hash!(ctx.context, inner_state, u)
        _pbkdf2_hash!(ctx.context, outer.state, u)
        for i in eachindex(u)
            result[i] ⊻= u[i]
        end
    end
    return result
end

# Finish SHA-256 from a prehashed 64-byte HMAC pad and a 32-byte digest.
# This uses SHA's internal state, buffer and transform! interface. transform!
# overwrites its buffer, so rebuild the entire final block before each call.
function _pbkdf2_hash!(ctx::SHA2_256_CTX, state::Vector{UInt32}, digest::Vector{UInt8})
    fill!(ctx.buffer, 0x00)
    copyto!(ctx.buffer, 1, digest, 1, 32)
    ctx.buffer[33] = 0x80
    ctx.buffer[63] = 0x03 # Big-endian bit length: (64 + 32) * 8 = 0x0300.
    copyto!(ctx.state, state)
    SHA.transform!(ctx)
    for i in eachindex(ctx.state)
        word = ctx.state[i]
        digest[4i - 3] = word >> 24
        digest[4i - 2] = (word >> 16) & 0xff
        digest[4i - 1] = (word >> 8) & 0xff
        digest[4i] = word & 0xff
    end
    return digest
end

struct SASLAuthError <: Exception
    msg::String
end

Base.showerror(io::IO, e::SASLAuthError) = print(io, e.msg)

# take a string like "a=b,c=d" and return a Dict("a" => "b", "c" => "d")
function parsekv(s::String)
    kv = Dict{String, String}()
    for pair in split(s, ',')
        k, v = split(pair, '=', limit=2)
        kv[String(k)] = String(v)
    end
    return kv
end

abstract type SASLClient end
abstract type SASLServer end

include("scramsha256.jl")
include("plain.jl")
include("external.jl")
include("gssapi.jl")

end
