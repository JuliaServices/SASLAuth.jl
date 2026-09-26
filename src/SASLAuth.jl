module SASLAuth

using SHA, Base64, Random

# RFC 5802 mandated SCRAM constants
const SCRAM_CLIENT_KEY_STR = "Client Key"
const SCRAM_SERVER_KEY_STR = "Server Key"

secure_nonce(n=18) = replace(Base64.base64encode(rand(Random.RandomDevice(), UInt8, n)), "+" => "-", "/" => "_")

"""
    SASLAuth.pbkdf2(password::Vector{UInt8}, salt::Vector{UInt8}, iters::Int)

Derive a 32-byte key with PBKDF2-HMAC-SHA-256. The iteration count must be positive.
"""
function pbkdf2(password::Vector{UInt8}, salt::Vector{UInt8}, iters::Int)
    iters > 0 || throw(ArgumentError("PBKDF2 iteration count must be positive"))
    ctx = HMAC_CTX(SHA2_256_CTX(), password)
    update!(ctx, salt)
    update!(ctx, b"\x00\x00\x00\x01")
    u = digest!(ctx)
    result = copy(u)
    for _ = 2:iters
        u = hmac_sha256(password, u)
        for i in eachindex(u)
            result[i] ⊻= u[i]
        end
    end
    return result
end

struct SASLAuthError <: Exception
    msg::String
end

Base.showerror(io::IO, e::SASLAuthError) = print(io, e.msg)

abstract type SASLClient end
abstract type SASLServer end

include("scramsha256.jl")
include("plain.jl")
include("external.jl")
include("gssapi.jl")

end
