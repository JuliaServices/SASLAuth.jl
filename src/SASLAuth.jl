module SASLAuth

using SHA, Base64, Random

# RFC 5802 mandated SCRAM constants
const SCRAM_CLIENT_KEY_STR = "Client Key"
const SCRAM_SERVER_KEY_STR = "Server Key"

secure_nonce(n=18) = replace(Base64.base64encode(rand(Random.RandomDevice(), UInt8, n)), "+" => "-", "/" => "_")

function pbkdf2(password::Vector{UInt8}, salt::Vector{UInt8}, iters::Int)
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

end
