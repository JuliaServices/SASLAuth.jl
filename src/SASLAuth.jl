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

mutable struct SCRAMSHA256Client
    username::String
    password::Vector{UInt8}
    client_nonce::String
    state::Symbol
    client_first_message_bare::String
    server_first_message::Union{Nothing, String}
    auth_message::Union{Nothing, String}
end

function SCRAMSHA256Client(username, password::AbstractString)
    password_bytes = Vector{UInt8}(password)
    nonce = secure_nonce()
    bare = "n=$username,r=$nonce"
    return SCRAMSHA256Client(username, password_bytes, nonce, :initial, bare, nothing, nothing)
end

function step!(client::SCRAMSHA256Client, input::Union{Nothing, String}; verify_server_signature::Bool=true)
    # === STEP 1: Send the first message (client-first-message) ===
    if client.state == :initial
        # Compose the initial message from the client.
        # This message starts with "n,," (GS2 header indicating no channel binding)
        # followed by the "bare" part, which includes the username and client nonce.
        msg = "n,," * client.client_first_message_bare

        # Update the client state to indicate that the first message has been sent
        client.state = :first_sent

        # Return the message to send, and indicate that the exchange is not yet done
        return msg, false

    # === STEP 2: Receive server-first-message and generate proof ===
    elseif client.state == :first_sent
        # Save the server's first message for later use
        client.server_first_message = input

        # Parse server-first-message fields (e.g. r=..., s=..., i=...)
        # This gives a Dict with the combined nonce, salt, and iteration count
        parts = Dict(split(input, ',') .|> s -> split(s, '=', limit=2))

        # Decode the server-provided salt from base64 to bytes
        salt = base64decode(parts["s"])

        # Parse the iteration count as an integer
        iters = parse(Int, parts["i"])

        # Get the full combined nonce (client + server)
        combined_nonce = parts["r"]

        # === Derive the salted password via PBKDF2 using the salt and iteration count ===
        salted = pbkdf2(client.password, salt, iters)

        # Derive the client key by HMAC(salted_password, SCRAM_CLIENT_KEY_STR)
        client_key = hmac_sha256(salted, SCRAM_CLIENT_KEY_STR)

        # Hash the client key to get the "stored key"
        stored_key = SHA.sha256(client_key)

        # === Construct the final message to send (client-final-message) ===

        # The part before the proof includes:
        # - "c=biws" — base64-encoded GS2 header (indicates no channel binding)
        # - "r=..." — full combined nonce
        client_final_no_proof = "c=biws,r=$combined_nonce"

        # Construct the auth message from:
        # - client-first-message-bare
        # - server-first-message
        # - client-final-message without proof
        client.auth_message = client.client_first_message_bare * "," * input * "," * client_final_no_proof

        # Sign the auth message with the stored key to get the client signature
        signature = hmac_sha256(stored_key, client.auth_message)

        # Compute the proof as XOR(client_key, client_signature), then encode to base64
        proof = base64encode(xor.(client_key, signature))

        # Final message includes the auth fields and the proof
        msg = "$client_final_no_proof,p=$proof"

        # Update state to indicate the final message has been sent
        client.state = :final_sent

        # Return the message to send, and indicate we're still waiting for final server response
        return msg, false

    # === STEP 3: Receive final server response (e.g. verification message) ===
    elseif client.state == :final_sent
        if verify_server_signature
            # Expect server final message like: "v=base64_server_signature"
            parts = Dict(split(input, ',') .|> s -> split(s, '=', limit=2))
            server_verifier = get(parts, "v", nothing)

            if server_verifier === nothing
                throw(SASLAuthError("Missing server verifier in final SCRAM message: '$input'"))
            end

            # Re-derive salted password from client state
            salted = pbkdf2(client.password, base64decode(
                Dict(split(client.server_first_message, ',') .|> s -> split(s, '=', limit=2))["s"]),
                parse(Int, Dict(split(client.server_first_message, ',') .|> s -> split(s, '=', limit=2))["i"]),
            )

            # Compute expected server signature: HMAC(ServerKey, auth_message)
            server_key = hmac_sha256(salted, SCRAM_SERVER_KEY_STR)
            expected_signature = hmac_sha256(server_key, client.auth_message)
            expected_b64 = base64encode(expected_signature)

            if expected_b64 != server_verifier
                throw(SASLAuthError("Server signature verification failed. Expected: $expected_b64, got: $server_verifier"))
            end
        end

        # No further messages to send — just mark the protocol as done
        client.state = :done

        # Return an empty string (no message to send) and signal that the exchange is complete
        return "", true

    # === Catch invalid states ===
    else
        # If we’re in a state that shouldn’t be reached, raise an error
        error("Invalid SCRAM state: $(client.state)")
    end
end

mutable struct SCRAMSHA256Server
    username::String
    salted_password::Vector{UInt8}
    salt::Vector{UInt8}
    iterations::Int
    client_nonce::String
    server_nonce::String
    combined_nonce::String
    client_first_message_bare::String
    server_first_message::Union{Nothing, String}
    client_final_message::Union{Nothing, String}
    auth_message::Union{Nothing, String}
    state::Symbol
end

"""
    SCRAMSHA256Server(username, salted_password, salt, iterations)

Creates a new SCRAM-SHA-256 server instance to authenticate one user session.
"""
function SCRAMSHA256Server(username, salted_password, salt, iterations)
    SCRAMSHA256Server(
        username,
        salted_password,
        salt,
        iterations,
        "", "", "", "", nothing, nothing, nothing, :initial
    )
end

"""
    step!(server, client_message)

Processes the next client message and returns a 3-tuple:
- `server_reply::String`: The next message to send back to the client
- `done::Bool`: Whether the exchange is complete
- `success::Bool`: Whether authentication succeeded (if `done == true`)
"""
function step!(server::SCRAMSHA256Server, client_msg::String)
    # === STEP 1: Receive initial message from client ===
    if server.state == :initial
        # Expect a message like: "n,,n=alice,r=clientnonce"
        startswith(client_msg, "n,,") || throw(SASLAuthError("initial client message incorrectly formatted: '$client_msg'")) # Ensure correct protocol prefix

        # Parse key=value pairs after "n,,"
        # This results in a Dict like: Dict("n" => "alice", "r" => "clientnonce")
        parts = Dict(split(client_msg[4:end], ',') .|> s -> split(s, '=', limit=2))

        # Extract and store the client-provided nonce
        server.client_nonce = parts["r"]

        # Store the 'bare' part of the client's first message (excluding GS2 header "n,,")
        server.client_first_message_bare = client_msg[4:end]

        # Generate a random server-side nonce (18 lower-case ASCII letters)
        server.server_nonce = secure_nonce()

        # Concatenate client and server nonces to form the "combined nonce"
        server.combined_nonce = server.client_nonce * server.server_nonce

        # Construct the server's first message ("challenge") including:
        # - r: combined nonce
        # - s: salt (base64-encoded)
        # - i: iteration count
        challenge = "r=$(server.combined_nonce),s=$(Base64.base64encode(server.salt)),i=$(server.iterations)"

        # Store the server's first message for later use in the auth message
        server.server_first_message = challenge

        # Update internal state
        server.state = :challenge_sent

        # Return the challenge, and signal that the exchange is not done yet
        return challenge, false, false

    # === STEP 2: Receive final message from client and verify ===
    elseif server.state == :challenge_sent
        # Store the full final message from the client (e.g. "c=biws,r=...,p=...")
        server.client_final_message = client_msg

        # Parse key=value fields from the final message
        parts = Dict(split(client_msg, ',') .|> s -> split(s, '=', limit=2))

        # Extract and decode the proof from base64
        proof = Base64.base64decode(parts["p"])

        # Strip out the ",p=..." part from the final message for use in auth message construction
        client_final_wo_proof = split(client_msg, ",p=", limit=2)[1]

        # Construct the "auth message" from the three exchanged messages:
        # - client-first-bare
        # - server-first
        # - client-final-without-proof
        server.auth_message = server.client_first_message_bare * "," * server.server_first_message * "," * client_final_wo_proof

        # Derive the client's key:
        # First, HMAC(salted_password, SCRAM_CLIENT_KEY_STR) gives the client key
        client_key = hmac_sha256(server.salted_password, SCRAM_CLIENT_KEY_STR)

        # Hash the client key to produce the "stored key"
        stored_key = SHA.sha256(client_key)

        # Sign the auth message with the stored key (this is what the client would have done)
        client_signature = hmac_sha256(stored_key, server.auth_message)

        # Compute what the proof *should* be by XORing client key and the client signature
        expected_proof = xor.(client_key, client_signature)

        # If the expected proof matches what the client sent, authentication succeeded
        if expected_proof == proof
            # Generate a final verification message for the client
            # HMAC(salted_password, SCRAM_SERVER_KEY_STR) is the server key
            # Then sign the auth message and base64-encode it
            server_signature = base64encode(
                hmac_sha256(hmac_sha256(server.salted_password, SCRAM_SERVER_KEY_STR), server.auth_message)
            )

            # Update state to done
            server.state = :done

            # Send final message to client and indicate success
            return "v=$server_signature", true, true
        else
            # If the proof doesn't match, authentication failed
            server.state = :failed

            # Return empty string, mark as done, but signal failure
            return "", true, false
        end

    # === Invalid state guard ===
    else
        # If this function is called in a state where it shouldn't be, raise an error
        error("Invalid SCRAM server state: $(server.state)")
    end
end

end
