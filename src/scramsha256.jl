mutable struct SCRAMSHA256Client <: SASLClient
    username::String
    password::Vector{UInt8}
    client_nonce::String
    state::Symbol
    client_first_message_bare::String
    server_first_message::Union{Nothing, String}
    auth_message::Union{Nothing, String}
    expected_server_verifier::Union{Nothing, String}
end

valid_scram_nonce(nonce::String) = !isempty(nonce) && all(c -> 0x21 <= c <= 0x7e && c != 0x2c, codeunits(nonce))

# RFC 5802 fixes core attribute order. Only unassigned letters are optional
# extensions; ignoring their values must not remove them from the transcript.
function scram_fields(message::Union{Nothing, String}, required::Tuple; final::Union{Nothing, Char}=nothing)
    message === nothing && throw(SASLAuthError("Missing SCRAM message"))
    attributes = split(message, ',')
    length(attributes) >= length(required) + (final !== nothing) ||
        throw(SASLAuthError("Missing SCRAM attribute"))
    fields = Dict{Char, String}()
    for (i, attribute) in enumerate(attributes)
        if ncodeunits(attribute) < 2 || !('a' <= first(attribute) <= 'z' || 'A' <= first(attribute) <= 'Z') ||
                codeunit(attribute, 2) != UInt8('=')
            throw(SASLAuthError("Malformed SCRAM attribute"))
        end
        name, value = first(attribute), String(attribute[3:end])
        isvalid(value) && !occursin('\0', value) || throw(SASLAuthError("Invalid SCRAM attribute value"))
        name == 'm' && throw(SASLAuthError("Unsupported mandatory SCRAM extension"))
        expected = i <= length(required) ? required[i] : i == length(attributes) ? final : nothing
        if expected !== nothing
            name == expected || throw(SASLAuthError("Incorrect SCRAM attribute order"))
            fields[name] = value
        elseif name in "ancirspve" || isempty(value)
            throw(SASLAuthError("Invalid SCRAM extension"))
        end
    end
    return fields
end

function scram_base64(value::String)
    decoded = try
        base64decode(value)
    catch err
        err isa ArgumentError || err isa EOFError || rethrow()
        throw(SASLAuthError("Invalid SCRAM base64 value"))
    end
    # SCRAM requires canonical base64, unlike the more permissive decoder.
    base64encode(decoded) == value || throw(SASLAuthError("Invalid SCRAM base64 value"))
    return decoded
end

function scram_username(value::String)
    isempty(value) && throw(SASLAuthError("Empty SCRAM username"))
    occursin('=', replace(value, "=2C" => "", "=3D" => "")) &&
        throw(SASLAuthError("Invalid SCRAM username escape"))
    return replace(value, "=2C" => ",", "=3D" => "=")
end

function SCRAMSHA256Client(username, password::AbstractString)
    username = String(username)
    isvalid(username) && !isempty(username) && !occursin('\0', username) ||
        throw(SASLAuthError("Invalid SCRAM username"))
    password_bytes = Vector{UInt8}(password)
    nonce = secure_nonce()
    bare = "n=$(replace(username, "=" => "=3D", "," => "=2C")),r=$nonce"
    return SCRAMSHA256Client(username, password_bytes, nonce, :initial, bare, nothing, nothing)
end

# RFC 5802's posit-number is an ASCII decimal integer without a leading zero.
function scram_iterations(value::AbstractString)
    valid = !isempty(value) && '1' <= first(value) <= '9' && all(c -> '0' <= c <= '9', value)
    count = valid ? tryparse(Int, value) : nothing
    count === nothing && throw(SASLAuthError("Invalid SCRAM iteration count"))
    return count
end

# Seven-argument construction leaves the exchange verifier uncached.
SCRAMSHA256Client(username, password, nonce, state, bare, server_first, auth_message) =
    SCRAMSHA256Client(username, password, nonce, state, bare, server_first, auth_message, nothing)

function step!(client::SCRAMSHA256Client, input::Union{Nothing, String}; verify_server_signature::Bool=true)
    if client.state == :initial
        # client-first-message; the "n,," GS2 header means no channel binding
        msg = "n,," * client.client_first_message_bare
        client.state = :first_sent
        return msg, false
    elseif client.state == :first_sent
        # server-first-message: compute the proof
        parts = scram_fields(input, ('r', 's', 'i'))
        salt = scram_base64(parts['s'])
        iters = scram_iterations(parts['i'])
        combined_nonce = parts['r']
        if !valid_scram_nonce(combined_nonce) || !startswith(combined_nonce, client.client_nonce) ||
                ncodeunits(combined_nonce) <= ncodeunits(client.client_nonce)
            throw(SASLAuthError("Server nonce must extend the client nonce"))
        end
        client.server_first_message = input
        salted = pbkdf2(client.password, salt, iters)
        client_key = hmac_sha256(salted, SCRAM_CLIENT_KEY_STR)
        stored_key = SHA.sha256(client_key)
        # "biws" is base64("n,,"), the GS2 header sent in client-first-message
        client_final_no_proof = "c=biws,r=$combined_nonce"
        client.auth_message = client.client_first_message_bare * "," * input * "," * client_final_no_proof
        signature = hmac_sha256(stored_key, client.auth_message)
        proof = base64encode(xor.(client_key, signature))
        msg = "$client_final_no_proof,p=$proof"

        # Keep only the verifier for this transcript, not the derived password.
        client.expected_server_verifier = base64encode(
            hmac_sha256(hmac_sha256(salted, SCRAM_SERVER_KEY_STR), client.auth_message))
        client.state = :final_sent
        return msg, false
    elseif client.state == :final_sent
        # server-final-message: check the server signature
        # Skipping signature verification permits an omitted final message,
        # but an explicit server error or malformed message must still fail.
        parts = if input !== nothing || verify_server_signature
            first_field = input !== nothing && startswith(input, "e=") ? 'e' : 'v'
            fields = scram_fields(input, (first_field,))
            haskey(fields, 'e') && throw(SASLAuthError("SCRAM server reported an authentication error"))
            scram_base64(fields['v'])
            fields
        end
        if verify_server_signature
            server_verifier = parts['v']

            expected_b64 = client.expected_server_verifier
            if expected_b64 === nothing
                # A restored client may not have a cached verifier.
                saved = scram_fields(client.server_first_message, ('r', 's', 'i'))
                salted = pbkdf2(client.password, scram_base64(saved['s']), scram_iterations(saved['i']))
                server_key = hmac_sha256(salted, SCRAM_SERVER_KEY_STR)
                expected_b64 = base64encode(hmac_sha256(server_key, client.auth_message))
            end

            if expected_b64 != server_verifier
                throw(SASLAuthError("Server signature verification failed. Expected: $expected_b64, got: $server_verifier"))
            end
        end

        client.expected_server_verifier = nothing
        client.state = :done
        return "", true
    else
        throw(SASLAuthError("Invalid SCRAM state: $(client.state)"))
    end
end

mutable struct SCRAMSHA256Server <: SASLServer
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

Creates a new SCRAM-SHA-256 server instance to authenticate the given username
with its salted password. The iteration count must be positive. Only the
`n,,` GS2 header (no channel binding or authorization identity) is supported.
"""
function SCRAMSHA256Server(username, salted_password, salt, iterations)
    iterations > 0 || throw(ArgumentError("SCRAM iteration count must be positive"))
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
    if server.state == :initial
        # client-first-message, e.g. "n,,n=alice,r=clientnonce"
        server.iterations > 0 || throw(ArgumentError("SCRAM iteration count must be positive"))
        startswith(client_msg, "n,,") || throw(SASLAuthError("initial client message incorrectly formatted: '$client_msg'"))
        parts = scram_fields(client_msg[4:end], ('n', 'r'))
        scram_username(parts['n']) == server.username || throw(SASLAuthError("Unexpected SCRAM username"))
        nonce = parts['r']
        valid_scram_nonce(nonce) || throw(SASLAuthError("Invalid client nonce"))
        server.client_nonce = nonce
        server.client_first_message_bare = client_msg[4:end]
        server.server_nonce = secure_nonce()
        server.combined_nonce = server.client_nonce * server.server_nonce
        challenge = "r=$(server.combined_nonce),s=$(Base64.base64encode(server.salt)),i=$(server.iterations)"
        server.server_first_message = challenge
        server.state = :challenge_sent
        return challenge, false, false
    elseif server.state == :challenge_sent
        # client-final-message, e.g. "c=biws,r=...,p=..."
        server.client_final_message = client_msg

        # Any invalid final message ends this server exchange unsuccessfully.
        server.state = :failed
        parts, proof = try
            fields = scram_fields(client_msg, ('c', 'r'); final='p')
            fields, scram_base64(fields['p'])
        catch err
            err isa SASLAuthError || rethrow()
            return "", true, false
        end

        if parts['c'] != "biws" || parts['r'] != server.combined_nonce
            return "", true, false
        end

        # The parser has verified that the unique proof is the final field.
        # Keep every preceding byte, including optional extensions, unchanged.
        client_final_wo_proof = split(client_msg, ",p=", limit=2)[1]

        server.auth_message = server.client_first_message_bare * "," * server.server_first_message * "," * client_final_wo_proof
        client_key = hmac_sha256(server.salted_password, SCRAM_CLIENT_KEY_STR)
        stored_key = SHA.sha256(client_key)
        client_signature = hmac_sha256(stored_key, server.auth_message)
        expected_proof = xor.(client_key, client_signature)

        # If the expected proof matches what the client sent, authentication succeeded
        if expected_proof == proof
            # Generate a final verification message for the client
            # HMAC(salted_password, SCRAM_SERVER_KEY_STR) is the server key
            # Then sign the auth message and base64-encode it
            server_signature = base64encode(
                hmac_sha256(hmac_sha256(server.salted_password, SCRAM_SERVER_KEY_STR), server.auth_message)
            )
            server.state = :done
            return "v=$server_signature", true, true
        else
            return "", true, false
        end
    else
        throw(SASLAuthError("Invalid SCRAM server state: $(server.state)"))
    end
end
