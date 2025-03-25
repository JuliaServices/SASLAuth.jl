# Define the PLAIN SASL client
mutable struct PLAINClient <: SASLClient
    username::String
    password::String
    state::Symbol
end

function PLAINClient(username::String, password::String)
    return PLAINClient(username, password, :initial)
end

"""
    step!(client::PLAINClient, input)

Sends the PLAIN authentication message. Only valid once.
Returns `(msg::String, done::Bool)`.
"""
function step!(client::PLAINClient, input::Union{Nothing, String})
    if client.state == :initial
        # PLAIN format: authzid \0 authcid \0 password
        # We'll leave authzid blank ("")
        msg = string('\0', client.username, '\0', client.password)
        client.state = :done
        return msg, true
    elseif client.state == :done
        return "", true
    else
        throw(SASLAuthError("Invalid PLAIN client state: $(client.state)"))
    end
end

# Define the PLAIN SASL server
mutable struct PLAINServer <: SASLServer
    password_lookup::Function
    state::Symbol
end

"""
    PLAINServer(password_lookup::Function)

Create a PLAIN server that checks username → password via the provided lookup.
The function should return either the expected password or `nothing`.
"""
function PLAINServer(password_lookup::Function)
    return PLAINServer(password_lookup, :initial)
end

"""
    step!(server::PLAINServer, client_message::String)

Validates the client-sent message.
Returns `(response::String, done::Bool, success::Bool)`.
"""
function step!(server::PLAINServer, client_msg::String)
    if server.state == :initial
        # Split the message into its 3 components
        parts = split(client_msg, '\0')
        length(parts) != 3 && throw(SASLAuthError("Malformed PLAIN message"))

        authzid, authcid, password = parts

        expected_password = server.password_lookup(authcid)

        server.state = :done

        if expected_password !== nothing && password == expected_password
            return "", true, true
        else
            return "", true, false
        end
    elseif server.state == :done
        return "", true, false
    else
        throw(SASLAuthError("Invalid PLAIN server state: $(server.state)"))
    end
end