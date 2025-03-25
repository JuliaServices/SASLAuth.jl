# Define EXTERNAL SASL client
mutable struct EXTERNALClient <: SASLClient
    authzid::String
    state::Symbol
end

"""
    EXTERNALClient(authzid = "")

Creates an EXTERNAL SASL client with optional authorization identity (authzid).
"""
function EXTERNALClient(authzid::String = "")
    return EXTERNALClient(authzid, :initial)
end

"""
    step!(client::EXTERNALClient, input)

Sends the optional `authzid` string.
Returns (message, done::Bool)
"""
function step!(client::EXTERNALClient, input::Union{Nothing, String})
    if client.state == :initial
        client.state = :done
        return client.authzid, true
    elseif client.state == :done
        return "", true
    else
        throw(SASLAuthError("Invalid EXTERNAL client state: $(client.state)"))
    end
end

# Define EXTERNAL SASL server
mutable struct EXTERNALServer <: SASLServer
    authorize::Function  # (authzid::String) -> Bool
    state::Symbol
end

"""
    EXTERNALServer(authorize::Function)

Create an EXTERNAL server that checks if an authzid is permitted.
"""
function EXTERNALServer(authorize::Function)
    return EXTERNALServer(authorize, :initial)
end

"""
    step!(server::EXTERNALServer, client_message)

Validates the authzid sent by the client.
Returns (response::String, done::Bool, success::Bool)
"""
function step!(server::EXTERNALServer, client_msg::String)
    if server.state == :initial
        # authzid might be "", which is valid — it means "same identity as TLS channel"
        allowed = server.authorize(client_msg)

        server.state = :done
        return "", true, allowed
    elseif server.state == :done
        return "", true, false
    else
        throw(SASLAuthError("Invalid EXTERNAL server state: $(server.state)"))
    end
end