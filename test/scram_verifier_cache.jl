# Public test transcript from RFC 7677 section 3.
const RFC_CLIENT_NONCE = "rOprNGfwEbeRWgbNEkqO"
const RFC_CLIENT_BARE = "n=user,r=" * RFC_CLIENT_NONCE
const RFC_COMBINED_NONCE = RFC_CLIENT_NONCE * raw"%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
const RFC_CHALLENGE = "r=$RFC_COMBINED_NONCE,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
const RFC_CLIENT_FINAL = "c=biws,r=$RFC_COMBINED_NONCE,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
const RFC_SERVER_FINAL = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="

function verifier_test_client()
    client = SASLAuth.SCRAMSHA256Client("user", "pencil")
    client.client_nonce = RFC_CLIENT_NONCE
    client.client_first_message_bare = RFC_CLIENT_BARE
    SASLAuth.step!(client, nothing)
    return client
end

@testset "SCRAM verifier reuse" begin
    client = verifier_test_client()
    @test SASLAuth.step!(client, RFC_CHALLENGE) == (RFC_CLIENT_FINAL, false)
    @test client.expected_server_verifier == RFC_SERVER_FINAL[3:end]
    @test SASLAuth.step!(client, RFC_SERVER_FINAL) == ("", true)
    @test client.expected_server_verifier === nothing
    @test client.state == :done

    for response in ("e=invalid-proof", "v=wrong")
        client = verifier_test_client()
        SASLAuth.step!(client, RFC_CHALLENGE)
        @test_throws SASLAuth.SASLAuthError SASLAuth.step!(client, response)
        @test client.state == :final_sent
        @test client.expected_server_verifier == RFC_SERVER_FINAL[3:end]
        @test SASLAuth.step!(client, RFC_SERVER_FINAL) == ("", true)
    end

    client = verifier_test_client()
    SASLAuth.step!(client, RFC_CHALLENGE)
    @test SASLAuth.step!(client, nothing; verify_server_signature=false) == ("", true)
    @test client.expected_server_verifier === nothing

    # The original full-field constructor can restore either exchange phase.
    client = SASLAuth.SCRAMSHA256Client("user", Vector{UInt8}("pencil"),
        RFC_CLIENT_NONCE, :first_sent, RFC_CLIENT_BARE, nothing, nothing)
    @test SASLAuth.step!(client, RFC_CHALLENGE) == (RFC_CLIENT_FINAL, false)
    restored = SASLAuth.SCRAMSHA256Client(client.username, client.password,
        client.client_nonce, client.state, client.client_first_message_bare,
        client.server_first_message, client.auth_message)
    @test restored.expected_server_verifier === nothing
    @test SASLAuth.step!(restored, RFC_SERVER_FINAL) == ("", true)

    # A repeated PBKDF2 derivation allocates megabytes at this iteration count.
    # Warm final verification first and allocate the prepared clients outside
    # the measurement, leaving room for parsing the small verifier message.
    client = verifier_test_client()
    SASLAuth.step!(client, RFC_CHALLENGE)
    SASLAuth.step!(client, RFC_SERVER_FINAL)
    for _ in 1:3
        client = verifier_test_client()
        SASLAuth.step!(client, RFC_CHALLENGE)
        @test (@allocated SASLAuth.step!(client, RFC_SERVER_FINAL)) < 16_384
        @test client.state == :done
    end
end
