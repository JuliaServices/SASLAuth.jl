function fresh_scram_server()
    salt = collect(codeunits("test-salt"))
    salted = SASLAuth.pbkdf2(collect(codeunits("test-password")), salt, 4)
    return SASLAuth.SCRAMSHA256Server("alice", salted, salt, 4)
end

function final_with_nonce(server, nonce)
    bare = "c=biws,r=$nonce"
    transcript = server.client_first_message_bare * "," * server.server_first_message * "," * bare
    key = SASLAuth.hmac_sha256(server.salted_password, SASLAuth.SCRAM_CLIENT_KEY_STR)
    signature = SASLAuth.hmac_sha256(SASLAuth.SHA.sha256(key), transcript)
    return bare * ",p=" * base64encode(xor.(key, signature))
end

@testset "SCRAM nonce continuity" begin
    for variant in (:unrelated, :unchanged, :truncated)
        client = SASLAuth.SCRAMSHA256Client("alice", "test-password")
        SASLAuth.step!(client, nothing)
        nonce = variant == :unrelated ? "differentnonce" : variant == :unchanged ? client.client_nonce : client.client_nonce[1:end-1]
        challenge = "r=$nonce,s=$(base64encode("test-salt")),i=4"
        @test_throws SASLAuth.SASLAuthError SASLAuth.step!(client, challenge)
    end
    for nonce in ("unrelatednonce", "clientnonce")
        server = fresh_scram_server()
        SASLAuth.step!(server, "n,,n=alice,r=clientnonce")
        _, done, success = SASLAuth.step!(server, final_with_nonce(server, nonce))
        @test done
        @test !success
        @test server.state == :failed
    end
    for nonce in ("", "bad\nnonce")
        server = fresh_scram_server()
        @test_throws SASLAuth.SASLAuthError SASLAuth.step!(server, "n,,n=alice,r=$nonce")
    end
    server = fresh_scram_server()
    client = SASLAuth.SCRAMSHA256Client("alice", "test-password")
    first, _ = SASLAuth.step!(client, nothing)
    challenge, _, _ = SASLAuth.step!(server, first)
    proof, _ = SASLAuth.step!(client, challenge)
    verifier, done, success = SASLAuth.step!(server, proof)
    @test done && success
    @test SASLAuth.step!(client, verifier) == ("", true)
end

@testset "SCRAM nonce validation boundaries" begin
    for suffix in ("\n", "\0", "é", " "), verify in (true, false)
        client = SASLAuth.SCRAMSHA256Client("alice", "test-password")
        SASLAuth.step!(client, nothing)
        challenge = "r=$(client.client_nonce)$suffix,s=$(base64encode("test-salt")),i=4"
        @test_throws SASLAuth.SASLAuthError SASLAuth.step!(client, challenge; verify_server_signature=verify)
    end
    for verify in (true, false)
        client = SASLAuth.SCRAMSHA256Client("alice", "test-password")
        SASLAuth.step!(client, nothing)
        @test_throws SASLAuth.SASLAuthError SASLAuth.step!(client, "s=dGVzdA==,i=4"; verify_server_signature=verify)
        @test client.state == :first_sent
        message, done = SASLAuth.step!(client, "r=$(client.client_nonce)!,s=dGVzdA==,i=4")
        @test startswith(message, "c=biws,r=$(client.client_nonce)!,p=")
        @test !done
    end
    server = fresh_scram_server()
    @test_throws SASLAuth.SASLAuthError SASLAuth.step!(server, "n,,n=alice")
    SASLAuth.step!(server, "n,,n=alice,r=clientnonce")
    @test SASLAuth.step!(server, "c=biws,p=") == ("", true, false)
    @test_throws SASLAuth.SASLAuthError SASLAuth.step!(server, final_with_nonce(server, server.combined_nonce))
end

@testset "RFC 7677 client exchange" begin
    client = SASLAuth.SCRAMSHA256Client("user", "pencil")
    client.client_nonce = "rOprNGfwEbeRWgbNEkqO"
    client.client_first_message_bare = "n=user,r=$(client.client_nonce)"
    nonce = raw"rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
    @test SASLAuth.step!(client, nothing) == ("n,,n=user,r=$(client.client_nonce)", false)
    challenge = "r=$nonce,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
    @test SASLAuth.step!(client, challenge) == ("c=biws,r=$nonce,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=", false)
    @test SASLAuth.step!(client, "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=") == ("", true)
end
