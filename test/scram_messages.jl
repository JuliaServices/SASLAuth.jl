function signed_scram_final(server, bare)
    transcript = server.client_first_message_bare * "," * server.server_first_message * "," * bare
    key = SASLAuth.hmac_sha256(server.salted_password, "Client Key")
    signature = SASLAuth.hmac_sha256(SASLAuth.SHA.sha256(key), transcript)
    return bare * ",p=" * base64encode(xor.(key, signature))
end

@testset "SCRAM ordered client messages" begin
    for first in (
        "n,,r=client,n=alice", "n,,n=alice", "n,,r=client", "n,,n=,r=client",
        "n,,n=alice,r=client,r=client", "n,,n=bob,r=client",
        "n,,n=alice,r=client,n=alice", "n,,m=required,n=alice,r=client",
        "n,,n=alice,r=client,m=required", "n,,n=alice,r=client,x=",
        "n,,n=alice,r=client,xx=value", "n,,n=alice,r=client,1=value",
        "n,,n=alice,r=client,x", "n,,n=alice,r=client,",
        "n,,n=alice,r=client,x=bad\0value", "n,,n=alice,r=client,x=\xff",
        "n,,n=alice,r=client,a=alice", "n,a=alice,n=alice,r=client",
        "p=tls-unique,,n=alice,r=client", "y,,n=alice,r=client",
    )
        server = fresh_scram_server()
        @test_throws SASLAuth.SASLAuthError SASLAuth.step!(server, first)
        @test server.state == :initial
        @test server.server_first_message === nothing
        @test !SASLAuth.step!(server, "n,,n=alice,r=client")[2]
    end

    for variant in (:missing_binding, :wrong_binding, :reordered, :duplicate_nonce,
                    :duplicate_binding, :missing_proof, :proof_not_last, :duplicate_proof,
                    :mandatory, :known_extension, :empty_extension, :bad_attribute,
                    :invalid_base64, :noncanonical_base64, :whitespace_base64)
        server = fresh_scram_server()
        SASLAuth.step!(server, "n,,n=alice,r=client")
        nonce = server.combined_nonce
        bare = variant == :missing_binding ? "r=$nonce" :
               variant == :wrong_binding ? "c=eSws,r=$nonce" :
               variant == :reordered ? "r=$nonce,c=biws" :
               variant == :duplicate_nonce ? "c=biws,r=other,r=$nonce" :
               variant == :duplicate_binding ? "c=eSws,c=biws,r=$nonce" :
               "c=biws,r=$nonce"
        variant == :mandatory && (bare *= ",m=required")
        variant == :known_extension && (bare *= ",s=dGVzdA==")
        variant == :empty_extension && (bare *= ",x=")
        variant == :bad_attribute && (bare *= ",x")
        final = signed_scram_final(server, bare)
        variant == :missing_proof && (final = bare)
        variant == :proof_not_last && (final *= ",x=unsigned")
        variant == :duplicate_proof && (final *= ",p=" * split(final, ",p=")[2])
        variant == :invalid_base64 && (final = bare * ",p=A")
        variant == :noncanonical_base64 && (final = String(chop(final)))
        variant == :whitespace_base64 && (final *= "\n")
        @test SASLAuth.step!(server, final) == ("", true, false)
        @test server.state == :failed
        @test_throws SASLAuth.SASLAuthError SASLAuth.step!(server, signed_scram_final(server, "c=biws,r=$nonce"))
    end
end

@testset "SCRAM ordered server messages" begin
    for variant in (:reordered, :duplicate_nonce, :duplicate_salt, :duplicate_count,
                    :missing_salt, :missing_count, :mandatory, :late_mandatory,
                    :known_extension, :bad_attribute, :empty_extension,
                    :invalid_base64, :noncanonical_base64, :whitespace_base64, :missing)
        for verify in (true, false)
            client = SASLAuth.SCRAMSHA256Client("alice", "test-password")
            SASLAuth.step!(client, nothing)
            nonce = client.client_nonce * "server"
            good = "r=$nonce,s=dGVzdA==,i=4"
            challenge = variant == :reordered ? "s=dGVzdA==,r=$nonce,i=4" :
                        variant == :duplicate_nonce ? "r=other,r=$nonce,s=dGVzdA==,i=4" :
                        variant == :duplicate_salt ? good * ",s=dGVzdA==" :
                        variant == :duplicate_count ? good * ",i=4" :
                        variant == :missing_salt ? "r=$nonce,i=4" :
                        variant == :missing_count ? "r=$nonce,s=dGVzdA==" :
                        variant == :mandatory ? "m=required," * good :
                        variant == :late_mandatory ? good * ",m=required" :
                        variant == :known_extension ? good * ",c=biws" :
                        variant == :bad_attribute ? good * ",x" :
                        variant == :empty_extension ? good * ",x=" :
                        variant == :invalid_base64 ? "r=$nonce,s=A,i=4" :
                        variant == :noncanonical_base64 ? "r=$nonce,s=dGVzdA,i=4" :
                        variant == :whitespace_base64 ? "r=$nonce,s=dGVz dA==,i=4" : nothing
            @test_throws SASLAuth.SASLAuthError SASLAuth.step!(client, challenge; verify_server_signature=verify)
            @test client.state == :first_sent
            @test client.auth_message === nothing
            @test !SASLAuth.step!(client, good)[2]
        end
    end

    for response in ("e=invalid-proof," * RFC_SERVER_FINAL,
                     RFC_SERVER_FINAL * ",e=invalid-proof", "e=invalid-proof",
                     RFC_SERVER_FINAL * ",v=" * RFC_SERVER_FINAL[3:end],
                     "m=required," * RFC_SERVER_FINAL, RFC_SERVER_FINAL * ",m=required",
                     "x=first," * RFC_SERVER_FINAL, RFC_SERVER_FINAL * ",x=",
                     RFC_SERVER_FINAL * ",", RFC_SERVER_FINAL * ",xx=value",
                     "v=%%%", "v=A", String(chop(RFC_SERVER_FINAL)),
                     RFC_SERVER_FINAL * "=", RFC_SERVER_FINAL * "\n",
                     replace(RFC_SERVER_FINAL, "G4=" => "G5="))
        for verify in (true, false)
            client = verifier_test_client()
            SASLAuth.step!(client, RFC_CHALLENGE)
            @test_throws SASLAuth.SASLAuthError SASLAuth.step!(client, response; verify_server_signature=verify)
            @test client.state == :final_sent
            @test client.expected_server_verifier == RFC_SERVER_FINAL[3:end]
            @test SASLAuth.step!(client, RFC_SERVER_FINAL) == ("", true)
        end
    end
end

@testset "SCRAM username encoding" begin
    for username in ("alice,=admin", "=2C=3D", "a,b=c", "é=,user")
        salt = Vector{UInt8}("test-salt")
        server = SASLAuth.SCRAMSHA256Server(username,
            SASLAuth.pbkdf2(Vector{UInt8}("test-password"), salt, 4), salt, 4)
        client = SASLAuth.SCRAMSHA256Client(username, "test-password")
        first, _ = SASLAuth.step!(client, nothing)
        @test startswith(first, "n,,n=" * replace(username, "=" => "=3D", "," => "=2C") * ",r=")
        challenge, _, _ = SASLAuth.step!(server, first)
        final, _ = SASLAuth.step!(client, challenge)
        verifier, done, ok = SASLAuth.step!(server, final)
        @test done && ok
        @test SASLAuth.step!(client, verifier) == ("", true)
    end
    for encoded in ("alice=", "alice=2c", "alice=3d", "alice=2D", "alice=2", "alice=3")
        server = fresh_scram_server()
        server.username = encoded
        @test_throws SASLAuth.SASLAuthError SASLAuth.step!(server, "n,,n=$encoded,r=client")
        @test server.state == :initial
    end
    for username in ("", "bad\0name", "bad\xffname")
        @test_throws SASLAuth.SASLAuthError SASLAuth.SCRAMSHA256Client(username, "password")
    end
end

@testset "RFC 7677 server proof and verifier" begin
    salt = base64decode("W22ZaJ0SNY7soEsUEjb6gQ==")
    salted = SASLAuth.pbkdf2(Vector{UInt8}("pencil"), salt, 4096)
    server = SASLAuth.SCRAMSHA256Server("user", salted, salt, 4096,
        RFC_CLIENT_NONCE, RFC_COMBINED_NONCE[length(RFC_CLIENT_NONCE)+1:end],
        RFC_COMBINED_NONCE, RFC_CLIENT_BARE, RFC_CHALLENGE, nothing, nothing, :challenge_sent)
    @test SASLAuth.step!(server, RFC_CLIENT_FINAL) == (RFC_SERVER_FINAL, true, true)
end

@testset "SCRAM optional extensions preserve the transcript" begin
    # Unknown, case-sensitive attributes may contain '=' and UTF-8, and occur
    # more than once. They remain byte-for-byte inputs to proof verification.
    extension = ",x=first=one,M=é,x=second"
    server = fresh_scram_server()
    first = "n=alice,r=client" * extension
    challenge, _, _ = SASLAuth.step!(server, "n,," * first)
    final_bare = "c=biws,r=$(server.combined_nonce)" * extension
    final = signed_scram_final(server, final_bare)
    verifier, done, ok = SASLAuth.step!(server, final)
    @test done && ok
    @test server.auth_message == first * "," * challenge * "," * final_bare
    @test startswith(verifier, "v=")

    client = verifier_test_client()
    final, _ = SASLAuth.step!(client, RFC_CHALLENGE * extension)
    @test client.auth_message == RFC_CLIENT_BARE * "," * RFC_CHALLENGE * extension * ",c=biws,r=" * RFC_COMBINED_NONCE
    @test final != RFC_CLIENT_FINAL
    expected = client.expected_server_verifier
    @test SASLAuth.step!(client, "v=$expected" * extension) == ("", true)

    for verify in (true, false)
        client = verifier_test_client()
        SASLAuth.step!(client, RFC_CHALLENGE)
        @test SASLAuth.step!(client, RFC_SERVER_FINAL * extension; verify_server_signature=verify) == ("", true)
    end
end
