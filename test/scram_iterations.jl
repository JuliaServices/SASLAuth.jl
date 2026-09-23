@testset "SCRAM iteration counts" begin
    password, salt = Vector{UInt8}("password"), Vector{UInt8}("salt")
    # Fixed-output PBKDF2-HMAC-SHA-256 vectors.
    for (count, expected) in (
        (1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
        (2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
    )
        salted = SASLAuth.pbkdf2(password, salt, count)
        @test bytes2hex(salted) == expected
        client = SASLAuth.SCRAMSHA256Client("fixture", "password")
        server = SASLAuth.SCRAMSHA256Server("fixture", salted, salt, count)
        first, _ = SASLAuth.step!(client, nothing)
        challenge, _, _ = SASLAuth.step!(server, first)
        proof, _ = SASLAuth.step!(client, challenge)
        final, done, success = SASLAuth.step!(server, proof)
        @test done && success
        @test SASLAuth.step!(client, final) == ("", true)
    end

    salted = SASLAuth.pbkdf2(password, salt, 1)
    for count in (0, -1, typemin(Int))
        @test_throws ArgumentError SASLAuth.pbkdf2(password, salt, count)
        @test_throws ArgumentError SASLAuth.SCRAMSHA256Server("fixture", salted, salt, count)
        # Full-field construction remains available, but cannot emit an invalid challenge.
        server = SASLAuth.SCRAMSHA256Server("fixture", salted, salt, count,
            "", "", "", "", nothing, nothing, nothing, :initial)
        @test_throws ArgumentError SASLAuth.step!(server, "n,,n=fixture,r=client")
        @test server.state == :initial
        @test server.server_first_message === nothing
    end
    server = SASLAuth.SCRAMSHA256Server("fixture", salted, salt, 1)
    server.iterations = 0
    @test_throws ArgumentError SASLAuth.step!(server, "n,,n=fixture,r=client")

    invalid = ("0", "-1", "+1", "01", " 1", "1 ", "1.0", "", "١", string(typemax(Int), "0"))
    for text in invalid
        client = SASLAuth.SCRAMSHA256Client("fixture", "password")
        SASLAuth.step!(client, nothing)
        prefix = "r=$(client.client_nonce)server,s=$(base64encode(salt)),i="
        @test_throws SASLAuth.SASLAuthError SASLAuth.step!(client, prefix * text)
        @test client.state == :first_sent
        @test client.auth_message === nothing
        @test !SASLAuth.step!(client, prefix * "1")[2]

        # Restored final-state clients must also validate saved wire counts.
        restored = SASLAuth.SCRAMSHA256Client("fixture", password, "client", :final_sent,
            "n=fixture,r=client", "r=clientserver,s=$(base64encode(salt)),i=$text", "fixture transcript")
        err = try
            SASLAuth.step!(restored, "v=fixture")
        catch caught
            caught
        end
        @test err isa SASLAuth.SASLAuthError
        @test occursin("Invalid SCRAM iteration count", sprint(showerror, err))
        @test restored.state == :final_sent
    end
    # Parsing limits are distinct from key derivation; do not perform this many iterations.
    @test SASLAuth.scram_iterations(string(typemax(Int))) == typemax(Int)
end
