using Test, Base64, SASLAuth

@testset "SCRAM SHA-256 Flow" begin
    client = SASLAuth.SCRAMSHA256Client("bob", "secr3t")
    msg1, done1 = SASLAuth.step!(client, nothing)
    @test startswith(msg1, "n,,n=bob,r=")
    @test !done1

    # Simulate a server message
    server_first = "r=$(client.client_nonce)xyz,s=$(Base64.base64encode("salt")),i=4096"
    msg2, done2 = SASLAuth.step!(client, server_first)
    @test occursin("c=biws", msg2)
    @test !done2

    # Final step (server final message)
    msg3, done3 = SASLAuth.step!(client, "v=abc123"; verify_server_signature=false)
    @test done3
end

@testset "SCRAM Server Auth Success" begin
    username = "alice"
    password = "correcthorsebatterystaple"
    salt = rand(UInt8, 16)
    iterations = 4096
    salted = SASLAuth.pbkdf2(Vector{UInt8}(password), salt, iterations)

    server = SASLAuth.SCRAMSHA256Server(username, salted, salt, iterations)
    client = SASLAuth.SCRAMSHA256Client(username, password)

    msg1, _ = SASLAuth.step!(client, nothing)
    msg2, _, _ = SASLAuth.step!(server, msg1)
    msg3, _ = SASLAuth.step!(client, msg2)
    final, done, success = SASLAuth.step!(server, msg3)
    _, client_done = SASLAuth.step!(client, final)

    @test success
    @test done
    @test startswith(final, "v=")
    @test client_done
end

@testset "SCRAM Client Verifies Server Signature" begin
    client = SASLAuth.SCRAMSHA256Client("bob", "secr3t")
    msg1, _ = SASLAuth.step!(client, nothing)

    server_first = "r=$(client.client_nonce)xyz,s=$(Base64.base64encode("salt")),i=4096"
    msg2, _ = SASLAuth.step!(client, server_first)

    @test_throws SASLAuth.SASLAuthError SASLAuth.step!(client, "v=invalid_signature")
end

@testset "SCRAM Server Detects Invalid Client Proof" begin
    username = "bob"
    password = "secret"
    salt = rand(UInt8, 16)
    iterations = 4096
    salted = SASLAuth.pbkdf2(Vector{UInt8}(password), salt, iterations)

    server = SASLAuth.SCRAMSHA256Server(username, salted, salt, iterations)

    # Tampered proof
    client_msg1 = "n,,n=bob,r=badnonce"
    challenge, _, _ = SASLAuth.step!(server, client_msg1)
    bad_client_final = "c=biws,r=badnoncexyz,p=ZmFrZXByb29m"  # base64("fakeproof")
    _, done, success = SASLAuth.step!(server, bad_client_final)

    @test done
    @test !success
end

@testset "SCRAM Client Rejects Invalid State" begin
    client = SASLAuth.SCRAMSHA256Client("bob", "pass")
    client.state = :done
    @test_throws SASLAuth.SASLAuthError SASLAuth.step!(client, "v=...")
end

@testset "PLAIN Authentication" begin
    using SASLAuth

    client = SASLAuth.PLAINClient("alice", "hunter2")
    server = SASLAuth.PLAINServer(username -> username == "alice" ? "hunter2" : nothing)

    msg, done = SASLAuth.step!(client, nothing)
    @test done
    @test msg == "\0alice\0hunter2"

    resp, done, ok = SASLAuth.step!(server, msg)
    @test done
    @test ok
end

@testset "PLAIN Authentication Failure" begin
    client = SASLAuth.PLAINClient("alice", "wrongpw")
    server = SASLAuth.PLAINServer(username -> username == "alice" ? "hunter2" : nothing)

    msg, _ = SASLAuth.step!(client, nothing)
    _, _, ok = SASLAuth.step!(server, msg)

    @test !ok
end

@testset "PLAIN Malformed Message" begin
    server = SASLAuth.PLAINServer(_ -> true)
    @test_throws SASLAuth.SASLAuthError SASLAuth.step!(server, "invalid_plain")
end

@testset "EXTERNAL Authentication Success" begin
    client = SASLAuth.EXTERNALClient("alice")
    server = SASLAuth.EXTERNALServer(authzid -> authzid == "alice")

    msg, done = SASLAuth.step!(client, nothing)
    @test done
    @test msg == "alice"

    _, done, ok = SASLAuth.step!(server, msg)
    @test done
    @test ok
end

@testset "EXTERNAL Authentication Failure" begin
    client = SASLAuth.EXTERNALClient("bob")
    server = SASLAuth.EXTERNALServer(authzid -> authzid == "alice")  # only "alice" allowed

    msg, _ = SASLAuth.step!(client, nothing)
    _, _, ok = SASLAuth.step!(server, msg)
    @test !ok
end

@testset "EXTERNAL Empty Authzid Allowed" begin
    client = SASLAuth.EXTERNALClient()
    server = SASLAuth.EXTERNALServer(authzid -> authzid == "")

    msg, _ = SASLAuth.step!(client, nothing)
    _, _, ok = SASLAuth.step!(server, msg)
    @test ok
end
