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
