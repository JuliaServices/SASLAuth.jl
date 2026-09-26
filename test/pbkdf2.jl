@testset "PBKDF2 SHA-256 state reuse" begin
    # Independent Python hashlib.pbkdf2_hmac("sha256", password, salt, count, 32)
    # vectors span HMAC's 64-byte key boundary and SHA-256 salt padding boundaries.
    for (password_length, salt_length, count, expected) in (
        (0, 0, 1, "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad"),
        (0, 16, 4096, "cc43c9f3fc6e2051a019dfb09c4168a57ef91dcf11f14f99af0feb350ec785f8"),
        (1, 0, 2, "ab25e885168a25086530e110891b0326b40ee859e863ebcbc25f4eb0a47c9040"),
        (63, 51, 3, "a88f2e2f05f09771f0be012ce8c2e4813e3bb0f6cf8b06b942aa3ab115b21116"),
        (64, 52, 17, "13a161ebba2f65302b06f33dce6a0613e9e1899e4cef9b2ad2d05c5bea5a73e6"),
        (65, 59, 4096, "7b0c47afc455a9128493b4a3db4e370a78ee5fa722b0fc8edf6adef6023496cb"),
        (127, 60, 3, "ed949a64dd1d09bb20a7831573e2eee288fc5fc78d1518d819111115dfc92beb"),
        (128, 63, 17, "de44e49151835f3a78fb33121fef81cee8556ade8a14904c69c944ce4a54af38"),
        (129, 64, 2, "6bfff6fd3892cb80817a56288d6509d9755da7883c9a40533aa34493c1015c03"),
        (1024, 65, 4096, "3adae9fe10ec5d43a01c252ce77f282cc871f4167a9ca72a8076d6259d8530b7"),
        (65, 128, 2, "767a13accb5ba492bb245794ff3dec8b27b46a8a9a2cbf139d12c0122c07d0f4"),
        (64, 1024, 17, "61aa09435d47e13dc516762118ae94bc0cc1c2f8246123399beea4eacf977926"),
    )
        password = UInt8[(37i + 11) % 256 for i in 1:password_length]
        salt = UInt8[(19i + 3) % 256 for i in 1:salt_length]
        original_password, original_salt = copy(password), copy(salt)
        result = SASLAuth.pbkdf2(password, salt, count)
        @test bytes2hex(result) == expected
        @test password == original_password
        @test salt == original_salt
        result[1] ⊻= 0xff
        @test bytes2hex(SASLAuth.pbkdf2(password, salt, count)) == expected
    end

    for password_length in (6, 64, 65, 128)
        password, salt = fill(0x70, password_length), fill(0x73, 16)
        SASLAuth.pbkdf2(password, salt, 2)
        SASLAuth.pbkdf2(password, salt, 4096)
        short = @allocated SASLAuth.pbkdf2(password, salt, 2)
        long = @allocated SASLAuth.pbkdf2(password, salt, 4096)
        # Additional iterations reuse the same buffers instead of allocating HMACs.
        @test long <= short + 1024
        @test long < 8192
    end
end
