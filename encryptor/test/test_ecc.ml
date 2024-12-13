open OUnit2
include Encryptor.Ecc

(* Constants for ECC testing *)
let base_point = ECC.Point (3, 6)
let a = 2
let b = 3
let p = 97
let n = 5

(* Helper: Assert a point is valid on the curve *)
let assert_point_valid point =
  match point with
  | ECC.Point (x, y) ->
      assert_bool "Point must be on the curve" (ECC.is_on_curve (x, y) a b p)
  | Infinity -> ()

(* Test: Key generation produces valid keys *)
let ecc_key_generation_test1 _ =
  let keys = ECC.generate_keys base_point a b p n in
  assert_point_valid keys.public_key

(* Test: Multiple key generations produce distinct keys *)
let ecc_key_generation_test2 _ =
  let keys1 = ECC.generate_keys base_point a b p n in
  let keys2 = ECC.generate_keys base_point a b p n in
  assert_bool "Keys must be distinct" (keys1.public_key <> keys2.public_key)

(* Test: Scalar multiplication with small scalar *)
let ecc_scalar_mult_test1 _ =
  let scalar = 3 in
  let result = ECC.scalar_mult scalar base_point a p in
  assert_point_valid result

(* Test: Scalar multiplication with large scalar *)
let ecc_scalar_mult_test2 _ =
  let scalar = 50 in
  let result = ECC.scalar_mult scalar base_point a p in
  assert_point_valid result

(* Test: Scalar multiplication with scalar = 0 *)
let ecc_scalar_mult_zero_test _ =
  let scalar = 0 in
  let result = ECC.scalar_mult scalar base_point a p in
  assert_equal ECC.Infinity result

(* Test: Scalar multiplication for multiple random scalars *)
let ecc_scalar_mult_random_test _ =
  for _ = 1 to 10 do
    let scalar = Random.int 100 in
    let result = ECC.scalar_mult scalar base_point a p in
    assert_point_valid result
  done

(* Test: Point addition with distinct points *)
let ecc_point_addition_test1 _ =
  let point1 = base_point in
  let point2 = ECC.Point (80, 10) in
  let result = ECC.add point1 point2 a p in
  assert_point_valid result

(* Test: Point addition where one point is Infinity *)
let ecc_point_addition_infinity_test _ =
  let result = ECC.add base_point ECC.Infinity a p in
  assert_equal base_point result

(* Test: Point addition with the same point *)
let ecc_point_addition_self_test _ =
  let result = ECC.add base_point base_point a p in
  assert_point_valid result

(* Test: Point addition for multiple random points *)
let ecc_point_addition_random_test _ =
  for _ = 1 to 10 do
    let x1 = Random.int p in
    let y1 = Random.int p in
    let x2 = Random.int p in
    let y2 = Random.int p in
    if ECC.is_on_curve (x1, y1) a b p && ECC.is_on_curve (x2, y2) a b p then
      let point1 = ECC.Point (x1, y1) in
      let point2 = ECC.Point (x2, y2) in
      let result = ECC.add point1 point2 a p in
      assert_point_valid result
  done

(* Test: Encrypt and decrypt a small message *)
let ecc_encrypt_decrypt_test_small _ =
  let keys = ECC.generate_keys base_point a b p n in
  let message = 42 in
  let c1, c2 = ECC.encrypt message base_point keys.public_key a b p n in
  let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
  assert_equal message decrypted_message

(* Test: Encrypt and decrypt a large message *)
let ecc_encrypt_decrypt_test_large _ =
  let keys = ECC.generate_keys base_point a b p n in
  let message = 89 in
  let c1, c2 = ECC.encrypt message base_point keys.public_key a b p n in
  let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
  assert_equal message decrypted_message

(* Test: Encrypt and decrypt for multiple random messages *)
let ecc_encrypt_decrypt_random_test _ =
  for _ = 1 to 10 do
    let keys = ECC.generate_keys base_point a b p n in
    let message = Random.int (p - 1) in
    let c1, c2 = ECC.encrypt message base_point keys.public_key a b p n in
    let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
    assert_equal message decrypted_message
  done

(* Test: Decrypt failure with incorrect private key *)
let ecc_decrypt_failure_wrong_key _ =
  let keys = ECC.generate_keys base_point a b p n in
  let wrong_keys = ECC.generate_keys base_point a b p n in
  let message = 50 in
  let c1, c2 = ECC.encrypt message base_point keys.public_key a b p n in
  assert_raises (Failure "Decryption failed") (fun () ->
      ECC.decrypt (c1, c2) wrong_keys.private_key a p)

(* Test: Decrypt failure with tampered ciphertext *)
let ecc_decrypt_failure_tampered_cipher _ =
  let keys = ECC.generate_keys base_point a b p n in
  let message = 42 in
  let c1, _ = ECC.encrypt message base_point keys.public_key a b p n in
  let tampered_c2 = ECC.Point (0, 0) in
  assert_raises (Failure "Decryption failed") (fun () ->
      ECC.decrypt (c1, tampered_c2) keys.private_key a p)

(* Test: Edge case messages for encryption and decryption *)
let ecc_encrypt_decrypt_edge_cases _ =
  let keys = ECC.generate_keys base_point a b p n in
  List.iter
    (fun msg ->
      let c1, c2 = ECC.encrypt msg base_point keys.public_key a b p n in
      let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
      assert_equal msg decrypted_message)
    [ 0; 1; p - 1; 50; 97 ]

(* Test: Point addition with invalid points *)
let ecc_point_addition_invalid_points_test _ =
  let invalid_point = ECC.Point (100, 200) in
  assert_raises (Failure "Invalid point") (fun () ->
      ECC.add invalid_point base_point a p)

(* Test: Scalar multiplication with very large scalar *)
let ecc_scalar_mult_large_scalar_test _ =
  let scalar = 10_000 in
  let result = ECC.scalar_mult scalar base_point a p in
  assert_point_valid result

(* Test: Key generation with boundary values for n *)
let ecc_key_generation_boundary_test _ =
  let keys1 = ECC.generate_keys base_point a b p 1 in
  let keys2 = ECC.generate_keys base_point a b p (n - 1) in
  assert_point_valid keys1.public_key;
  assert_point_valid keys2.public_key

(* Test: Check identity property for addition *)
let ecc_point_addition_identity_property_test _ =
  let result1 = ECC.add base_point ECC.Infinity a p in
  let result2 = ECC.add ECC.Infinity base_point a p in
  assert_equal base_point result1;
  assert_equal base_point result2

(* Test: Verify commutative property of point addition *)
let ecc_point_addition_commutative_test _ =
  let point1 = ECC.scalar_mult 5 base_point a p in
  let point2 = ECC.scalar_mult 3 base_point a p in
  let result1 = ECC.add point1 point2 a p in
  let result2 = ECC.add point2 point1 a p in
  assert_equal result1 result2

(* Test: Verify associative property of point addition *)
let ecc_point_addition_associative_test _ =
  let point1 = ECC.scalar_mult 2 base_point a p in
  let point2 = ECC.scalar_mult 3 base_point a p in
  let point3 = ECC.scalar_mult 4 base_point a p in
  let result1 = ECC.add point1 (ECC.add point2 point3 a p) a p in
  let result2 = ECC.add (ECC.add point1 point2 a p) point3 a p in
  assert_equal result1 result2

(* Test: Ensure encrypt-decrypt preserves message integrity for boundary
   messages *)
let ecc_encrypt_decrypt_boundary_test _ =
  let keys = ECC.generate_keys base_point a b p n in
  List.iter
    (fun msg ->
      let c1, c2 = ECC.encrypt msg base_point keys.public_key a b p n in
      let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
      assert_equal msg decrypted_message)
    [ 0; p - 1 ]

(* Test: Validate that key generation produces unique private keys *)
let ecc_private_key_uniqueness_test _ =
  let keys1 = ECC.generate_keys base_point a b p n in
  let keys2 = ECC.generate_keys base_point a b p n in
  assert_bool "Private keys must be distinct"
    (keys1.private_key <> keys2.private_key)

(* Test: Validate point multiplication with negative scalar *)
let ecc_scalar_mult_negative_test _ =
  let scalar = -3 in
  assert_raises (Failure "Negative scalar") (fun () ->
      ECC.scalar_mult scalar base_point a p)

(* Test: Ensure point doubling works correctly *)
let ecc_point_doubling_test _ =
  let result = ECC.add base_point base_point a p in
  assert_point_valid result

(* Test: Ensure that scalar multiplication by 1 returns the original point *)
let ecc_scalar_mult_identity_test _ =
  let result = ECC.scalar_mult 1 base_point a p in
  assert_equal base_point result

(* Test: Scalar multiplication with maximum scalar value *)
let ecc_scalar_mult_max_scalar_test _ =
  let scalar = max_int mod p in
  let result = ECC.scalar_mult scalar base_point a p in
  assert_point_valid result

(* Test: Encrypt-decrypt with large messages *)
let ecc_encrypt_decrypt_large_message_test _ =
  let keys = ECC.generate_keys base_point a b p n in
  let message = p - 10 in
  let c1, c2 = ECC.encrypt message base_point keys.public_key a b p n in
  let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
  assert_equal message decrypted_message

(* Test: Ensure point addition with invalid points raises an exception *)
let ecc_point_addition_invalid_test _ =
  let invalid_point = ECC.Point (1000, 2000) in
  assert_raises (Failure "Invalid point") (fun () ->
      ECC.add base_point invalid_point a p)

(* Test: Scalar multiplication with zero returns Infinity *)
let ecc_scalar_mult_zero_return_infinity_test _ =
  let result = ECC.scalar_mult 0 base_point a p in
  assert_equal ECC.Infinity result

(* Test: Validate that multiples of a point are on the curve *)
let ecc_validate_multiples_test _ =
  for i = 1 to 20 do
    let result = ECC.scalar_mult i base_point a p in
    assert_point_valid result
  done

(* Test: Randomized key generation produces valid public keys *)
let ecc_random_key_generation_test _ =
  for _ = 1 to 20 do
    let keys = ECC.generate_keys base_point a b p n in
    assert_point_valid keys.public_key
  done

(* Test: Randomized point addition produces valid results *)
let ecc_random_point_addition_test _ =
  for _ = 1 to 20 do
    let scalar1 = Random.int 50 in
    let scalar2 = Random.int 50 in
    let point1 = ECC.scalar_mult scalar1 base_point a p in
    let point2 = ECC.scalar_mult scalar2 base_point a p in
    let result = ECC.add point1 point2 a p in
    assert_point_valid result
  done

(* Test: Verify that decrypting an unencrypted message raises an error *)
let ecc_decrypt_unencrypted_message_test _ =
  let keys = ECC.generate_keys base_point a b p n in
  let invalid_c1 = ECC.Point (0, 0) in
  let invalid_c2 = ECC.Point (1, 1) in
  assert_raises (Failure "Decryption failed") (fun () ->
      ECC.decrypt (invalid_c1, invalid_c2) keys.private_key a p)

(* Test: Validate that encrypt-decrypt works for multiple random messages *)
let ecc_encrypt_decrypt_multiple_random_test _ =
  for _ = 1 to 10 do
    let keys = ECC.generate_keys base_point a b p n in
    let message = Random.int p in
    let c1, c2 = ECC.encrypt message base_point keys.public_key a b p n in
    let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
    assert_equal message decrypted_message
  done

(* Test: Ensure point addition commutativity holds for random points *)
let ecc_point_addition_commutativity_random_test _ =
  for _ = 1 to 10 do
    let point1 = ECC.scalar_mult (Random.int n) base_point a p in
    let point2 = ECC.scalar_mult (Random.int n) base_point a p in
    let result1 = ECC.add point1 point2 a p in
    let result2 = ECC.add point2 point1 a p in
    assert_equal result1 result2
  done

(* Group all ECC tests *)
let ecc_tests =
  [
    "ECC key generation test (valid keys)" >:: ecc_key_generation_test1;
    "ECC key generation test (distinct keys)" >:: ecc_key_generation_test2;
    "ECC scalar multiplication test (small scalar)" >:: ecc_scalar_mult_test1;
    "ECC scalar multiplication test (large scalar)" >:: ecc_scalar_mult_test2;
    "ECC scalar multiplication test (scalar = 0)" >:: ecc_scalar_mult_zero_test;
    "ECC scalar multiplication test (random scalars)"
    >:: ecc_scalar_mult_random_test;
    "ECC point addition test (distinct points)" >:: ecc_point_addition_test1;
    "ECC point addition test (with Infinity)"
    >:: ecc_point_addition_infinity_test;
    "ECC point addition test (same point)" >:: ecc_point_addition_self_test;
    "ECC point addition test (random points)" >:: ecc_point_addition_random_test;
    "ECC encrypt and decrypt test (small message)"
    >:: ecc_encrypt_decrypt_test_small;
    "ECC encrypt and decrypt test (large message)"
    >:: ecc_encrypt_decrypt_test_large;
    "ECC encrypt and decrypt test (random messages)"
    >:: ecc_encrypt_decrypt_random_test;
    "ECC decrypt failure test (wrong private key)"
    >:: ecc_decrypt_failure_wrong_key;
    "ECC decrypt failure test (tampered ciphertext)"
    >:: ecc_decrypt_failure_tampered_cipher;
    "ECC encrypt and decrypt edge cases" >:: ecc_encrypt_decrypt_edge_cases;
    "ECC point addition invalid points test"
    >:: ecc_point_addition_invalid_points_test;
    "ECC scalar multiplication large scalar test"
    >:: ecc_scalar_mult_large_scalar_test;
    "ECC key generation boundary test" >:: ecc_key_generation_boundary_test;
    "ECC point addition identity property test"
    >:: ecc_point_addition_identity_property_test;
    "ECC point addition commutative test"
    >:: ecc_point_addition_commutative_test;
    "ECC point addition associative test"
    >:: ecc_point_addition_associative_test;
    "ECC encrypt-decrypt boundary test" >:: ecc_encrypt_decrypt_boundary_test;
    "ECC private key uniqueness test" >:: ecc_private_key_uniqueness_test;
    "ECC scalar multiplication negative test" >:: ecc_scalar_mult_negative_test;
    "ECC point doubling test" >:: ecc_point_doubling_test;
    "ECC scalar multiplication identity test" >:: ecc_scalar_mult_identity_test;
    "ECC scalar multiplication max scalar test"
    >:: ecc_scalar_mult_max_scalar_test;
    "ECC encrypt-decrypt large message test"
    >:: ecc_encrypt_decrypt_large_message_test;
    "ECC point addition invalid test" >:: ecc_point_addition_invalid_test;
    "ECC scalar multiplication zero returns infinity test"
    >:: ecc_scalar_mult_zero_return_infinity_test;
    "ECC validate multiples test" >:: ecc_validate_multiples_test;
    "ECC random key generation test" >:: ecc_random_key_generation_test;
    "ECC random point addition test" >:: ecc_random_point_addition_test;
    "ECC decrypt unencrypted message test"
    >:: ecc_decrypt_unencrypted_message_test;
    "ECC encrypt-decrypt multiple random test"
    >:: ecc_encrypt_decrypt_multiple_random_test;
    "ECC point addition commutativity random test"
    >:: ecc_point_addition_commutativity_random_test;
  ]

(* Run ECC tests *)
(* let () = run_test_tt_main ("ECC Test Suite" >::: ecc_tests) *)
