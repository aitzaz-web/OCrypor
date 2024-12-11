open OUnit2
open Encryptor.Rsa
open Encryptor.Util
open Encryptor.Sha3

(********************************* RC2 component tests
  *****************************)

(** [rotl64_test1] tests basic left rotation by 1 bit *)
let rotl64_test1 _ =
  let input = Int64.of_int 1 in
  let expected = Int64.shift_left (Int64.of_int 1) 1 in
  assert_equal expected (rotl64 input 1)

(** [rotl64_test2] tests rotation that wraps around *)
let rotl64_test2 _ =
  let input = Int64.shift_left Int64.one 63 in
  let expected = Int64.one in
  assert_equal expected (rotl64 input 1)

(** [rotl64_test3] tests rotation by 0 bits (no change) *)
let rotl64_test3 _ =
  let input = Int64.of_int 0xABCD in
  assert_equal input (rotl64 input 0)

(** [to_state_test1] tests creation of empty 5x5 matrix *)
let to_state_test1 _ =
  let state = to_state [||] in
  assert_equal 5 (Array.length state);
  assert_equal 5 (Array.length state.(0));
  for i = 0 to 4 do
    for j = 0 to 4 do
      assert_equal Int64.zero state.(i).(j)
    done
  done

(** [to_state_test2] tests initialization remains consistent *)
let to_state_test2 _ =
  let state1 = to_state [||] in
  let state2 = to_state [||] in
  for i = 0 to 4 do
    for j = 0 to 4 do
      assert_equal state1.(i).(j) state2.(i).(j)
    done
  done

(** [from_state_test1] tests conversion from 5x5 matrix to linear array *)
let from_state_test1 _ =
  let state = Array.make_matrix 5 5 0L in
  (* Set some test values *)
  state.(0).(0) <- Int64.of_int 1;
  state.(1).(1) <- Int64.of_int 2;
  state.(2).(2) <- Int64.of_int 3;
  state.(3).(3) <- Int64.of_int 4;
  state.(4).(4) <- Int64.of_int 5;

  let result = from_state state in
  assert_equal 25 (Array.length result);
  assert_equal (Int64.of_int 1) result.(0);
  assert_equal (Int64.of_int 2) result.(6);
  assert_equal (Int64.of_int 3) result.(12);
  assert_equal (Int64.of_int 4) result.(18);
  assert_equal (Int64.of_int 5) result.(24)

(** [from_state_test2] tests tffhat all zeros are preserved *)
let from_state_test2 _ =
  let state = Array.make_matrix 5 5 0L in
  let result = from_state state in
  assert_equal 25 (Array.length result);
  Array.iter (fun x -> assert_equal Int64.zero x) result

open OUnit2

(* Helper function to create a 5x5 state array from a list of lists *)
let create_state_from_list lst = Array.of_list (List.map Array.of_list lst)

(* Test data - a simple 5x5 state matrix *)
let test_state =
  create_state_from_list
    [
      [ 1L; 2L; 3L; 4L; 5L ];
      [ 6L; 7L; 8L; 9L; 10L ];
      [ 11L; 12L; 13L; 14L; 15L ];
      [ 16L; 17L; 18L; 19L; 20L ];
      [ 21L; 22L; 23L; 24L; 25L ];
    ]

let test_xor_slice_simple _ =
  let arr =
    [|
      Int64.of_int 1;
      Int64.of_int 2;
      Int64.of_int 3;
      Int64.of_int 4;
      Int64.of_int 5;
    |]
  in
  assert_equal
    Int64.(of_int 0)
    (Encryptor.Sha3.xor_slice arr 0 2)
    ~printer:Int64.to_string;
  assert_equal
    Int64.(of_int 4)
    (Encryptor.Sha3.xor_slice arr 0 3)
    ~printer:Int64.to_string

let test_compute_column_parity _ =
  let test_state =
    Array.init 5 (fun i ->
        Array.init 5 (fun j -> Int64.of_int ((i + 1) * (j + 1))))
  in

  let result = Encryptor.Sha3.compute_column_parity test_state in

  let expected =
    [|
      Int64.of_int (1 lxor 2 lxor 3 lxor 4 lxor 5);
      (* First column *)
      Int64.of_int (2 lxor 4 lxor 6 lxor 8 lxor 10);
      (* Second column *)
      Int64.of_int (3 lxor 6 lxor 9 lxor 12 lxor 15);
      (* Third column *)
      Int64.of_int (4 lxor 8 lxor 12 lxor 16 lxor 20);
      (* Fourth column *)
      Int64.of_int (5 lxor 10 lxor 15 lxor 20 lxor 25)
      (* Fifth column *);
    |]
  in

  (* Check that the result array has the correct length *)
  assert_equal 5 (Array.length result) ~printer:string_of_int;

  (* Check each column's parity matches expected value *)
  Array.iteri
    (fun i x ->
      assert_equal
        ~msg:(Printf.sprintf "Column %d parity mismatch" i)
        ~printer:Int64.to_string expected.(i) x)
    result

let test_compute_theta_d _ =
  let c = Array.map Int64.of_int [| 1; 2; 4; 8; 16 |] in

  let result = Encryptor.Sha3.compute_theta_d c in

  let expected_at_x x =
    let x4 = c.((x + 4) mod 5) in
    (* Value from x+4 position *)
    let x1_rotated = rotl64 c.((x + 1) mod 5) 1 in
    (* Rotated value from x+1 position *)
    Int64.logxor x4 x1_rotated
  in

  assert_equal 5 (Array.length result) ~printer:string_of_int;

  (* For x = 0: - Uses c[4] (16) and rotated c[1] (2 rotated left by 1 = 4)
     Expected: 16 XOR 4 *)
  assert_equal ~msg:"Failed at x=0" ~printer:Int64.to_string (expected_at_x 0)
    result.(0);

  (* For x = 1: - Uses c[0] (1) and rotated c[2] (4 rotated left by 1 = 8)
     Expected: 1 XOR 8 *)
  assert_equal ~msg:"Failed at x=1" ~printer:Int64.to_string (expected_at_x 1)
    result.(1);

  (* For x = 2: - Uses c[1] (2) and rotated c[3] (8 rotated left by 1 = 16)
     Expected: 2 XOR 16 *)
  assert_equal ~msg:"Failed at x=2" ~printer:Int64.to_string (expected_at_x 2)
    result.(2);

  (* For x = 3: - Uses c[2] (4) and rotated c[4] (16 rotated left by 1 = 32)
     Expected: 4 XOR 32 *)
  assert_equal ~msg:"Failed at x=3" ~printer:Int64.to_string (expected_at_x 3)
    result.(3);

  (* For x = 4: - Uses c[3] (8) and rotated c[0] (1 rotated left by 1 = 2)
     Expected: 8 XOR 2 *)
  assert_equal ~msg:"Failed at x=4" ~printer:Int64.to_string (expected_at_x 4)
    result.(4)

let create_test_state () =
  Array.init 5 (fun x ->
      Array.init 5 (fun y -> Int64.of_int ((x + 1) * (y + 1))))

let test_theta _ =
  let state = create_test_state () in
  let result = Encryptor.Sha3.theta state in

  (* Test dimensions *)
  assert_equal 5 (Array.length result) ~printer:string_of_int;
  assert_equal 5 (Array.length result.(0)) ~printer:string_of_int;

  (* Verify that result is a new array *)
  assert_bool "Should create new array" (result != state);

  (* Compute expected values manually *)
  let c = Encryptor.Sha3.compute_column_parity state in
  let d = Encryptor.Sha3.compute_theta_d c in

  (* Check that each position is correctly transformed *)
  for x = 0 to 4 do
    for y = 0 to 4 do
      let expected = Int64.logxor state.(x).(y) d.(x) in
      assert_equal
        ~msg:(Printf.sprintf "Mismatch at position (%d,%d)" x y)
        ~printer:Int64.to_string expected
        result.(x).(y)
    done
  done

let test_compute_rho_offset _ =
  (* Test first few values *)
  let test_cases =
    [
      (0, 1);
      (* (0+1)*(0+2)/2 = 1 *)
      (1, 3);
      (* (1+1)*(1+2)/2 = 3 *)
      (2, 6);
      (* (2+1)*(2+2)/2 = 6 *)
      (3, 10);
      (* (3+1)*(3+2)/2 = 10 *)
      (4, 15);
      (* (4+1)*(4+2)/2 = 15 *)
      (5, 21);
      (* (5+1)*(5+2)/2 = 21 *)
    ]
  in

  List.iter
    (fun (input, expected) ->
      assert_equal
        ~msg:(Printf.sprintf "Rho offset mismatch for t=%d" input)
        ~printer:string_of_int expected
        (Encryptor.Sha3.compute_rho_offset input))
    test_cases;

  (* Test that results are always within valid range (0-63) *)
  for t = 0 to 23 do
    let result = Encryptor.Sha3.compute_rho_offset t in
    assert_bool
      (Printf.sprintf "Offset %d out of range for t=%d" result t)
      (result >= 0 && result < 64)
  done

let test_compute_pi_position _ =
  (* Test known mappings *)
  let test_cases =
    [
      ((0, 0), (0, 0));
      (* y=0, (2*0 + 3*0) mod 5 = 0 *)
      ((1, 0), (0, 2));
      (* y=0, (2*1 + 3*0) mod 5 = 2 *)
      ((2, 0), (0, 4));
      (* y=0, (2*2 + 3*0) mod 5 = 4 *)
      ((0, 1), (1, 3));
      (* y=1, (2*0 + 3*1) mod 5 = 3 *)
      ((1, 1), (1, 0));
      (* y=1, (2*1 + 3*1) mod 5 = 0 *)
    ]
  in

  List.iter
    (fun ((x, y), (exp_x, exp_y)) ->
      let res_x, res_y = Encryptor.Sha3.compute_pi_position x y in
      assert_equal
        ~msg:(Printf.sprintf "Pi position mismatch for (%d,%d)" x y)
        ~printer:(fun (x, y) -> Printf.sprintf "(%d,%d)" x y)
        (exp_x, exp_y) (res_x, res_y))
    test_cases

let test_rho_pi _ =
  let state = create_test_state () in
  let result = Encryptor.Sha3.rho_pi state in

  (* Test dimensions *)
  assert_equal 5 (Array.length result) ~printer:string_of_int;
  assert_equal 5 (Array.length result.(0)) ~printer:string_of_int;

  (* Test that (0,0) is unchanged *)
  assert_equal ~printer:Int64.to_string state.(0).(0) result.(0).(0);

  (* Test first transformation (t=0) *)
  let new_x, new_y = Encryptor.Sha3.compute_pi_position 1 0 in
  let rotated = rotl64 state.(1).(0) (Encryptor.Sha3.compute_rho_offset 0) in
  assert_equal ~msg:"First rho-pi transformation failed"
    ~printer:Int64.to_string rotated
    result.(new_x).(new_y);

  (* Verify all positions are filled (no zeros except where expected) *)
  let zero_count = ref 0 in
  for x = 0 to 4 do
    for y = 0 to 4 do
      if Int64.equal result.(x).(y) 0L then incr zero_count
    done
  done;
  assert_bool "Too many zero values in result" (!zero_count < 25)

let test_chi_at_position _ =
  let state = create_test_state () in

  (* Test specific position (0,0) *)
  let result = Encryptor.Sha3.chi_at_position state 0 0 in
  let expected =
    Int64.logxor
      state.(0).(0)
      (Int64.logand (Int64.lognot state.(1).(0)) state.(2).(0))
  in
  assert_equal ~msg:"chi_at_position failed for (0,0)" ~printer:Int64.to_string
    expected result;

  (* Test position with wraparound (4,0) *)
  let result_wrap = Encryptor.Sha3.chi_at_position state 4 0 in
  let expected_wrap =
    Int64.logxor
      state.(4).(0)
      (Int64.logand (Int64.lognot state.(0).(0)) state.(1).(0))
  in
  assert_equal ~msg:"chi_at_position failed for wraparound case (4,0)"
    ~printer:Int64.to_string expected_wrap result_wrap

let test_chi _ =
  let state = create_test_state () in
  let result = Encryptor.Sha3.chi state in

  (* Test dimensions *)
  assert_equal 5 (Array.length result) ~printer:string_of_int;
  assert_equal 5 (Array.length result.(0)) ~printer:string_of_int;

  (* Test that each position matches chi_at_position *)
  for x = 0 to 4 do
    for y = 0 to 4 do
      let expected = Encryptor.Sha3.chi_at_position state x y in
      assert_equal
        ~msg:(Printf.sprintf "chi transformation mismatch at (%d,%d)" x y)
        ~printer:Int64.to_string expected
        result.(x).(y)
    done
  done

let test_iota _ =
  let state = create_test_state () in
  let round = 0 in
  let result = Encryptor.Sha3.iota state round in

  (* Test dimensions *)
  assert_equal 5 (Array.length result) ~printer:string_of_int;
  assert_equal 5 (Array.length result.(0)) ~printer:string_of_int;

  (* Test that only (0,0) is modified *)
  assert_equal ~msg:"(0,0) position not correctly transformed"
    ~printer:Int64.to_string
    (Int64.logxor state.(0).(0) keccak_round_constants.(round))
    result.(0).(0);

  (* Test that all other positions remain unchanged *)
  for x = 0 to 4 do
    for y = 0 to 4 do
      if not (x = 0 && y = 0) then
        assert_equal
          ~msg:(Printf.sprintf "Position (%d,%d) changed unexpectedly" x y)
          ~printer:Int64.to_string
          state.(x).(y)
          result.(x).(y)
    done
  done

let test_keccak_round _ =
  let state = create_test_state () in
  let round = 0 in
  let result = Encryptor.Sha3.keccak_round state round in

  (* Test dimensions *)
  assert_equal 5 (Array.length result) ~printer:string_of_int;
  assert_equal 5 (Array.length result.(0)) ~printer:string_of_int;

  (* Verify round transformation by applying each step manually *)
  let expected =
    state |> Encryptor.Sha3.theta |> Encryptor.Sha3.rho_pi |> Encryptor.Sha3.chi
    |> fun s -> Encryptor.Sha3.iota s round
  in

  (* Compare with expected result *)
  for x = 0 to 4 do
    for y = 0 to 4 do
      assert_equal
        ~msg:(Printf.sprintf "Round transformation mismatch at (%d,%d)" x y)
        ~printer:Int64.to_string
        expected.(x).(y)
        result.(x).(y)
    done
  done

let test_hex_of_string _ =
  let test_cases =
    [
      (* Empty string *)
      ("", "");
      (* Single byte *)
      (String.make 1 (char_of_int 0xab), "ab");
      (* Multiple bytes *)
      ( String.make 1 (char_of_int 0x12) ^ String.make 1 (char_of_int 0x34),
        "1234" );
    ]
  in

  List.iter
    (fun (input, expected) ->
      let result = Encryptor.Sha3.hex_of_string (Bytes.of_string input) in
      assert_equal
        ~msg:(Printf.sprintf "Hex conversion failed for input: %S" input)
        ~printer:(fun x -> x)
        expected result)
    test_cases

(********************************* SHA3 functionality tests
  *****************************)
(* Helper function to convert hex string to bytes *)
let hex_to_bytes hex =
  let hex = String.lowercase_ascii hex in
  let len = String.length hex in
  let bytes = Bytes.create (len / 2) in
  for i = 0 to (len / 2) - 1 do
    let high = int_of_char hex.[i * 2] in
    let low = int_of_char hex.[(i * 2) + 1] in
    let high = if high <= 57 then high - 48 else high - 87 in
    let low = if low <= 57 then low - 48 else low - 87 in
    Bytes.set bytes i (char_of_int ((high lsl 4) lor low))
  done;
  bytes

(* Helper function to convert bytes to hex string *)
let bytes_to_hex bytes =
  let len = Bytes.length bytes in
  let hex = Bytes.create (len * 2) in
  for i = 0 to len - 1 do
    let v = int_of_char (Bytes.get bytes i) in
    let high = if v lsr 4 <= 9 then (v lsr 4) + 48 else (v lsr 4) + 87 in
    let low =
      if v land 0xf <= 9 then (v land 0xf) + 48 else (v land 0xf) + 87
    in
    Bytes.set hex (i * 2) (char_of_int high);
    Bytes.set hex ((i * 2) + 1) (char_of_int low)
  done;
  Bytes.unsafe_to_string hex

let test_pad_input _ =
  (* Test string shorter than rate *)
  let padded2 = Encryptor.Sha3.pad_input "Hello" in
  let len2 = Bytes.length padded2 in

  (* Assert the length is valid *)
  assert_equal true (len2 > 5)
    ~msg:"Hello string padding should be longer than input"

let test_absorb _ =
  let state = Array.make_matrix 5 5 0L in
  let input = "test" in
  let padded = Encryptor.Sha3.pad_input input in
  Encryptor.Sha3.absorb state padded;

  (* Verify state is modified *)
  assert_bool "State should be modified"
    (Array.exists (fun row -> Array.exists (fun el -> el <> 0L) row) state)

(* Test cases for squeeze *)

(** [get_output_length hash_size] returns the output length in bytes for a given
    hash size in bits. *)
let get_output_length hash_size_bits = hash_size_bits / 8

let test_squeeze _ =
  let state = Array.make_matrix 5 5 0L in
  (* Set some known values in state *)
  state.(0).(0) <- 0x0123456789abcdefL;
  state.(1).(0) <- 0xfedcba9876543210L;

  (* Calculate the expected output length using the helper *)
  let expected_length = get_output_length 256 in

  let output = Encryptor.Sha3.squeeze state in
  assert_equal expected_length (Bytes.length output)
    ~msg:
      (Printf.sprintf "Expected output length: %d, but got: %d" expected_length
         (Bytes.length output))

(* Test cases for complete sha3_256 *)
let test_sha3_256 _ =
  (* Test vectors from NIST *)

  (* Test empty string *)
  let test_empty = Encryptor.Sha3.sha3_256 "" in
  let test_empty_hex = bytes_to_hex test_empty in
  Printf.printf "Empty string hash: %s\n" test_empty_hex;
  assert_equal
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    test_empty_hex ~msg:"Empty string hash does not match expected value";

  (* Test "abc" *)
  let test_abc = Encryptor.Sha3.sha3_256 "abc" in
  let test_abc_hex = bytes_to_hex test_abc in
  Printf.printf "abc string hash: %s\n" test_abc_hex;
  assert_equal
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    test_abc_hex ~msg:"'abc' hash does not match expected value";

  (* Test long input *)
  let test_long =
    Encryptor.Sha3.sha3_256
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  in
  let test_long_hex = bytes_to_hex test_long in
  Printf.printf "Long string hash: %s\n" test_long_hex;
  assert_equal
    "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
    test_long_hex ~msg:"Long string hash does not match expected value"

let test_expand_key _ =
  (* Test with a short key and maximum effective bits *)
  let key = "testkey" in
  let effective_bits = 1024 in
  let expanded_key = expand_key key effective_bits in

  (* Assert the length of the expanded key is 128 *)
  assert_equal 128 (Array.length expanded_key) ~printer:string_of_int;

  (* Check the first few values for consistency *)
  assert_bool "First byte of expanded key should not be zero"
    (expanded_key.(0) <> 0);

  assert_bool "Last byte of expanded key should not be zero"
    (expanded_key.(127) <> 0);

  (* Test with a shorter effective key size *)
  let effective_bits_short = 64 in
  let expanded_key_short = expand_key key effective_bits_short in

  (* Assert the length is still 128 but effective bits applied *)
  assert_equal 128 (Array.length expanded_key_short) ~printer:string_of_int;

  (* Print first few bytes for debugging *)
  Printf.printf "Expanded key (short effective bits): [";
  Array.iteri
    (fun i x -> if i < 10 then Printf.printf "0x%02x " x)
    expanded_key_short;
  Printf.printf "...]\n";

  (* Check if the effective bits are applied correctly *)
  let t3 = (effective_bits_short + 7) / 8 in
  let last_used_index = t3 - 1 in
  let unused_bytes = Array.sub expanded_key_short t3 (128 - t3) in
  Array.iter (fun x -> assert_equal 0 x ~printer:string_of_int) unused_bytes;

  (* Ensure values after the effective key size are zeroed *)
  assert_equal expanded_key_short.(last_used_index + 1) ~printer:string_of_int

open OUnit2

let test_driver_encrypt_decrypt _ =
  (* Temporary file names for testing *)
  let input_filename = "test_message.txt" in
  let encrypted_filename = input_filename ^ ".enc" in
  let decrypted_filename = input_filename ^ ".dec" in

  (* Test message to encrypt *)
  let test_message =
    "This is a test message for encryption and decryption. It ensures the \
     process is reversible and consistent."
  in

  (* Step 1: Write test message to file *)
  let oc = open_out input_filename in
  output_string oc test_message;
  close_out oc;

  (* Step 2: Encrypt the file *)
  assert_bool "Encryption failed" (encrypt input_filename);

  (* Step 3: Decrypt the file *)
  assert_bool "Decryption failed" (decrypt encrypted_filename);

  (* Step 4: Verify the decrypted file contents match the original *)
  let ic = open_in decrypted_filename in
  let decrypted_message = really_input_string ic (in_channel_length ic) in
  close_in ic;

  assert_equal
    ~printer:(fun x -> x)
    test_message decrypted_message
    ~msg:"Decrypted message does not match the original";

  (* Clean up temporary files *)
  Sys.remove input_filename;
  Sys.remove encrypted_filename;
  Sys.remove decrypted_filename

let tests =
  "test suite"
  >::: [
         (*SHA3*)
         "rotl64 basic rotation" >:: rotl64_test1;
         "rotl64 wraparound" >:: rotl64_test2;
         "rotl64 no rotation" >:: rotl64_test3;
         "to_state empty initialization" >:: to_state_test1;
         "to_state consistent initialization" >:: to_state_test2;
         "from_state with values" >:: from_state_test1;
         "from_state all zeros" >:: from_state_test2;
         "test_xor_slice_simple" >:: test_xor_slice_simple;
         "test_compute_column_parity" >:: test_compute_column_parity;
         "test_compute_theta_d" >:: test_compute_theta_d;
         "test_theta" >:: test_theta;
         "test_compute_rho_offset" >:: test_compute_rho_offset;
         "test_compute_pi_position" >:: test_compute_pi_position;
         "test_rho_pi" >:: test_rho_pi;
         "test_chi_at_position" >:: test_chi_at_position;
         "test_chi" >:: test_chi;
         "test_iota" >:: test_iota;
         "test_keccak_round" >:: test_keccak_round;
         "test_hex_of_string" >:: test_hex_of_string;
         "test_pad_input" >:: test_pad_input;
         "test_absorb" >:: test_absorb;
         "test_squeeze" >:: test_squeeze;
         "test_driver_encrypt_decrypt" >:: test_driver_encrypt_decrypt;
       ]

let _ = run_test_tt_main tests
