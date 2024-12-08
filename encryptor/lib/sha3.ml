
(** [read_int64_file filename] reads Int64 hex values from a file at [filename] and returns
    them as an Int64 array. Each value should be on a new line. Returns an empty array
    on error. *)
let read_int64_file filename =
  try
    let ic = open_in filename in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    let values = List.filter 
      (fun s -> String.length s > 0)
      (String.split_on_char '\n' (String.trim content)) in
    Array.of_list (List.map (fun s -> Int64.of_string ("0x" ^ s)) values)
  with e ->
    Printf.printf "Error reading Int64 values: %s\n" (Printexc.to_string e);
    [||]

(** Load constants from data files *)
let pitable = [| 
  0xd9; 0x78; 0xf9; 0xc4; 0x19; 0xdd; 0xb5; 0xed; 0x28; 0xe9; 0xfd; 0x79; 0x4a; 0xa0; 0xd8; 0x9d;
  0xc6; 0x7e; 0x37; 0x83; 0x2b; 0x76; 0x53; 0x8e; 0x62; 0x4c; 0x64; 0x88; 0x44; 0x8b; 0xfb; 0xa2;
  0x17; 0x9a; 0x59; 0xf5; 0x87; 0xb3; 0x4f; 0x13; 0x61; 0x45; 0x6d; 0x8d; 0x09; 0x81; 0x7d; 0x32;
  0xbd; 0x8f; 0x40; 0xeb; 0x86; 0xb7; 0x7b; 0x0b; 0xf0; 0x95; 0x21; 0x22; 0x5c; 0x6b; 0x4e; 0x82;
  0x54; 0xd6; 0x65; 0x93; 0xce; 0x60; 0xb2; 0x1c; 0x73; 0x56; 0xc0; 0x14; 0xa7; 0x8c; 0xf1; 0xdc;
  0x12; 0x75; 0xca; 0x1f; 0x3b; 0xbe; 0xe4; 0xd1; 0x42; 0x3d; 0xd4; 0x30; 0xa3; 0x3c; 0xb6; 0x26;
  0x6f; 0xbf; 0x0e; 0xda; 0x46; 0x69; 0x07; 0x57; 0x27; 0xf2; 0x1d; 0x9b; 0xbc; 0x94; 0x43; 0x03;
  0xf8; 0x11; 0xc7; 0xf6; 0x90; 0xef; 0x3e; 0xe7; 0x06; 0xc3; 0xd5; 0x2f; 0xc8; 0x66; 0x1e; 0xd7;
  0x08; 0xe8; 0xea; 0xde; 0x80; 0x52; 0xee; 0xf7; 0x84; 0xaa; 0x72; 0xac; 0x35; 0x4d; 0x6a; 0x2a;
  0x96; 0x1a; 0xd2; 0x71; 0x5a; 0x15; 0x49; 0x74; 0x4b; 0x9f; 0xd0; 0x5e; 0x04; 0x18; 0xa4; 0xec;
  0xc2; 0xe0; 0x41; 0x6e; 0x0f; 0x51; 0xcb; 0xcc; 0x24; 0x91; 0xaf; 0x50; 0xa1; 0xf4; 0x70; 0x39;
  0x99; 0x7c; 0x3a; 0x85; 0x23; 0xb8; 0xb4; 0x7a; 0xfc; 0x02; 0x36; 0x5b; 0x25; 0x55; 0x97; 0x31;
  0x2d; 0x5d; 0xfa; 0x98; 0xe3; 0x8a; 0x92; 0xae; 0x05; 0xdf; 0x29; 0x10; 0x67; 0x6c; 0xba; 0xc9;
  0xd3; 0x00; 0xe6; 0xcf; 0xe1; 0x9e; 0xa8; 0x2c; 0x63; 0x16; 0x01; 0x3f; 0x58; 0xe2; 0x89; 0xa9;
  0x0d; 0x38; 0x34; 0x1b; 0xab; 0x33; 0xff; 0xb0; 0xbb; 0x48; 0x0c; 0x5f; 0xb9; 0xb1; 0xcd; 0x2e;
  0xc5; 0xf3; 0xdb; 0x47; 0xe5; 0xa5; 0x9c; 0x77; 0x0a; 0xa6; 0x20; 0x68; 0xfe; 0x7f; 0xc1; 0xad;
|]
let keccak_round_constants = [|
  0x0000000000000001L; 0x0000000000008082L;
  0x800000000000808AL; 0x8000000080008000L;
  0x000000000000808BL; 0x0000000080000001L;
  0x8000000080008081L; 0x8000000000008009L;
  0x000000000000008AL; 0x0000000000000088L;
  0x0000000080008009L; 0x000000008000000AL;
  0x000000008000808BL; 0x800000000000008BL;
  0x8000000000008089L; 0x8000000000008003L;
  0x8000000000008002L; 0x8000000000000080L;
  0x000000000000800AL; 0x800000008000000AL;
  0x8000000080008081L; 0x8000000000008080L;
  0x0000000080000001L; 0x8000000080008008L
|]



(** [rotl64 x n] performs a 64-bit left rotation on [x] by [n] bits and returns
    the rotated value. *)
let rotl64 x n =
  Int64.logor (Int64.shift_left x n) (Int64.shift_right_logical x (64 - n))

(** [to_state arr] creates a new 5x5 matrix of Int64 values initialized to 0L.
    Returns the initialized matrix. *)
let to_state arr = Array.make_matrix 5 5 0L

(** [from_state state] converts a 5x5 state matrix into a linear array of length 25.
    Returns the linearized array. *)
let from_state state = Array.init 25 (fun i -> state.(i / 5).(i mod 5))

(** [xor_slice arr start end_idx] computes the XOR of elements from start to end_idx *)
let xor_slice arr start end_idx =
  let result = ref arr.(start) in
  for i = start + 1 to end_idx do
    result := Int64.logxor !result arr.(i)
  done;
  !result

(** [compute_column_parity state] computes the column parity for theta transformation *)
let compute_column_parity state =
  Array.init 5 (fun x ->
    xor_slice state.(x) 0 4
  )

(** [compute_theta_d c] computes the d array for theta transformation *)
let compute_theta_d c =
  Array.init 5 (fun x ->
    Int64.logxor 
      c.((x + 4) mod 5) 
      (rotl64 c.((x + 1) mod 5) 1)
  )

(** [theta state] performs the theta transformation *)
let theta state =
  let state_copy = Array.map Array.copy state in
  let c = compute_column_parity state in
  let d = compute_theta_d c in
  for x = 0 to 4 do
    for y = 0 to 4 do
      state_copy.(x).(y) <- Int64.logxor state_copy.(x).(y) d.(x)
    done
  done;
  state_copy

(** [compute_rho_offset t] computes rotation offset for rho transformation *)
let compute_rho_offset t =
  (t + 1) * (t + 2) / 2 mod 64

(** [compute_pi_position x y] computes new position after pi transformation *)
let compute_pi_position x y =
  (y, ((2 * x) + (3 * y)) mod 5)

(** [rho_pi state] performs combined rho and pi transformations *)
let rho_pi state =
  let result = Array.make_matrix 5 5 0L in
  result.(0).(0) <- state.(0).(0);
  
  let rec rho_pi_loop t (x, y) current =
    if t >= 24 then result
    else
      let (newx, newy) = compute_pi_position x y in
      let rotated = rotl64 current (compute_rho_offset t) in
      result.(newx).(newy) <- rotated;
      rho_pi_loop (t + 1) (newx, newy) state.(newx).(newy)
  in
  ignore (rho_pi_loop 0 (1, 0) state.(1).(0));
  result

(** [chi_at_position state x y] computes chi transformation for one position *)
let chi_at_position state x y =
  Int64.logxor 
    state.(x).(y)
    (Int64.logand
      (Int64.lognot state.((x + 1) mod 5).(y))
      state.((x + 2) mod 5).(y))

(** [chi state] performs the chi transformation *)
let chi state =
  Array.init 5 (fun x ->
    Array.init 5 (fun y ->
      chi_at_position state x y
    )
  )

(** [iota state round] performs the iota transformation *)
let iota state round =
  let state_copy = Array.map Array.copy state in
  state_copy.(0).(0) <- Int64.logxor state.(0).(0) keccak_round_constants.(round);
  state_copy

(** [keccak_round state round] performs one complete round of Keccak-f *)
let keccak_round state round =
  state 
  |> theta 
  |> rho_pi 
  |> chi 
  |> fun s -> iota s round

(** [keccak_f state] performs the complete Keccak-f[1600] permutation *)
let keccak_f state =
  let rec loop state round =
    if round >= 24 then state
    else
      let new_state = keccak_round state round in
      loop new_state (round + 1)
  in
  loop state 0

(** [sha3_256 input] computes the SHA3-256 hash of the [input] string.
    Returns a 32-byte string containing the hash value. *)
  

(** Fixed parameters for SHA3-256 *)
let rate = 1088 / 8
let capacity = 512 / 8
let output_length = 256 / 8

(** [create_block padded offset] creates a 64-bit block from the padded input starting
    at the specified offset.
    @param padded The padded input bytes
    @param offset The starting position in the padded input
    @return A 64-bit integer representing the block
*)
let create_block padded offset =
  let block = ref 0L in
  for k = 0 to 7 do
    block :=
      Int64.logor !block
        (Int64.shift_left
           (Int64.of_int
              (int_of_char (Bytes.get padded (offset + k))))
           (k * 8))
  done;
  !block

(** [pad_input input] applies SHA3 padding to the input string.
    Adds the padding bits according to the SHA3 specification:
    - Appends the bits 01 (in hex: 0x06)
    - Fills with zeros
    - Appends the bit 1 (in hex: 0x80)
    @param input The input string to be padded
    @return A bytes buffer containing the padded input
*)
(** [pad_input input] applies SHA3 padding to the input string. *)
let pad_input input =
  let input_length = String.length input in
  let padded_length = ((input_length + rate - 1) / rate) * rate in
  let padded_length = max padded_length rate in
  let padded = Bytes.create padded_length in
  Bytes.blit_string input 0 padded 0 input_length;
  Bytes.set padded input_length '\x06';
  Bytes.set padded (padded_length - 1) '\x80';
  padded


(** [absorb state padded] performs the absorption phase of SHA3.
    Processes the padded input in rate-sized blocks, incorporating
    them into the state array using XOR operations.
    @param state The 5x5 state array
    @param padded The padded input bytes
*)
let absorb state padded =
  let padded_length = Bytes.length padded in
  for i = 0 to (padded_length / rate) - 1 do
    for j = 0 to (rate / 8) - 1 do
      let block_offset = (i * rate) + (j * 8) in
      if block_offset < padded_length then (
        let block = create_block padded block_offset in
        let x = j mod 5 in
        let y = j / 5 in
        state.(x).(y) <- Int64.logxor state.(x).(y) block)
    done;
    ignore (keccak_f state)
  done

(** [squeeze state] performs the squeeze phase of SHA3.
    Extracts the specified number of output bytes from the state array.
    For SHA3-256, this produces a 32-byte (256-bit) hash value.
    @param state The 5x5 state array
    @return The final hash value as bytes
*)
let squeeze state =
  let output = Bytes.create output_length in
  let output_blocks = (output_length + 7) / 8 in
  for i = 0 to output_blocks - 1 do
    let x = i mod 5 in
    let y = i / 5 in
    let lane = state.(x).(y) in
    for j = 0 to min 7 (output_length - (i * 8) - 1) do
      Bytes.set output
        ((i * 8) + j)
        (char_of_int (Int64.to_int (Int64.shift_right lane (j * 8)) land 0xff))
    done
  done;
  output

(** [sha3_256 input] computes the SHA3-256 hash of the input string.
    Implements the full SHA3-256 algorithm:
    1. Initializes the state array
    2. Pads the input
    3. Absorbs the padded input into the state
    4. Squeezes out the final hash value
    @param input The input string to be hashed
    @return A 32-byte buffer containing the SHA3-256 hash
*)
let sha3_256 input =
  let state = Array.make_matrix 5 5 0L in
  let padded = pad_input input in
  absorb state padded;
  squeeze state

(** [hex_of_string s] converts a byte string [s] to its hexadecimal representation.
    Returns a string containing the hex digits. *)
    let hex_of_string s =
  let len = Bytes.length s in
  let res = Buffer.create (len * 2) in
  for i = 0 to len - 1 do
    Printf.bprintf res "%02x" (int_of_char (Bytes.get s i))
  done;
  Buffer.contents res

(** [expand_key key effective_bits] expands the RC2 [key] using the specified number
    of [effective_bits]. Returns a 128-byte array containing the expanded key. *)
    let expand_key key effective_bits =
  let key_len = String.length key in
  let t1 = Array.make 128 0 in

  (* Copy key into expansion buffer *)
  for i = 0 to key_len - 1 do
    t1.(i) <- int_of_char key.[i]
  done;

  (* Expand key using PITABLE *)
  let t2 = ref key_len in
  while !t2 < 128 do
    t1.(!t2) <- pitable.((t1.(!t2 - 1) + t1.(!t2 - key_len)) land 0xFF);
    t2 := !t2 + 1
  done;

  (* Apply effective key bits *)
  if effective_bits < 1024 then begin
    let t3 = (effective_bits + 7) / 8 in
    let t4 = (effective_bits + 7) land -8 in
    let t5 = 255 lsr (t4 - (t3 * 8)) in
    t1.(t3 - 1) <- t1.(t3 - 1) land t5
  end;
  t1

(** [encrypt_block key data] encrypts an 8-byte [data] block using RC2 with the given [key].
    Returns the encrypted block as a string. *)
    let encrypt_block key data =
  let expanded_key = expand_key key 1024 in
  let r = Array.make 4 0 in

  (* Convert block to words *)
  for i = 0 to 3 do
    r.(i) <-
      int_of_char data.[i * 2]
      lor (int_of_char data.[(i * 2) + 1] lsl 8)
      land 0xFFFF
  done;

  (* Mixing rounds *)
  for i = 0 to 15 do
    r.(0) <-
      (r.(0)
      + (r.(3) land lnot r.(1))
      + (r.(2) land r.(1))
      + expanded_key.(i * 4))
      land 0xFFFF;
    r.(0) <- (r.(0) lsl 1) lor (r.(0) lsr 15);

    r.(1) <-
      (r.(1)
      + (r.(0) land lnot r.(2))
      + (r.(3) land r.(2))
      + expanded_key.((i * 4) + 1))
      land 0xFFFF;
    r.(1) <- (r.(1) lsl 2) lor (r.(1) lsr 14);

    r.(2) <-
      (r.(2)
      + (r.(1) land lnot r.(3))
      + (r.(0) land r.(3))
      + expanded_key.((i * 4) + 2))
      land 0xFFFF;
    r.(2) <- (r.(2) lsl 3) lor (r.(2) lsr 13);

    r.(3) <-
      (r.(3)
      + (r.(2) land lnot r.(0))
      + (r.(1) land r.(0))
      + expanded_key.((i * 4) + 3))
      land 0xFFFF;
    r.(3) <- (r.(3) lsl 5) lor (r.(3) lsr 11)
  done;

  let result = Bytes.create 8 in
  for i = 0 to 3 do
    Bytes.set result (i * 2) (char_of_int (r.(i) land 0xFF));
    Bytes.set result ((i * 2) + 1) (char_of_int ((r.(i) lsr 8) land 0xFF))
  done;
  Bytes.to_string result

(** [decrypt_block key data] decrypts an 8-byte [data] block using RC2 with the given [key].
    Returns the decrypted block as a string. *)
    let decrypt_block key data =
  let expanded_key = expand_key key 1024 in
  let r = Array.make 4 0 in

  (* Convert input block to words *)
  for i = 0 to 3 do
    r.(i) <-
      int_of_char data.[i * 2]
      lor (int_of_char data.[(i * 2) + 1] lsl 8)
      land 0xFFFF
  done;

  (* Reverse mixing rounds *)
  for i = 15 downto 0 do
    r.(3) <- (r.(3) lsr 5) lor (r.(3) lsl 11) land 0xFFFF;
    r.(3) <-
      (r.(3)
      - (r.(2) land lnot r.(0))
      - (r.(1) land r.(0))
      - expanded_key.((i * 4) + 3))
      land 0xFFFF;

    r.(2) <- (r.(2) lsr 3) lor (r.(2) lsl 13) land 0xFFFF;
    r.(2) <-
      (r.(2)
      - (r.(1) land lnot r.(3))
      - (r.(0) land r.(3))
      - expanded_key.((i * 4) + 2))
      land 0xFFFF;

    r.(1) <- (r.(1) lsr 2) lor (r.(1) lsl 14) land 0xFFFF;
    r.(1) <-
      (r.(1)
      - (r.(0) land lnot r.(2))
      - (r.(3) land r.(2))
      - expanded_key.((i * 4) + 1))
      land 0xFFFF;

    r.(0) <- (r.(0) lsr 1) lor (r.(0) lsl 15) land 0xFFFF;
    r.(0) <-
      (r.(0)
      - (r.(3) land lnot r.(1))
      - (r.(2) land r.(1))
      - expanded_key.(i * 4))
      land 0xFFFF
  done;

  let result = Bytes.create 8 in
  for i = 0 to 3 do
    Bytes.set result (i * 2) (char_of_int (r.(i) land 0xFF));
    Bytes.set result ((i * 2) + 1) (char_of_int ((r.(i) lsr 8) land 0xFF))
  done;
  Bytes.to_string result

(** [pad_data data] applies PKCS7 padding to [data] to ensure its length is a multiple of 8.
    Returns the padded string. *)
    let pad_data data =
  let block_size = 8 in
  let padding_length = block_size - (String.length data mod block_size) in
  let padded = Bytes.create (String.length data + padding_length) in
  Bytes.blit_string data 0 padded 0 (String.length data);
  for i = 0 to padding_length - 1 do
    Bytes.set padded (String.length data + i) (char_of_int padding_length)
  done;
  Bytes.to_string padded


(*ocamlformatbug*)
  (** [remove_padding data] removes PKCS7 padding from [data].
    Returns the unpadded string. If padding is invalid, returns the original string. *)
let remove_padding data =
  let len = String.length data in
  if len = 0 then data
  else
    let padding_length = int_of_char data.[len - 1] in
    if padding_length > len then data
    else String.sub data 0 (len - padding_length)
(** Combined encryption/decryption functions *)let encrypt_rc2_sha3 key input =
  let key_hash = sha3_256 key in
  let rc2_key = String.sub (Bytes.to_string key_hash) 0 8 in
  let padded_data = pad_data input in
  let num_blocks = String.length padded_data / 8 in
  let result = Buffer.create (num_blocks * 8) in

  for i = 0 to num_blocks - 1 do
    let block = String.sub padded_data (i * 8) 8 in
    let encrypted_block = encrypt_block rc2_key block in
    Buffer.add_string result encrypted_block
  done;
  Buffer.contents result

(** [decrypt_rc2_sha3 key input] decrypts [input] using RC2 with a SHA3-derived key from [key].
    Returns the decrypted string. *)
let decrypt_rc2_sha3 key input =
  let key_hash = sha3_256 key in
  let rc2_key = String.sub (Bytes.to_string key_hash) 0 8 in
  let num_blocks = String.length input / 8 in
  let result = Buffer.create (num_blocks * 8) in

  for i = 0 to num_blocks - 1 do
    let block = String.sub input (i * 8) 8 in
    let decrypted_block = decrypt_block rc2_key block in
    Buffer.add_string result decrypted_block
  done;
  remove_padding (Buffer.contents result)
(** [encrypt_sha3 input] computes the SHA3-256 hash of [input] and returns it as a hex string. *)

let encrypt_sha3 input =
  let hash = sha3_256 input in
  hex_of_string hash
(** [decrypt_sha3 hex_hash] returns the provided [hex_hash] unchanged. This function exists
    for API symmetry. *)

let decrypt_sha3 hex_hash = hex_hash
(** [encrypt filename] encrypts the contents of the file at [filename] using RC2/SHA3
    and writes the result to [filename].enc. Returns true on success, false on error. *)
let encrypt filename =
  try
    
    let ic = open_in filename in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;

    (* Generate a fixed key from the filename *)
    let key = filename in
    Printf.printf "Using key (filename): %s\n" key;
    let encrypted = encrypt_rc2_sha3 key content in
    Printf.printf "Encryption completed\n";

    (* Write to output file *)
    let output_filename = filename ^ ".enc" in
    Printf.printf "Writing to: %s\n" output_filename;
    let oc = open_out_bin output_filename in
    output_string oc encrypted;
    close_out oc;
    Printf.printf "Write completed\n";
    true
  with e -> 
    Printf.printf "Error during encryption: %s\n" (Printexc.to_string e);
    false
  (** [decrypt filename] decrypts the contents of the file at [filename] using RC2/SHA3
    and writes the result to the original filename with .dec extension.
    Returns true on success, false on error. Requires [filename] to have .enc extension. *)
let decrypt filename =
  try
    Printf.printf "Starting decryption of %s\n" filename;
    if not (Filename.check_suffix filename ".enc") then begin
      Printf.printf "Error: File must have .enc extension\n";
      false
    end else begin
      let ic = open_in_bin filename in
      let encrypted = really_input_string ic (in_channel_length ic) in
      close_in ic;
      Printf.printf "Read %d bytes of encrypted data\n" (String.length encrypted);

      let original_filename = Filename.chop_suffix filename ".enc" in
      let key = original_filename in
      let decrypted = decrypt_rc2_sha3 key encrypted in
      Printf.printf "Decryption completed, output size: %d bytes\n" 
        (String.length decrypted);

      let output_filename = original_filename ^ ".dec" in
      let oc = open_out_bin output_filename in
      output_string oc decrypted;
      close_out oc;
      Printf.printf "Decrypted data written to %s\n" output_filename;
      true
    end
  with e ->
    Printf.printf "Decryption failed: %s\n" (Printexc.to_string e);
    false

