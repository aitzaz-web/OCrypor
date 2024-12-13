let pad_block block =
  let block_length = String.length block in
  if block_length = 16 then block
  else
    let padding_length = 16 - block_length in
    block ^ String.make padding_length (Char.chr padding_length)

let split_into_blocks_encrypt message =
  let rec aux i acc =
    if i >= String.length message then List.rev acc
    else
      let block =
        if i + 16 > String.length message then
          String.sub message i (String.length message - i) |> pad_block
        else String.sub message i 16
      in
      aux (i + 16) (block :: acc)
  in
  aux 0 []

let split_into_blocks_decrypt message =
  let rec aux i acc =
    if i >= String.length message then List.rev acc
    else
      let block = String.sub message i 16 in
      aux (i + 16) (block :: acc)
  in
  aux 0 []

let csv_to_array filename =
  Array.of_list
    (List.map
       (fun s -> int_of_string (String.trim s))
       (List.flatten (Csv.load filename)))

(**[base_data_dir] ensures that file paths to the data directory are correct.*)
let base_data_dir =
  let rec find_root dir =
    if Sys.file_exists (Filename.concat dir "dune-project") then dir
    else find_root (Filename.dirname dir)
  in
  find_root (Sys.getcwd ()) ^ "/encryptor/data/"

let s_box = csv_to_array (base_data_dir ^ "sbox.csv")
let inv_s_box = csv_to_array (base_data_dir ^ "inv_sbox.csv")

let string_to_state s =
  let state = Array.make_matrix 4 4 0 in
  for i = 0 to 15 do
    let col = i mod 4 in
    let row = i / 4 in
    state.(row).(col) <- Char.code s.[i]
  done;
  state

let sub_bytes state =
  Array.init 4 (fun row ->
      Array.init 4 (fun col ->
          let byte = state.(row).(col) in
          s_box.(byte)))

let shift_rows state =
  Array.init 4 (fun row ->
      Array.init 4 (fun col -> state.(row).((col + row) mod 4)))

let transpose matrix =
  let rows = Array.length matrix in
  let cols = Array.length matrix.(0) in
  Array.init cols (fun i -> Array.init rows (fun j -> matrix.(j).(i)))

let gmul a b =
  let rec aux a b acc =
    if b = 0 then acc
    else
      let acc = if b land 1 <> 0 then acc lxor a else acc in
      let a = if a land 0x80 <> 0 then (a lsl 1) lxor 0x11b else a lsl 1 in
      aux a (b lsr 1) acc
  in
  aux a b 0

let mix_columns_generic state matrix =
  Array.init 4 (fun row ->
      Array.init 4 (fun col ->
          Array.fold_left
            (fun acc i -> acc lxor gmul matrix.(row).(i) state.(i).(col))
            0
            (Array.init 4 (fun i -> i))))

let mix_columns state =
  let mix_matrix =
    [| [| 2; 3; 1; 1 |]; [| 1; 2; 3; 1 |]; [| 1; 1; 2; 3 |]; [| 3; 1; 1; 2 |] |]
  in
  mix_columns_generic state mix_matrix

let inv_mix_columns state =
  let inv_mix_matrix =
    [|
      [| 14; 11; 13; 9 |];
      [| 9; 14; 11; 13 |];
      [| 13; 9; 14; 11 |];
      [| 11; 13; 9; 14 |];
    |]
  in
  mix_columns_generic state inv_mix_matrix

let add_round_key state round_key =
  Array.init 4 (fun row ->
      Array.init 4 (fun col -> state.(row).(col) lxor round_key.(row).(col)))

let sub_word word = Array.map (fun byte -> s_box.(byte)) word
let rot_word word = [| word.(1); word.(2); word.(3); word.(0) |]

let key_expansion key =
  let rcon = [| 0x01; 0x02; 0x04; 0x08; 0x10; 0x20; 0x40; 0x80; 0x1b; 0x36 |] in
  let key_words = Array.make_matrix 44 4 0 in
  for i = 0 to 3 do
    for j = 0 to 3 do
      key_words.(i).(j) <- Char.code key.[(i * 4) + j]
    done
  done;
  for i = 4 to 43 do
    let temp = Array.copy key_words.(i - 1) in
    if i mod 4 = 0 then (
      let temp = rot_word temp in
      let temp = sub_word temp in
      for j = 0 to 3 do
        temp.(j) <- temp.(j) lxor rcon.((i / 4) - 1)
      done;
      Array.blit temp 0 key_words.(i) 0 4)
    else
      for j = 0 to 3 do
        key_words.(i).(j) <- key_words.(i - 4).(j) lxor key_words.(i - 1).(j)
      done
  done;
  Array.init 11 (fun i -> Array.sub key_words (i * 4) 4)

let serialize_state state =
  Array.map
    (fun row ->
      Array.map (Printf.sprintf "%02X") row
      |> Array.to_list |> String.concat " ")
    state
  |> Array.to_list |> String.concat "\n"

let deserialize_state serialized =
  serialized |> String.split_on_char '\n'
  |> List.map (fun row ->
         row |> String.split_on_char ' '
         |> List.map (fun hex -> int_of_string ("0x" ^ hex))
         |> Array.of_list)
  |> Array.of_list

let state_to_string state =
  let buffer = Buffer.create 16 in
  Array.iter
    (fun row ->
      Array.iter (fun byte -> Buffer.add_char buffer (Char.chr byte)) row)
    state;
  Buffer.contents buffer

let aes_encrypt_block block round_keys =
  (* Convert string block to state matrix *)
  let state = string_to_state block in

  (* Initial round: AddRoundKey *)
  let state = add_round_key state round_keys.(0) in

  (* Main rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey *)
  let state = ref state in
  for round = 1 to 9 do
    state := sub_bytes !state;
    state := shift_rows !state;
    state := mix_columns !state;
    state := add_round_key !state round_keys.(round)
  done;

  (* Final round: SubBytes, ShiftRows, AddRoundKey *)
  state := sub_bytes !state;
  state := shift_rows !state;
  state := add_round_key !state round_keys.(10);

  (* Convert state matrix back to string *)
  state_to_string !state

let encrypt message key =
  let blocks = split_into_blocks_encrypt message in
  let round_keys = key_expansion key in
  let encrypted_blocks =
    List.map (fun block -> aes_encrypt_block block round_keys) blocks
  in
  String.concat "" encrypted_blocks

let inv_sub_bytes state =
  Array.init 4 (fun row ->
      Array.init 4 (fun col ->
          let byte = state.(row).(col) in
          inv_s_box.(byte)))

let inv_shift_rows state =
  Array.init 4 (fun row ->
      Array.init 4 (fun col -> state.(row).((col - row + 4) mod 4)))

let aes_decrypt_block block round_keys =
  (* Convert encrypted string block to state matrix *)
  let state = string_to_state block in

  (* Initial round: AddRoundKey *)
  let state = ref (add_round_key state round_keys.(10)) in

  (* Final round: InvShiftRows, InvSubBytes *)
  state := inv_shift_rows !state;
  state := inv_sub_bytes !state;

  (* Main rounds: AddRoundKey, InvMixColumns, InvShiftRows, InvSubBytes *)
  for round = 9 downto 1 do
    state := add_round_key !state round_keys.(round);
    state := inv_mix_columns !state;
    state := inv_shift_rows !state;
    state := inv_sub_bytes !state
  done;

  (* Final AddRoundKey *)
  state := add_round_key !state round_keys.(0);
  (* Convert state matrix back to string *)
  state_to_string !state

let remove_padding message =
  let padding_length =
    Char.code (String.get message (String.length message - 1))
  in
  String.sub message 0 (String.length message - padding_length)

let decrypt message key =
  let blocks = split_into_blocks_decrypt message in
  let round_keys = key_expansion key in
  let decrypted_message =
    String.concat ""
      (List.map (fun block -> aes_decrypt_block block round_keys) blocks)
  in
  remove_padding decrypted_message

let encrypt_file filename key =
  let input_path = Filename.concat "data" filename in
  let ic = open_in_bin input_path in
  let input_length = in_channel_length ic in
  let buffer = really_input_string ic input_length in
  close_in ic;
  Printf.printf "Encrypting file: %s\n" input_path;
  let encrypted_content = encrypt buffer key in
  let output_path = Filename.concat "data" (filename ^ ".enc") in
  let oc = open_out_bin output_path in
  output_string oc encrypted_content;
  close_out oc;
  Printf.printf "Encrypted file saved as: %s\n" output_path

let decrypt_file filename key =
  let input_path = Filename.concat "data" filename in
  let ic = open_in_bin input_path in
  let input_length = in_channel_length ic in
  let buffer = really_input_string ic input_length in
  close_in ic;
  Printf.printf "Decrypting file: %s\n" input_path;

  (* Ensure the decrypted file path removes only ".enc" *)
  let base_name =
    if Filename.check_suffix filename ".enc" then
      Filename.chop_suffix filename ".enc"
    else filename
  in
  let output_path = Filename.concat "data" (base_name ^ ".dec") in

  let decrypted_content = decrypt buffer key in
  let oc = open_out_bin output_path in
  output_string oc decrypted_content;
  close_out oc;
  Printf.printf "Decrypted file saved as: %s\n" output_path
