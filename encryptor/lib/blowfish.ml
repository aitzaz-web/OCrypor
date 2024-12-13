open Csv
open Util

(**[csv_to_array filename] loads in the contents of the csv file at [filename]
   as an array.*)
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
  find_root (Sys.getcwd ()) ^ "/data/"

let p_array = csv_to_array (base_data_dir ^ "p_array.csv")
let s_box_1 = csv_to_array (base_data_dir ^ "s1_box.csv")
let s_box_2 = csv_to_array (base_data_dir ^ "s2_box.csv")
let s_box_3 = csv_to_array (base_data_dir ^ "s3_box.csv")
let s_box_4 = csv_to_array (base_data_dir ^ "s4_box.csv")

let int_to_binary n =
  let rec to_binary_list n acc =
    if n = 0 then acc else to_binary_list (n lsr 1) ((n land 1) :: acc)
  in
  let binary = to_binary_list n [] in
  let padding = List.init (32 - List.length binary) (fun _ -> 0) in
  padding @ binary

let binary_to_int bin_lst =
  List.fold_left (fun acc bit -> (acc lsl 1) lor bit) 0 bin_lst

let string_to_binary key =
  let char_to_bin c =
    let ascii = Char.code c in
    List.init 8 (fun i -> (ascii lsr (7 - i)) land 1)
  in
  List.flatten (List.map char_to_bin (String.to_seq key |> List.of_seq))

let binary_to_string binary_list =
  let bits_to_char bits =
    let ascii = List.fold_left (fun acc bit -> (acc lsl 1) lor bit) 0 bits in
    Char.chr ascii
  in
  let rec split_at n lst =
    if n <= 0 then ([], lst)
    else
      match lst with
      | [] -> ([], [])
      | x :: xs ->
          let left, right = split_at (n - 1) xs in
          (x :: left, right)
  in
  let rec split_into_chunks n lst acc =
    match lst with
    | [] -> List.rev acc
    | _ ->
        let chunk, rest = split_at n lst in
        split_into_chunks n rest (chunk :: acc)
  in
  if List.length binary_list mod 8 <> 0 then invalid_arg "Problem."
  else
    let chunks = split_into_chunks 8 binary_list [] in
    let chars = List.map bits_to_char chunks in
    String.of_seq (List.to_seq chars)

let xor bin_lst1 bin_lst2 =
  if List.length bin_lst1 <> List.length bin_lst2 then
    invalid_arg "Binary lists must both be length 32."
  else List.map2 (fun l1 l2 -> if l1 = l2 then 0 else 1) bin_lst1 bin_lst2

let sub s e list =
  let rec sub_traverse i acc =
    if i >= e then List.rev acc
    else sub_traverse (i + 1) (List.nth list i :: acc)
  in
  sub_traverse s []

let binary_string_to_list binary_string =
  binary_string |> String.to_seq |> List.of_seq
  |> List.map (fun c -> int_of_char c - int_of_char '0')

(**[init_p_array key] is the p-array after the 8-digit [key] is encoded into the
   p-array via xor.*)
let init_p_array key =
  let key_string = Printf.sprintf "%08d" key in
  let key_as_binary = string_to_binary key_string in
  if List.length key_as_binary <> 64 then
    invalid_arg "The key must be 64 bits long."
  else
    let key_l = sub 0 32 key_as_binary in
    let key_r = sub 32 64 key_as_binary in
    let new_p_array =
      Array.mapi
        (fun i p ->
          let p_as_binary = int_to_binary p in
          let key_half = if i mod 2 = 0 then key_l else key_r in
          binary_to_int (xor p_as_binary key_half))
        p_array
    in
    new_p_array

(**[pad_to_64_bits binary_message] pads the binary representation list of a
   message to 64 bits by padding on 0's.*)
let pad_to_64_bits binary_message =
  let length = List.length binary_message in
  if length > 64 then invalid_arg "Must be 64 bits at most."
  else if length = 64 then binary_message
  else
    let padding = 64 - length in
    binary_message @ List.init padding (fun _ -> 0)

(**[f_function xl_binary] is the result of calling the blowfish f-function on
   the [xl_binary] half of the message. It uses substitution with the s-boxes to
   encode the message. The formula is F(xL)=((S1,a+S2,b mod 2^32)XOR S3,c)+ S4,d
   mod 2^32 where S1,a is the ath index element of the s1 array, etc.*)
let f_function xl_binary =
  let a = sub 0 8 xl_binary in
  let b = sub 8 16 xl_binary in
  let c = sub 16 24 xl_binary in
  let d = sub 24 32 xl_binary in
  let a_index = binary_to_int a in
  let b_index = binary_to_int b in
  let c_index = binary_to_int c in
  let d_index = binary_to_int d in
  let s1 = s_box_1.(a_index) in
  let s2 = s_box_2.(b_index) in
  let s3 = s_box_3.(c_index) in
  let s4 = s_box_4.(d_index) in
  let sum1 = (s1 + s2) mod 0x100000000 in
  let xor_result =
    binary_to_int (xor (int_to_binary sum1) (int_to_binary s3))
  in
  let final_result = (xor_result + s4) mod 0x100000000 in
  int_to_binary final_result

let encrypt message key =
  try
    let local_p_array = init_p_array key in
    let message_as_binary = string_to_binary message in
    let padding_length = 64 - List.length message_as_binary in
    let padded_message = pad_to_64_bits message_as_binary in
    let xl = sub 0 32 padded_message in
    let xr = sub 32 64 padded_message in
    let rec feistel_rounds xl xr round =
      if round > 16 then (xl, xr)
      else
        let xl = xor xl (int_to_binary local_p_array.(round - 1)) in
        let xr = xor (f_function xl) xr in
        feistel_rounds xr xl (round + 1)
    in
    let xl, xr = feistel_rounds xl xr 1 in
    let xl, xr = (xr, xl) in
    let xr = xor xr (int_to_binary local_p_array.(16)) in
    let xl = xor xl (int_to_binary local_p_array.(17)) in
    let bin_ciphertext = xl @ xr @ int_to_binary padding_length in
    String.concat "" (List.map string_of_int bin_ciphertext)
  with _ -> failwith "Error occurred during encryption."

let decrypt ciphertext_str key =
  try
    let ciphertext = binary_string_to_list ciphertext_str in
    let local_p_array = init_p_array key in
    let padding_length_binary =
      sub (List.length ciphertext - 8) (List.length ciphertext) ciphertext
    in
    let padding_length = binary_to_int padding_length_binary in
    let ciphertext_without_padding =
      sub 0 (List.length ciphertext - 8) ciphertext
    in
    let xl = sub 0 32 ciphertext_without_padding in
    let xr = sub 32 64 ciphertext_without_padding in
    let rec feistel_rounds xl xr round =
      if round < 3 then (xl, xr)
      else
        let xl = xor xl (int_to_binary local_p_array.(round - 1)) in
        let xr = xor (f_function xl) xr in
        feistel_rounds xr xl (round - 1)
    in
    let xl, xr = feistel_rounds xl xr 18 in
    let xl, xr = (xr, xl) in
    let xr = xor xr (int_to_binary local_p_array.(1)) in
    let xl = xor xl (int_to_binary local_p_array.(0)) in
    let value = xl @ xr in
    let unpadded_binary = sub 0 (List.length value - padding_length) value in
    binary_to_string unpadded_binary
  with _ -> failwith "Error occurred during decryption."
